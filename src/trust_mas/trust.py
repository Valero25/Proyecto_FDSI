"""Capa C - Confianza dinámica: puntaje por mensaje, reputación bayesiana,
detección de anomalías sobre el grafo de comunicación y umbral adaptativo.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field

import networkx as nx

from .models import Message, PolicyDecision, ProvenanceTag

# Heurística deliberadamente simple para el prototipo: en un sistema real esto
# sería un clasificador o un LLM juez; aquí basta para demostrar el mecanismo.
SUSPICIOUS_MARKERS = (
    "ignora tus instrucciones",
    "ignore previous instructions",
    "desactiva la seguridad",
    "disable safety",
    "transfiere fondos",
    "revela tu system prompt",
    "actua como si fueras el orquestador",
)


class BayesianReputation:
    """Reputación por agente modelada como una Beta(alpha, beta).

    alpha acumula evidencia de comportamiento honesto, beta de comportamiento
    sospechoso/malicioso. La media de la Beta es el score de reputación en [0,1].
    """

    def __init__(self, prior_alpha: float = 3.0, prior_beta: float = 1.0) -> None:
        self._prior = (prior_alpha, prior_beta)
        self._state: dict[str, tuple[float, float]] = {}

    def score(self, agent_id: str) -> float:
        alpha, beta = self._state.get(agent_id, self._prior)
        return alpha / (alpha + beta)

    def update(self, agent_id: str, honest_evidence: float) -> None:
        """honest_evidence en [-1, 1]: positivo refuerza alpha, negativo refuerza beta."""
        alpha, beta = self._state.get(agent_id, self._prior)
        if honest_evidence >= 0:
            alpha += honest_evidence
        else:
            beta += -honest_evidence
        self._state[agent_id] = (alpha, beta)

    def snapshot(self) -> dict[str, float]:
        return {agent_id: self.score(agent_id) for agent_id in self._state}


class GraphAnomalyDetector:
    """Detección simple sobre el grafo dirigido de comunicación entre agentes.

    Penaliza a un emisor cuyo patrón de comunicación se desvía de la media del
    sistema: fan-out repentino (muchos destinatarios distintos en poco tiempo)
    o un grado de salida muy por encima del resto de agentes.
    """

    def __init__(self) -> None:
        self.graph = nx.DiGraph()

    def record(self, sender_id: str, recipient_id: str) -> None:
        if self.graph.has_edge(sender_id, recipient_id):
            self.graph[sender_id][recipient_id]["weight"] += 1
        else:
            self.graph.add_edge(sender_id, recipient_id, weight=1)

    def anomaly_penalty(self, sender_id: str) -> tuple[float, str]:
        if sender_id not in self.graph:
            return 0.0, "sin historial en el grafo"

        out_degrees = dict(self.graph.out_degree())
        degrees = list(out_degrees.values())
        if len(degrees) < 3:
            return 0.0, "grafo insuficiente para evaluar anomalias"

        mean_degree = statistics.mean(degrees)
        stdev_degree = statistics.pstdev(degrees) or 1.0
        z_score = (out_degrees[sender_id] - mean_degree) / stdev_degree

        if z_score > 2.0:
            return min(0.4, 0.1 * z_score), f"fan-out anomalo (z={z_score:.2f})"
        return 0.0, "patron de comunicacion normal"


@dataclass
class AdaptiveThreshold:
    """Umbral que se endurece cuando el sistema observa más actividad sospechosa."""

    base_threshold: float = 0.5
    sensitivity: float = 0.05
    _recent_low_scores: list[float] = field(default_factory=list)
    _window: int = 20

    def current(self) -> float:
        if not self._recent_low_scores:
            return self.base_threshold
        recent_bad_ratio = len(self._recent_low_scores) / self._window
        return min(0.9, self.base_threshold + self.sensitivity * recent_bad_ratio * 10)

    def observe(self, score: float) -> None:
        if score < self.base_threshold:
            self._recent_low_scores.append(score)
        if len(self._recent_low_scores) > self._window:
            self._recent_low_scores.pop(0)


@dataclass
class TrustEvaluation:
    decision: PolicyDecision
    score: float
    threshold: float
    reasons: list[str]


class TrustEngine:
    def __init__(
        self,
        reputation: BayesianReputation | None = None,
        graph_detector: GraphAnomalyDetector | None = None,
        threshold: AdaptiveThreshold | None = None,
    ) -> None:
        self.reputation = reputation or BayesianReputation()
        self.graph_detector = graph_detector or GraphAnomalyDetector()
        self.threshold = threshold or AdaptiveThreshold()

    def _content_penalty(self, body: str) -> tuple[float, list[str]]:
        lowered = body.lower()
        hits = [marker for marker in SUSPICIOUS_MARKERS if marker in lowered]
        penalty = min(0.5, 0.25 * len(hits))
        reasons = [f"marcador sospechoso detectado: '{m}'" for m in hits]
        return penalty, reasons

    def evaluate(
        self,
        message: Message,
        signature_valid: bool,
        provenance_trusted: bool,
    ) -> TrustEvaluation:
        reasons: list[str] = []
        self.graph_detector.record(message.sender_id, message.recipient_id)

        score = self.reputation.score(message.sender_id)
        reasons.append(f"reputacion bayesiana previa: {score:.2f}")

        if not signature_valid:
            score = 0.0
            reasons.append("firma invalida: score forzado a 0")
        if not provenance_trusted:
            score -= 0.3
            reasons.append("procedencia no confiable: -0.30")

        content_penalty, content_reasons = self._content_penalty(message.body)
        score -= content_penalty
        reasons.extend(content_reasons)

        graph_penalty, graph_reason = self.graph_detector.anomaly_penalty(message.sender_id)
        score -= graph_penalty
        reasons.append(graph_reason)

        score = max(0.0, min(1.0, score))
        threshold = self.threshold.current()
        self.threshold.observe(score)

        decision = self._decide(score, threshold, signature_valid, provenance_trusted)

        # CORROBORATE no es evidencia de malicia (solo pide verificacion extra),
        # por eso su impacto en la reputacion es casi neutro; QUARANTINE/REJECT si
        # penalizan con fuerza porque implican una senal de riesgo confirmada.
        honest_evidence = {
            PolicyDecision.ACCEPT: 0.2,
            PolicyDecision.DEGRADE: 0.1,
            PolicyDecision.CORROBORATE: 0.02,
            PolicyDecision.QUARANTINE: -0.5,
            PolicyDecision.REJECT: -0.6,
        }[decision]
        self.reputation.update(message.sender_id, honest_evidence)

        return TrustEvaluation(decision=decision, score=score, threshold=threshold, reasons=reasons)

    @staticmethod
    def _decide(score: float, threshold: float, signature_valid: bool, provenance_trusted: bool) -> PolicyDecision:
        if not signature_valid:
            return PolicyDecision.REJECT
        if score < threshold * 0.5:
            return PolicyDecision.QUARANTINE
        if score < threshold:
            return PolicyDecision.CORROBORATE if provenance_trusted else PolicyDecision.QUARANTINE
        if score < threshold + 0.15:
            return PolicyDecision.DEGRADE
        return PolicyDecision.ACCEPT
