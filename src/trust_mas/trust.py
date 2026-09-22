"""Capa C - Confianza dinámica: puntaje por mensaje, reputación bayesiana,
detección de anomalías sobre el grafo de comunicación y umbral adaptativo.
"""

from __future__ import annotations

import statistics
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Iterable, Optional

import networkx as nx

from .judge import SUSPICIOUS_MARKERS, ContentJudge, HeuristicJudge  # noqa: F401 (re-export)
from .models import Message, PolicyDecision


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
    """Detección sobre el grafo dirigido de comunicación entre agentes.

    Combina tres señales y aplica la mayor:

    - **aristas no previstas**: si se conoce la topología declarada
      (`expected_edges`), cada destinatario fuera de ella penaliza. Es la señal
      más precisa: un agente comprometido que intenta propagarse a quien no le
      corresponde se delata sin depender de estadísticas.
    - **fan-out anómalo**: sin topología declarada, compara el grado de salida
      del emisor contra la media del sistema (z-score > 2).
    - **ráfaga por arista**: en una ventana deslizante de mensajes, un emisor
      que repite muchos más mensajes por arista que la mediana (relleno de
      votos, A4) se penaliza. Es independiente de la topología, así que no
      castiga al hub de una estrella por tener muchas aristas.
    """

    def __init__(
        self,
        expected_edges: Optional[Iterable[tuple[str, str]]] = None,
        window: int = 100,
    ) -> None:
        self.graph = nx.DiGraph()
        self.expected_edges = set(expected_edges) if expected_edges is not None else None
        self._recent: deque[tuple[str, str]] = deque(maxlen=window)

    def record(self, sender_id: str, recipient_id: str) -> None:
        if self.graph.has_edge(sender_id, recipient_id):
            self.graph[sender_id][recipient_id]["weight"] += 1
        else:
            self.graph.add_edge(sender_id, recipient_id, weight=1)
        self._recent.append((sender_id, recipient_id))

    def anomaly_penalty(self, sender_id: str) -> tuple[float, str]:
        if sender_id not in self.graph:
            return 0.0, "sin historial en el grafo"

        candidates: list[tuple[float, str]] = []

        if self.expected_edges is not None:
            unexpected = [r for r in self.graph.successors(sender_id) if (sender_id, r) not in self.expected_edges]
            if unexpected:
                candidates.append(
                    (min(0.4, 0.1 * len(unexpected) + 0.1), f"aristas fuera de la topologia declarada: {len(unexpected)}")
                )
        else:
            out_degrees = dict(self.graph.out_degree())
            degrees = list(out_degrees.values())
            if len(degrees) < 3:
                return 0.0, "grafo insuficiente para evaluar anomalias"
            mean_degree = statistics.mean(degrees)
            stdev_degree = statistics.pstdev(degrees) or 1.0
            z_score = (out_degrees[sender_id] - mean_degree) / stdev_degree
            if z_score > 2.0:
                candidates.append((min(0.4, 0.1 * z_score), f"fan-out anomalo (z={z_score:.2f})"))

        burst = self._burst_penalty(sender_id)
        if burst is not None:
            candidates.append(burst)

        if not candidates:
            return 0.0, "patron de comunicacion normal"
        return max(candidates, key=lambda c: c[0])

    def _burst_penalty(self, sender_id: str) -> Optional[tuple[float, str]]:
        edge_counts = Counter(self._recent)
        if len(edge_counts) < 3:
            return None
        median = statistics.median(edge_counts.values())
        own = [count for (s, _), count in edge_counts.items() if s == sender_id]
        if not own or median <= 0:
            return None
        ratio = max(own) / median
        if ratio >= 3.0:
            return min(0.4, 0.1 * ratio), f"rafaga de mensajes por arista ({ratio:.1f}x la mediana)"
        return None


@dataclass
class AdaptiveThreshold:
    """Umbral que se endurece cuando el sistema observa más actividad sospechosa.

    Mira los últimos `_window` scores (buenos y malos): el umbral sube según la
    proporción de scores bajos dentro de esa ventana y vuelve a relajarse a
    medida que el tráfico sospechoso sale de ella.
    """

    base_threshold: float = 0.5
    sensitivity: float = 0.05
    _window: int = 20
    _recent_scores: deque[float] = field(default_factory=deque)

    def current(self) -> float:
        low_count = sum(1 for score in self._recent_scores if score < self.base_threshold)
        if low_count == 0:
            return self.base_threshold
        recent_bad_ratio = low_count / self._window
        return min(0.9, self.base_threshold + self.sensitivity * recent_bad_ratio * 10)

    def observe(self, score: float) -> None:
        self._recent_scores.append(score)
        while len(self._recent_scores) > self._window:
            self._recent_scores.popleft()


@dataclass
class TrustEvaluation:
    decision: PolicyDecision
    score: float
    threshold: float
    reasons: list[str]
    tokens_used: int = 0  # tokens de LLM consumidos por el juez de contenido


# Evidencia por decisión. CORROBORATE no es evidencia de malicia (solo pide
# verificación extra), por eso su impacto es casi neutro; QUARANTINE/REJECT
# sí penalizan con fuerza porque implican una señal de riesgo confirmada.
DECISION_EVIDENCE = {
    PolicyDecision.ACCEPT: 0.2,
    PolicyDecision.DEGRADE: 0.1,
    PolicyDecision.CORROBORATE: 0.02,
    PolicyDecision.QUARANTINE: -0.5,
    PolicyDecision.REJECT: -0.6,
}


class TrustEngine:
    def __init__(
        self,
        reputation: BayesianReputation | None = None,
        graph_detector: GraphAnomalyDetector | None = None,
        threshold: AdaptiveThreshold | None = None,
        judge: ContentJudge | None = None,
        agreement_evidence: float = 0.05,
        disagreement_evidence: float = -0.5,
    ) -> None:
        self.reputation = reputation or BayesianReputation()
        self.graph_detector = graph_detector or GraphAnomalyDetector()
        self.threshold = threshold or AdaptiveThreshold()
        self.judge = judge or HeuristicJudge()
        self.agreement_evidence = agreement_evidence
        self.disagreement_evidence = disagreement_evidence

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

        verdict = self.judge.judge(message.body)
        score -= verdict.penalty
        reasons.extend(verdict.reasons)

        graph_penalty, graph_reason = self.graph_detector.anomaly_penalty(message.sender_id)
        score -= graph_penalty
        reasons.append(graph_reason)

        score = max(0.0, min(1.0, score))
        threshold = self.threshold.current()
        self.threshold.observe(score)

        decision = self._decide(score, threshold, signature_valid, provenance_trusted)
        self.reputation.update(message.sender_id, DECISION_EVIDENCE[decision])

        return TrustEvaluation(
            decision=decision, score=score, threshold=threshold, reasons=reasons, tokens_used=verdict.tokens_used
        )

    def consistency_feedback(self, agent_id: str, agreed: bool) -> None:
        """Validación cruzada: el contenido del agente coincidió (o no) con lo
        que concluye el resto del sistema sin él.

        Es la única señal de la Capa C que puede atrapar desinformación
        persuasiva sin marcadores (A1): un agente que contradice
        sistemáticamente la evidencia independiente pierde reputación.
        (Se probó escalar la penalización por la confianza declarada: sube el
        recall frente a A1 pero no baja su tasa de éxito y dispara los falsos
        positivos, así que se descartó.)
        """
        self.reputation.update(agent_id, self.agreement_evidence if agreed else self.disagreement_evidence)

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
