"""Orquestador / bus de mensajes: aplica las capas A -> B -> C en orden y
registra cada decisión en el log de auditoría (defensa en profundidad).
"""

from __future__ import annotations

from dataclasses import dataclass

from .audit import AuditLog
from .identity import IdentityRegistry, NonceStore, verify_message
from .models import CapabilityToken, Message, PolicyDecision
from .provenance import QuarantineEngine, check_action_capability
from .trust import TrustEngine


@dataclass
class RoutingResult:
    decision: PolicyDecision
    score: float
    threshold: float
    reasons: list[str]


class MessageBus:
    def __init__(
        self,
        registry: IdentityRegistry,
        trust_engine: TrustEngine | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.registry = registry
        self.nonce_store = NonceStore()
        self.quarantine = QuarantineEngine()
        self.trust_engine = trust_engine or TrustEngine()
        self.audit_log = audit_log or AuditLog()
        self._capability_tokens: dict[str, CapabilityToken] = {}

    def register_capability_token(self, agent_id: str, token: CapabilityToken) -> None:
        self._capability_tokens[agent_id] = token

    def route(self, message: Message) -> RoutingResult:
        reasons: list[str] = []

        # --- Capa A: identidad ---
        identity_result = verify_message(self.registry, self.nonce_store, message)
        reasons.append(f"[Capa A] {identity_result.reason}")
        signature_valid = identity_result.ok

        # --- Capa B: procedencia y autorización por acción ---
        provenance_verdict = self.quarantine.evaluate(message)
        reasons.append(f"[Capa B] {provenance_verdict.reason}")
        provenance_trusted = not provenance_verdict.requires_quarantine

        sender_token = self._capability_tokens.get(message.sender_id)
        action_ok, action_reason = check_action_capability(sender_token, message.action)
        if message.action is not None:
            reasons.append(f"[Capa B] {action_reason}")

        if not signature_valid:
            # Sin identidad verificada no tiene sentido seguir evaluando confianza,
            # pero el intento en si mismo (rol falso, replay, firma invalida) es
            # evidencia fuerte de mal comportamiento: golpea la reputacion igual.
            self.trust_engine.reputation.update(message.sender_id, -0.6)
            entry_decision = PolicyDecision.REJECT
            self._audit(message, entry_decision, 0.0, self.trust_engine.threshold.current(), provenance_trusted, reasons)
            return RoutingResult(entry_decision, 0.0, self.trust_engine.threshold.current(), reasons)

        # --- Capa C: confianza dinamica ---
        evaluation = self.trust_engine.evaluate(message, signature_valid, provenance_trusted)
        reasons.append(f"[Capa C] score={evaluation.score:.2f} umbral={evaluation.threshold:.2f}")
        reasons.extend(f"[Capa C] {r}" for r in evaluation.reasons)

        final_decision = evaluation.decision
        if provenance_verdict.requires_quarantine and final_decision == PolicyDecision.ACCEPT:
            # La procedencia puede forzar cuarentena incluso si el score es alto:
            # defensa en profundidad, ninguna capa por si sola decide "aceptar".
            final_decision = PolicyDecision.QUARANTINE
            reasons.append("[Capa B] cuarentena forzada por procedencia pese a score alto")

        if not action_ok:
            final_decision = PolicyDecision.REJECT
            reasons.append("[Capa B] accion rechazada por falta de capacidad")
            if evaluation.decision in (PolicyDecision.ACCEPT, PolicyDecision.DEGRADE):
                # La Capa C no vio nada sospechoso en el contenido, asi que esta
                # senal (accion no autorizada) todavia no se reflejo en la reputacion.
                self.trust_engine.reputation.update(message.sender_id, -0.3)

        self._audit(message, final_decision, evaluation.score, evaluation.threshold, provenance_trusted, reasons)
        return RoutingResult(final_decision, evaluation.score, evaluation.threshold, reasons)

    def _audit(
        self,
        message: Message,
        decision: PolicyDecision,
        score: float,
        threshold: float,
        provenance_trusted: bool,
        reasons: list[str],
    ) -> None:
        source = message.provenance.source.value if message.provenance else "sin_etiqueta"
        self.audit_log.append(
            sender_id=message.sender_id,
            recipient_id=message.recipient_id,
            decision=decision.value,
            score=score,
            threshold=threshold,
            provenance_source=source,
            provenance_trusted=provenance_trusted,
            reasons=reasons,
            content=message.body,
        )
