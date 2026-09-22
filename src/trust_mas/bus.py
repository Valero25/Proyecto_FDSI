"""Orquestador / bus de mensajes: aplica las capas A -> B -> C en orden y
registra cada decisión en el log de auditoría (defensa en profundidad).

Las capas se pueden desactivar con `DefenseConfig` para construir la línea
base sin defensas y la ablación. Con una capa apagada, el bus se comporta
como un sistema multiagente sin esa protección (p. ej. sin Capa A cree el
emisor y el rol que diga el mensaje), que es justo lo que el banco de
pruebas necesita para medir el aporte marginal de cada una.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field, replace
from typing import Optional

from .audit import AuditLog
from .config import DefenseConfig
from .identity import IdentityRegistry, NonceStore, verify_capability_token, verify_message
from .models import AgentRole, CapabilityToken, Message, PolicyDecision, ProvenanceSource, ProvenanceTag
from .provenance import UNTRUSTED_BY_DEFAULT, QuarantineEngine, check_action_capability
from .quarantine_model import QuarantineModel, RuleBasedQuarantineModel, SanitizedContent
from .trust import TrustEngine

# Decisiones que dejan pasar el contenido al destinatario. Si la Capa B exige
# cuarentena, ninguna de ellas puede sostenerse.
DELIVERING_DECISIONS = (PolicyDecision.ACCEPT, PolicyDecision.DEGRADE)
BLOCKING_DECISIONS = (PolicyDecision.QUARANTINE, PolicyDecision.REJECT)


@dataclass
class RoutingResult:
    decision: PolicyDecision
    score: float
    threshold: float
    reasons: list[str]
    # Salida del modelo en cuarentena (solo datos, sin instrucciones) cuando
    # el mensaje fue a cuarentena y el modelo está activo.
    sanitized: Optional[SanitizedContent] = None
    # Agentes aislados por remediación selectiva a raíz de este mensaje.
    newly_isolated: list[str] = field(default_factory=list)
    tokens_used: int = 0  # tokens de LLM que consumieron las defensas (juez, cuarentena)
    latency_s: float = 0.0  # tiempo de cómputo de las defensas para este mensaje


@dataclass(frozen=True)
class RemediationPolicy:
    """Cuándo aislar a un agente: reputación muy baja o bloqueos repetidos."""

    isolate_below: float = 0.35
    max_blocked: int = 3


@dataclass
class RemediationEvent:
    agent_id: str
    reason: str
    timestamp: float


class MessageBus:
    def __init__(
        self,
        registry: IdentityRegistry,
        trust_engine: TrustEngine | None = None,
        audit_log: AuditLog | None = None,
        config: DefenseConfig | None = None,
        quarantine_model: QuarantineModel | None = None,
        remediation: RemediationPolicy | None = None,
    ) -> None:
        self.registry = registry
        self.config = config or DefenseConfig()
        self.nonce_store = NonceStore()
        self.quarantine = QuarantineEngine()
        self.trust_engine = trust_engine or TrustEngine()
        self.audit_log = audit_log or AuditLog()
        self.quarantine_model = quarantine_model or RuleBasedQuarantineModel()
        self.remediation = remediation or RemediationPolicy()
        self._capability_tokens: dict[str, CapabilityToken] = {}
        # agent_id -> origenes no confiables que ese agente ingirio.
        self._taint: dict[str, list[str]] = {}
        self._blocked_count: dict[str, int] = {}
        self.isolated: set[str] = set()
        self.remediation_events: list[RemediationEvent] = []
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ API
    def register_capability_token(self, agent_id: str, token: CapabilityToken) -> None:
        self._capability_tokens[agent_id] = token

    def capability_token(self, agent_id: str) -> Optional[CapabilityToken]:
        return self._capability_tokens.get(agent_id)

    def record_ingestion(self, agent_id: str, tag: ProvenanceTag) -> None:
        """El runtime (no el agente) informa que `agent_id` leyo un contenido.

        Si ese contenido no es confiable, el agente queda contaminado: todo lo
        que emita despues se trata como no confiable, diga lo que diga su
        etiqueta. Es lo que impide que un agente lea un documento malicioso y
        lo reenvie "lavado" como si fuera contenido propio.
        """
        if tag.trusted and tag.source not in UNTRUSTED_BY_DEFAULT:
            return
        origins = self._taint.setdefault(agent_id, [])
        origin = f"{tag.source.value}:{tag.origin_id}"
        if origin not in origins:
            origins.append(origin)

    def clear_taint(self, agent_id: str) -> None:
        """Levanta la contaminacion (p. ej. tras sanear el contenido en cuarentena)."""
        self._taint.pop(agent_id, None)

    def is_tainted(self, agent_id: str) -> bool:
        return agent_id in self._taint

    def isolate(self, agent_id: str, reason: str) -> None:
        """Remediación selectiva: aísla SOLO a este agente.

        Se le revoca el token de capacidad y todo lo que envíe en adelante va a
        cuarentena. El resto del sistema sigue operando con normalidad; el
        llamador (p. ej. el banco de pruebas) puede además retirar del contexto
        lo que ese agente ya había aportado.
        """
        if agent_id in self.isolated:
            return
        self.isolated.add(agent_id)
        self._capability_tokens.pop(agent_id, None)
        self.remediation_events.append(RemediationEvent(agent_id, reason, time.time()))

    # --------------------------------------------------------------- routing
    def route(
        self,
        message: Message,
        expected_digest: Optional[str] = None,
        channel_sender: Optional[str] = None,
    ) -> RoutingResult:
        """Enruta un mensaje por las capas activas.

        `expected_digest`: digest de conversacion vigente; si se pasa, un
        mensaje de otro flujo o de una ronda vieja se rechaza (integridad de
        flujo, brecha B3).
        `channel_sender`: agente dueño del canal autenticado por el que llegó
        el mensaje (p. ej. la conexión mTLS del transporte). Si no coincide con
        `sender_id`, es suplantación de emisor y se atribuye al dueño del canal.

        Es seguro llamarlo desde varios hilos (p. ej. nodos de LangGraph que se
        ejecutan en paralelo): el estado compartido (nonces, reputación, cadena
        de auditoría) se actualiza bajo un lock.
        """
        with self._lock:
            return self._route(message, expected_digest, channel_sender)

    def _route(
        self,
        message: Message,
        expected_digest: Optional[str],
        channel_sender: Optional[str],
    ) -> RoutingResult:
        started = time.perf_counter()
        reasons: list[str] = []
        tokens_used = 0
        cfg = self.config

        # --- Capa A: identidad (+ integridad de flujo) ---
        if cfg.identity:
            identity_result = verify_message(self.registry, self.nonce_store, message)
            identity_ok = identity_result.ok
            attributable = identity_result.attributable
            reasons.append(f"[Capa A] {identity_result.reason}")
            if (
                channel_sender is not None
                and channel_sender != message.sender_id
                and self.registry.known(channel_sender)
            ):
                # Aunque la firma cuadrara (clave robada), el canal delata al emisor real.
                identity_ok = False
                attributable = True
                reasons.append(
                    f"[Capa A] suplantacion de emisor: el canal autenticado pertenece a '{channel_sender}', "
                    f"no a '{message.sender_id}'"
                )
            if identity_ok and expected_digest is not None and message.conversation_digest != expected_digest:
                identity_ok = False
                attributable = True  # firma valida sobre un digest que no corresponde
                reasons.append("[Capa A] digest de conversacion no coincide: mensaje fuera de este flujo")
        else:
            identity_ok = True
            attributable = False
            reasons.append("[Capa A] desactivada: se cree el emisor y el rol declarados")

        # --- Capa B: procedencia y autorización por acción ---
        if cfg.provenance:
            # La etiqueta la declara el emisor: el bus la recalcula y nunca deja
            # que el emisor se otorgue a si mismo mas confianza de la que merece.
            effective_provenance, provenance_notes = self._effective_provenance(message)
            reasons.extend(f"[Capa B] {note}" for note in provenance_notes)
            effective_message = replace(message, provenance=effective_provenance)
            provenance_verdict = self.quarantine.evaluate(effective_message)
            reasons.append(f"[Capa B] {provenance_verdict.reason}")
            requires_quarantine = provenance_verdict.requires_quarantine
            action_ok, action_reason = self._authorize_action(message)
            if message.action is not None:
                reasons.append(f"[Capa B] {action_reason}")
        else:
            effective_message = message
            requires_quarantine = False
            action_ok = True
            reasons.append("[Capa B] desactivada: toda procedencia se considera confiable")
        provenance_trusted = not requires_quarantine

        if not identity_ok:
            # Sin identidad verificada no tiene sentido seguir evaluando confianza.
            # Si el fallo es atribuible (firma valida, rol falso), el intento es
            # evidencia fuerte contra el emisor; si no (firma invalida, replay),
            # no se sabe quien lo envio y no se castiga al emisor declarado.
            threshold = self.trust_engine.threshold.current()
            newly_isolated: list[str] = []
            if cfg.trust and attributable:
                culprit = channel_sender if channel_sender is not None else message.sender_id
                self.trust_engine.reputation.update(culprit, -0.6)
                newly_isolated = self._apply_remediation(culprit, PolicyDecision.REJECT, reasons)
            self._audit(effective_message, PolicyDecision.REJECT, 0.0, threshold, provenance_trusted, reasons)
            return RoutingResult(
                PolicyDecision.REJECT, 0.0, threshold, reasons,
                newly_isolated=newly_isolated, latency_s=time.perf_counter() - started,
            )

        if cfg.remediation and message.sender_id in self.isolated:
            decision = PolicyDecision.QUARANTINE
            reasons.append("[Remediacion] emisor aislado: todo su contenido va a cuarentena")
            sanitized = self._sanitize(message, reasons)
            tokens_used += sanitized.tokens_used if sanitized else 0
            self._audit(effective_message, decision, 0.0, self.trust_engine.threshold.current(), False, reasons)
            return RoutingResult(
                decision, 0.0, self.trust_engine.threshold.current(), reasons,
                sanitized=sanitized, tokens_used=tokens_used, latency_s=time.perf_counter() - started,
            )

        # --- Capa C: confianza dinamica ---
        if cfg.trust:
            evaluation = self.trust_engine.evaluate(message, True, provenance_trusted)
            tokens_used += evaluation.tokens_used
            reasons.append(f"[Capa C] score={evaluation.score:.2f} umbral={evaluation.threshold:.2f}")
            reasons.extend(f"[Capa C] {r}" for r in evaluation.reasons)
            layer_c_decision = evaluation.decision
            score, threshold = evaluation.score, evaluation.threshold
        else:
            layer_c_decision = PolicyDecision.ACCEPT
            score, threshold = 1.0, 0.0
            reasons.append("[Capa C] desactivada: se acepta sin puntaje de confianza")

        final_decision = layer_c_decision
        if requires_quarantine and final_decision in DELIVERING_DECISIONS:
            # La procedencia puede forzar cuarentena incluso si el score es alto:
            # defensa en profundidad, ninguna capa por si sola decide "aceptar".
            # Aplica tambien a DEGRADE: degradar el peso sigue entregando el
            # contenido, y el contenido no confiable no debe llegar sin sanear.
            final_decision = PolicyDecision.QUARANTINE
            reasons.append("[Capa B] cuarentena forzada por procedencia pese a score alto")

        if not action_ok:
            final_decision = PolicyDecision.REJECT
            reasons.append("[Capa B] accion rechazada por falta de capacidad")
            if cfg.trust and layer_c_decision in DELIVERING_DECISIONS:
                # La Capa C no vio nada sospechoso en el contenido, asi que esta
                # senal (accion no autorizada) todavia no se reflejo en la reputacion.
                self.trust_engine.reputation.update(message.sender_id, -0.3)

        sanitized = None
        if final_decision == PolicyDecision.QUARANTINE:
            sanitized = self._sanitize(message, reasons)
            tokens_used += sanitized.tokens_used if sanitized else 0

        newly_isolated = self._apply_remediation(message.sender_id, final_decision, reasons) if cfg.trust else []

        self._audit(effective_message, final_decision, score, threshold, provenance_trusted, reasons)
        return RoutingResult(
            final_decision, score, threshold, reasons,
            sanitized=sanitized, newly_isolated=newly_isolated,
            tokens_used=tokens_used, latency_s=time.perf_counter() - started,
        )

    # -------------------------------------------------------------- helpers
    def _sanitize(self, message: Message, reasons: list[str]) -> Optional[SanitizedContent]:
        if not self.config.quarantine_model:
            return None
        sanitized = self.quarantine_model.sanitize(message.body)
        if sanitized.had_instructions:
            reasons.append(
                f"[Cuarentena] modelo aislado elimino {len(sanitized.removed_instructions)} "
                "instruccion(es) embebida(s); solo se conservan datos"
            )
        return sanitized

    def _apply_remediation(self, agent_id: str, decision: PolicyDecision, reasons: list[str]) -> list[str]:
        if not self.config.remediation or agent_id in self.isolated:
            return []
        if decision in BLOCKING_DECISIONS:
            self._blocked_count[agent_id] = self._blocked_count.get(agent_id, 0) + 1
        return self.check_remediation(agent_id, reasons)

    def check_remediation(self, agent_id: str, reasons: Optional[list[str]] = None) -> list[str]:
        """Aísla al agente si cruzó algún umbral de la política. Devuelve los
        agentes recién aislados (vacío o `[agent_id]`)."""
        if not (self.config.trust and self.config.remediation) or agent_id in self.isolated:
            return []
        reputation = self.trust_engine.reputation.score(agent_id)
        blocked = self._blocked_count.get(agent_id, 0)
        cause = None
        if reputation < self.remediation.isolate_below:
            cause = f"reputacion {reputation:.2f} < {self.remediation.isolate_below:.2f}"
        elif blocked >= self.remediation.max_blocked:
            cause = f"{blocked} mensajes bloqueados"
        if cause is None:
            return []
        self.isolate(agent_id, cause)
        if reasons is not None:
            reasons.append(f"[Remediacion] agente '{agent_id}' aislado ({cause}); token revocado")
        return [agent_id]

    def _effective_provenance(self, message: Message) -> tuple[ProvenanceTag | None, list[str]]:
        """Etiqueta que el bus realmente cree, a partir de la declarada.

        Solo puede quitar confianza, nunca añadirla:
        - fuentes no confiables por defecto (documentos, herramientas) nunca
          se vuelven confiables por decision del emisor;
        - AGENT solo es confiable si el origen es el propio emisor (un reenvio
          de contenido ajeno no se puede verificar sin la firma del autor);
        - USER solo es confiable si lo retransmite el orquestador, que es el
          punto de entrada del humano (un worker no puede "hablar por el usuario");
        - un emisor contaminado por contenido no confiable contamina todo lo
          que envia.
        """
        declared = message.provenance
        if declared is None:
            return None, []

        notes: list[str] = []
        trusted = declared.trusted
        chain = declared.chain

        if trusted and declared.source in UNTRUSTED_BY_DEFAULT:
            trusted = False
            notes.append(f"el emisor no puede marcar como confiable una fuente {declared.source.value}")
        if trusted and declared.source == ProvenanceSource.AGENT and declared.origin_id != message.sender_id:
            trusted = False
            notes.append(f"origen '{declared.origin_id}' distinto del emisor: contenido reenviado no verificable")
        if (
            trusted
            and declared.source == ProvenanceSource.USER
            and self.registry.official_role(message.sender_id) != AgentRole.ORCHESTRATOR
        ):
            trusted = False
            notes.append("solo el orquestador puede retransmitir contenido del usuario como confiable")
        if message.sender_id in self._taint:
            taint_origins = self._taint[message.sender_id]
            if trusted:
                trusted = False
                notes.append(f"emisor contaminado por contenido no confiable ({', '.join(taint_origins)})")
            chain = chain + tuple(origin for origin in taint_origins if origin not in chain)

        if trusted == declared.trusted and chain == declared.chain:
            return declared, notes
        return replace(declared, trusted=trusted, chain=chain), notes

    def _authorize_action(self, message: Message) -> tuple[bool, str]:
        return self.authorize_action(message.sender_id, message.action)

    def authorize_action(self, agent_id: str, action: Optional[str]) -> tuple[bool, str]:
        """¿Puede `agent_id` ejecutar `action`? Verifica token, titular y cadena.

        Es la misma comprobación que aplica `route` a `message.action`; se
        expone para guardar llamadas a herramientas que no viajan como mensaje
        entre agentes (p. ej. `tools/call` de MCP).
        """
        if action is None:
            return check_action_capability(None, None)
        if self.config.remediation and agent_id in self.isolated:
            return False, f"agente '{agent_id}' aislado por remediacion: sin capacidades"
        token = self._capability_tokens.get(agent_id)
        if token is None:
            return check_action_capability(None, action)
        if token.subject != agent_id:
            return False, f"el token pertenece a '{token.subject}', no al emisor '{agent_id}'"
        token_check = verify_capability_token(self.registry, token)
        if not token_check.ok:
            return False, token_check.reason
        return check_action_capability(token, action)

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
