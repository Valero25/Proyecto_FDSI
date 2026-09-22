"""Capa A - Identidad: firma Ed25519, roles anclados al registro, anti-repetición
y tokens de capacidad atenuables.

Detalle clave del diseño: el rol de un agente lo certifica el `IdentityRegistry`
(el "sistema"), nunca el propio mensaje. Un mensaje que declara un rol distinto
al registrado se rechaza en `verify_message`, lo que anula la suplantación de rol.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Optional

from nacl.exceptions import CryptoError
from nacl.signing import SigningKey, VerifyKey

from .models import AgentRole, CapabilityToken, Message

NONCE_WINDOW_SECONDS = 300.0  # ventana de validez del timestamp del mensaje


@dataclass
class KeyPair:
    """Par de claves Ed25519 de un agente."""

    signing_key: SigningKey
    verify_key: VerifyKey

    @classmethod
    def generate(cls) -> "KeyPair":
        sk = SigningKey.generate()
        return cls(signing_key=sk, verify_key=sk.verify_key)

    def sign(self, payload: bytes) -> bytes:
        return self.signing_key.sign(payload).signature

    def verify_key_bytes(self) -> bytes:
        return bytes(self.verify_key)


class IdentityRegistry:
    """Fuente de verdad de qué agente existe, con qué clave pública y qué rol.

    Verificar contra el registro (en vez de confiar en lo que el mensaje dice)
    es lo que impide que un agente comprometido se declare "orchestrator" para
    ganar autoridad que no tiene.
    """

    def __init__(self) -> None:
        self._verify_keys: dict[str, VerifyKey] = {}
        self._roles: dict[str, AgentRole] = {}

    def register_agent(self, agent_id: str, verify_key_bytes: bytes, role: AgentRole) -> None:
        self._verify_keys[agent_id] = VerifyKey(verify_key_bytes)
        self._roles[agent_id] = role

    def official_role(self, agent_id: str) -> Optional[AgentRole]:
        return self._roles.get(agent_id)

    def verify_key_for(self, agent_id: str) -> Optional[VerifyKey]:
        return self._verify_keys.get(agent_id)

    def known(self, agent_id: str) -> bool:
        return agent_id in self._verify_keys


class NonceStore:
    """Registro de nonces vistos para bloquear reenvío de mensajes capturados.

    Solo hace falta recordar un nonce mientras su mensaje podría pasar el
    chequeo de ventana de `verify_message`; pasado ese punto el replay ya se
    rechaza por timestamp, así que la entrada se depura y la memoria no crece
    sin límite en corridas largas del banco de pruebas.
    """

    def __init__(self, window_seconds: float = NONCE_WINDOW_SECONDS) -> None:
        self.window_seconds = window_seconds
        self._seen: dict[tuple[str, str], float] = {}

    def check_and_record(
        self,
        sender_id: str,
        nonce: str,
        timestamp: Optional[float] = None,
        now: Optional[float] = None,
    ) -> bool:
        """Devuelve True si el nonce es nuevo (mensaje aceptable); False si es replay.

        `timestamp` es el del mensaje (por defecto, `now`): determina hasta
        cuándo hay que recordar el nonce.
        """
        now = time.time() if now is None else now
        self._prune(now)
        key = (sender_id, nonce)
        if key in self._seen:
            return False
        self._seen[key] = now if timestamp is None else timestamp
        return True

    def _prune(self, now: float) -> None:
        expired = [key for key, ts in self._seen.items() if ts + self.window_seconds < now]
        for key in expired:
            del self._seen[key]

    def __len__(self) -> int:
        return len(self._seen)

    @staticmethod
    def new_nonce() -> str:
        return uuid.uuid4().hex


def sign_message(keypair: KeyPair, message: Message) -> Message:
    message.signature = keypair.sign(message.signing_payload())
    return message


@dataclass
class VerificationResult:
    ok: bool
    reason: str = ""
    # True si el fallo se puede atribuir al emisor (firma valida pero conducta
    # indebida, p. ej. declarar un rol falso). Solo esos fallos cuentan como
    # evidencia contra su reputacion.
    attributable: bool = False


def verify_message(
    registry: IdentityRegistry,
    nonce_store: NonceStore,
    message: Message,
    now: Optional[float] = None,
) -> VerificationResult:
    now = now if now is not None else time.time()

    if not registry.known(message.sender_id):
        return VerificationResult(False, "emisor desconocido en el registro de identidad")

    # La firma va primero: solo con una firma valida el fallo es atribuible
    # al emisor. Una falsificacion a nombre de un agente honesto no debe
    # castigar la reputacion de ese agente (si no, el atacante lo incrimina).
    verify_key = registry.verify_key_for(message.sender_id)
    assert verify_key is not None
    try:
        verify_key.verify(message.signing_payload(), message.signature)
    except CryptoError:  # firma incorrecta, vacia o de longitud invalida
        return VerificationResult(False, "firma invalida")

    official_role = registry.official_role(message.sender_id)
    if official_role != message.declared_role:
        return VerificationResult(
            False,
            f"suplantacion de rol: registrado={official_role}, declarado={message.declared_role}",
            attributable=True,
        )

    # Un mensaje viejo o repetido con firma valida es tipicamente un replay
    # hecho por un tercero: se rechaza, pero no se atribuye al firmante.
    if abs(now - message.timestamp) > NONCE_WINDOW_SECONDS:
        return VerificationResult(False, "timestamp fuera de ventana valida")

    # El nonce se registra DESPUES de validar la firma: si no, un mensaje
    # falsificado que reutiliza el nonce de uno legitimo en transito lo
    # "quemaria" y el legitimo se rechazaria como replay (DoS).
    if not nonce_store.check_and_record(message.sender_id, message.nonce, message.timestamp, now):
        return VerificationResult(False, "nonce repetido (posible ataque de repeticion)")

    return VerificationResult(True, "firma y rol verificados")


def issue_capability_token(
    issuer_keypair: KeyPair,
    issuer_id: str,
    subject: str,
    actions: frozenset[str],
    max_delegation_depth: int,
    ttl_seconds: float = 3600.0,
) -> CapabilityToken:
    token = CapabilityToken(
        issuer=issuer_id,
        subject=subject,
        actions=actions,
        max_delegation_depth=max_delegation_depth,
        expiry=time.time() + ttl_seconds,
    )
    payload = _token_signing_payload(token)
    token.signature = issuer_keypair.sign(payload)
    return token


def attenuate_capability_token(
    parent_token: CapabilityToken,
    delegator_keypair: KeyPair,
    delegator_id: str,
    new_subject: str,
    requested_actions: frozenset[str],
) -> CapabilityToken:
    """Delega un subconjunto de la autoridad propia; nunca puede ampliarla.

    Lanza ValueError si quien delega no es el titular del token padre, si el
    token padre expiró, si se solicitan acciones fuera de su alcance o si ya
    no queda profundidad de delegación disponible.
    """
    if parent_token.subject != delegator_id:
        raise ValueError("solo el titular del token padre puede delegarlo")
    if parent_token.is_expired():
        raise ValueError("token padre expirado: no se puede delegar")
    if parent_token.max_delegation_depth <= 0:
        raise ValueError("profundidad de delegacion agotada: no se puede atenuar mas")
    if not requested_actions.issubset(parent_token.actions):
        raise ValueError("intento de escalar privilegios: acciones fuera del token padre")

    child = CapabilityToken(
        issuer=delegator_id,
        subject=new_subject,
        actions=requested_actions,
        max_delegation_depth=parent_token.max_delegation_depth - 1,
        expiry=parent_token.expiry,
        parent=parent_token,
    )
    child.signature = delegator_keypair.sign(_token_signing_payload(child))
    return child


def verify_capability_token(
    registry: IdentityRegistry,
    token: CapabilityToken,
    now: Optional[float] = None,
    root_roles: frozenset[AgentRole] = frozenset({AgentRole.ORCHESTRATOR}),
) -> VerificationResult:
    """Verifica el token y toda su cadena de delegación hasta la raíz.

    Cada eslabón debe estar vigente y firmado por su emisor registrado; cada
    hijo debe haberlo emitido el titular del padre, sin ampliar acciones,
    expiración ni profundidad. La raíz debe emitirla un agente cuyo rol
    oficial esté en `root_roles`: si no, cualquier agente podría firmarse a sí
    mismo un token con `transfer_funds`.
    """
    now = time.time() if now is None else now
    current: Optional[CapabilityToken] = token
    while current is not None:
        if current.is_expired(now):
            return VerificationResult(False, "token de capacidad expirado")
        verify_key = registry.verify_key_for(current.issuer)
        if verify_key is None:
            return VerificationResult(False, "emisor del token desconocido")
        try:
            verify_key.verify(_token_signing_payload(current), current.signature)
        except CryptoError:  # firma incorrecta, vacia o de longitud invalida
            return VerificationResult(False, "firma de token invalida")

        parent = current.parent
        if parent is None:
            if registry.official_role(current.issuer) not in root_roles:
                return VerificationResult(
                    False, f"emisor raiz '{current.issuer}' sin autoridad para emitir tokens"
                )
        else:
            if current.issuer != parent.subject:
                return VerificationResult(False, "cadena de delegacion rota: emisor no es titular del padre")
            if not current.actions.issubset(parent.actions):
                return VerificationResult(False, "cadena de delegacion amplia acciones del padre")
            if current.max_delegation_depth >= parent.max_delegation_depth:
                return VerificationResult(False, "cadena de delegacion no reduce la profundidad")
            if current.expiry > parent.expiry:
                return VerificationResult(False, "cadena de delegacion extiende la expiracion")
        current = parent
    return VerificationResult(True, "token valido")


def _token_signing_payload(token: CapabilityToken) -> bytes:
    parts = [
        token.issuer,
        token.subject,
        ",".join(sorted(token.actions)),
        str(token.max_delegation_depth),
        f"{token.expiry:.6f}",
        # Liga el hijo a SU padre concreto: no se puede reusar la firma del
        # hijo colgandolo de otro token padre.
        token.parent.signature.hex() if token.parent is not None else "",
    ]
    return "\x1f".join(parts).encode("utf-8")
