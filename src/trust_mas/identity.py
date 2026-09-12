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

from nacl.exceptions import BadSignatureError
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
    """Registro de nonces vistos para bloquear reenvío de mensajes capturados."""

    def __init__(self) -> None:
        self._seen: set[tuple[str, str]] = set()

    def check_and_record(self, sender_id: str, nonce: str) -> bool:
        """Devuelve True si el nonce es nuevo (mensaje aceptable); False si es replay."""
        key = (sender_id, nonce)
        if key in self._seen:
            return False
        self._seen.add(key)
        return True

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


def verify_message(
    registry: IdentityRegistry,
    nonce_store: NonceStore,
    message: Message,
    now: Optional[float] = None,
) -> VerificationResult:
    now = now if now is not None else time.time()

    if not registry.known(message.sender_id):
        return VerificationResult(False, "emisor desconocido en el registro de identidad")

    official_role = registry.official_role(message.sender_id)
    if official_role != message.declared_role:
        return VerificationResult(
            False,
            f"suplantacion de rol: registrado={official_role}, declarado={message.declared_role}",
        )

    if abs(now - message.timestamp) > NONCE_WINDOW_SECONDS:
        return VerificationResult(False, "timestamp fuera de ventana valida")

    if not nonce_store.check_and_record(message.sender_id, message.nonce):
        return VerificationResult(False, "nonce repetido (posible ataque de repeticion)")

    verify_key = registry.verify_key_for(message.sender_id)
    assert verify_key is not None
    try:
        verify_key.verify(message.signing_payload(), message.signature)
    except BadSignatureError:
        return VerificationResult(False, "firma invalida")

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

    Lanza ValueError si se solicitan acciones fuera del alcance del token padre
    o si ya no queda profundidad de delegación disponible.
    """
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
    )
    child.signature = delegator_keypair.sign(_token_signing_payload(child))
    return child


def verify_capability_token(registry: IdentityRegistry, token: CapabilityToken) -> VerificationResult:
    if token.is_expired():
        return VerificationResult(False, "token de capacidad expirado")
    verify_key = registry.verify_key_for(token.issuer)
    if verify_key is None:
        return VerificationResult(False, "emisor del token desconocido")
    try:
        verify_key.verify(_token_signing_payload(token), token.signature)
    except BadSignatureError:
        return VerificationResult(False, "firma de token invalida")
    return VerificationResult(True, "token valido")


def _token_signing_payload(token: CapabilityToken) -> bytes:
    parts = [
        token.issuer,
        token.subject,
        ",".join(sorted(token.actions)),
        str(token.max_delegation_depth),
        f"{token.expiry:.6f}",
    ]
    return "\x1f".join(parts).encode("utf-8")
