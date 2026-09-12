"""Tipos de datos compartidos entre las tres capas de TRUST-MAS."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AgentRole(str, Enum):
    ORCHESTRATOR = "orchestrator"
    WORKER = "worker"
    TOOL = "tool"
    QUARANTINE = "quarantine"


class ProvenanceSource(str, Enum):
    AGENT = "agent"
    EXTERNAL_DOC = "external_doc"
    TOOL_OUTPUT = "tool_output"
    USER = "user"


class PolicyDecision(str, Enum):
    ACCEPT = "accept"
    DEGRADE = "degrade"
    CORROBORATE = "corroborate"
    QUARANTINE = "quarantine"
    REJECT = "reject"


@dataclass(frozen=True)
class ProvenanceTag:
    """Etiqueta de origen de un contenido (Capa B)."""

    source: ProvenanceSource
    origin_id: str
    trusted: bool
    chain: tuple[str, ...] = field(default_factory=tuple)


@dataclass
class CapabilityToken:
    """Token de capacidad atenuable: un agente no puede otorgar más de lo que tiene."""

    issuer: str
    subject: str
    actions: frozenset[str]
    max_delegation_depth: int
    expiry: float
    signature: bytes = b""

    def is_expired(self, now: Optional[float] = None) -> bool:
        return (now or time.time()) > self.expiry

    def allows(self, action: str) -> bool:
        return action in self.actions


@dataclass
class Message:
    """Un mensaje entre agentes, firmado antes de circular por el bus."""

    sender_id: str
    recipient_id: str
    declared_role: AgentRole
    body: str
    conversation_digest: str
    nonce: str
    timestamp: float
    action: Optional[str] = None
    signature: bytes = b""
    provenance: Optional[ProvenanceTag] = None

    def signing_payload(self) -> bytes:
        """Serialización canónica de los campos cubiertos por la firma.

        Deliberadamente NO incluye `provenance` (la añade el bus, no el emisor)
        ni `signature` (es el resultado de firmar esto).
        """
        parts = [
            self.sender_id,
            self.recipient_id,
            self.declared_role.value,
            self.body,
            self.conversation_digest,
            self.nonce,
            f"{self.timestamp:.6f}",
            self.action or "",
        ]
        return "\x1f".join(parts).encode("utf-8")
