"""Agente simulado para el banco de pruebas: mantiene su propio par de claves
y firma sus mensajes antes de entregarlos al bus.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from .identity import KeyPair, NonceStore, sign_message
from .models import AgentRole, CapabilityToken, Message, ProvenanceTag


@dataclass
class SimulatedAgent:
    agent_id: str
    role: AgentRole
    keypair: KeyPair
    capability_token: Optional[CapabilityToken] = None

    def compose(
        self,
        recipient_id: str,
        body: str,
        conversation_digest: str,
        declared_role: Optional[AgentRole] = None,
        action: Optional[str] = None,
        provenance: Optional[ProvenanceTag] = None,
    ) -> Message:
        """Construye y firma un mensaje.

        `declared_role` normalmente coincide con `self.role`; el parámetro existe
        para poder simular en la demo un agente que intenta declarar un rol falso
        (lo cual la Capa A debe rechazar comparando contra el registro).
        """
        message = Message(
            sender_id=self.agent_id,
            recipient_id=recipient_id,
            declared_role=declared_role or self.role,
            body=body,
            conversation_digest=conversation_digest,
            nonce=NonceStore.new_nonce(),
            timestamp=time.time(),
            action=action,
            provenance=provenance,
        )
        return sign_message(self.keypair, message)
