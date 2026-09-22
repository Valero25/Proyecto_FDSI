"""Adaptadores de protocolo: TRUST-MAS delante de A2A y de MCP.

No reimplementan los protocolos ni abren conexiones de red (el rediseño de
protocolos está fuera del alcance de la propuesta). Muestran dónde se
engancha la defensa en profundidad en cada uno:

- **A2A (agente a agente)**: `to_a2a` / `from_a2a` convierten un `Message`
  firmado en un sobre JSON-RPC 2.0 con método ``message/send`` y lo
  recuperan del otro lado. Los campos que TRUST-MAS necesita (firma, nonce,
  rol declarado, digest, procedencia) viajan en ``metadata.trustmas``; el
  receptor pasa el resultado de `from_a2a` por `MessageBus.route` como con
  cualquier otro mensaje.
- **MCP (agente a herramienta)**: `McpToolGuard` intercepta las peticiones
  ``tools/call``. Antes de ejecutar exige una capacidad para esa herramienta
  (Capa B, autorización por acción); después, etiqueta el resultado como
  ``tool_output`` no confiable y registra la ingestión, de modo que el
  agente que lo leyó queda contaminado (taint) hasta que se sanee.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .bus import MessageBus
from .models import AgentRole, Message, ProvenanceSource, ProvenanceTag
from .provenance import tag_provenance

A2A_METHOD = "message/send"
MCP_TOOLS_CALL = "tools/call"
UNAUTHORIZED_CODE = -32001  # error de aplicación JSON-RPC: acción no autorizada


# ------------------------------------------------------------------- A2A
def to_a2a(message: Message, request_id: Any = 1) -> dict:
    provenance = None
    if message.provenance is not None:
        provenance = {
            "source": message.provenance.source.value,
            "origin_id": message.provenance.origin_id,
            "trusted": message.provenance.trusted,
            "chain": list(message.provenance.chain),
        }
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": A2A_METHOD,
        "params": {
            "message": {
                "role": "agent",
                "messageId": message.nonce,
                "parts": [{"kind": "text", "text": message.body}],
                "metadata": {
                    "trustmas": {
                        "sender_id": message.sender_id,
                        "recipient_id": message.recipient_id,
                        "declared_role": message.declared_role.value,
                        "conversation_digest": message.conversation_digest,
                        "timestamp": message.timestamp,
                        "action": message.action,
                        "provenance": provenance,
                        "signature": base64.b64encode(message.signature).decode("ascii"),
                    }
                },
            }
        },
    }


def from_a2a(payload: dict | str) -> Message:
    """Reconstruye el `Message` desde un sobre A2A. No verifica nada: la
    verificación es trabajo del bus (`route`), igual que para cualquier otro
    mensaje. Lanza ValueError si el sobre no trae los metadatos de TRUST-MAS
    (fail-closed: sin firma no hay mensaje)."""
    if isinstance(payload, str):
        payload = json.loads(payload)
    if payload.get("method") != A2A_METHOD:
        raise ValueError(f"metodo A2A no soportado: {payload.get('method')!r}")
    msg = payload["params"]["message"]
    meta = (msg.get("metadata") or {}).get("trustmas")
    if not meta:
        raise ValueError("sobre A2A sin metadatos trustmas: no se puede verificar identidad")
    body = "".join(part.get("text", "") for part in msg.get("parts", []) if part.get("kind") == "text")
    provenance = None
    if meta.get("provenance"):
        p = meta["provenance"]
        provenance = ProvenanceTag(
            source=ProvenanceSource(p["source"]),
            origin_id=p["origin_id"],
            trusted=bool(p["trusted"]),
            chain=tuple(p.get("chain", ())),
        )
    return Message(
        sender_id=meta["sender_id"],
        recipient_id=meta["recipient_id"],
        declared_role=AgentRole(meta["declared_role"]),
        body=body,
        conversation_digest=meta["conversation_digest"],
        nonce=msg["messageId"],
        timestamp=float(meta["timestamp"]),
        action=meta.get("action"),
        signature=base64.b64decode(meta["signature"]),
        provenance=provenance,
    )


# ------------------------------------------------------------------- MCP
@dataclass
class GuardedToolResult:
    response: dict  # respuesta JSON-RPC lista para devolver al agente
    provenance: Optional[ProvenanceTag]  # etiqueta del resultado (None si se rechazó)
    authorized: bool
    reason: str


class McpToolGuard:
    """Guardián de ``tools/call`` para un agente concreto.

    `execute` es la función que realmente llama al servidor MCP (o a un doble
    en los tests): recibe la petición JSON-RPC y devuelve su respuesta.
    """

    def __init__(self, bus: MessageBus, agent_id: str, execute: Callable[[dict], dict]) -> None:
        self.bus = bus
        self.agent_id = agent_id
        self.execute = execute

    def call(self, request: dict) -> GuardedToolResult:
        if request.get("method") != MCP_TOOLS_CALL:
            raise ValueError(f"solo se guardan peticiones {MCP_TOOLS_CALL!r}")
        tool = request["params"]["name"]
        ok, reason = self.bus.authorize_action(self.agent_id, tool)
        self.bus.audit_log.append(
            sender_id=self.agent_id,
            recipient_id=f"mcp:{tool}",
            decision="accept" if ok else "reject",
            score=1.0 if ok else 0.0,
            threshold=0.0,
            provenance_source="tool_call",
            provenance_trusted=ok,
            reasons=[f"[Capa B] {reason}"],
            content=json.dumps(request, sort_keys=True),
        )
        if not ok:
            error = {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "error": {"code": UNAUTHORIZED_CODE, "message": f"TRUST-MAS: {reason}"},
            }
            return GuardedToolResult(error, None, False, reason)

        response = self.execute(request)
        tag = tag_provenance(ProvenanceSource.TOOL_OUTPUT, tool)
        # El agente acaba de leer contenido no confiable: queda contaminado.
        self.bus.record_ingestion(self.agent_id, tag)
        return GuardedToolResult(response, tag, True, reason)

    @staticmethod
    def result_text(response: dict) -> str:
        content = (response.get("result") or {}).get("content", [])
        return "".join(item.get("text", "") for item in content if item.get("type") == "text")
