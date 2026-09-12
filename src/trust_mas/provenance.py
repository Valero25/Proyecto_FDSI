"""Capa B - Procedencia: etiquetado de origen, control de flujo hacia el modelo
en cuarentena, y autorización por acción individual.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import CapabilityToken, Message, ProvenanceSource, ProvenanceTag

# Fuentes que nunca deben poder disparar una acción con herramientas directamente:
# su contenido debe pasar primero por un modelo en cuarentena sin autoridad de planear.
UNTRUSTED_BY_DEFAULT = {ProvenanceSource.EXTERNAL_DOC, ProvenanceSource.TOOL_OUTPUT}


def tag_provenance(source: ProvenanceSource, origin_id: str, trusted: bool | None = None, chain: tuple[str, ...] = ()) -> ProvenanceTag:
    if trusted is None:
        trusted = source not in UNTRUSTED_BY_DEFAULT
    return ProvenanceTag(source=source, origin_id=origin_id, trusted=trusted, chain=chain)


@dataclass
class ProvenanceVerdict:
    requires_quarantine: bool
    reason: str


class QuarantineEngine:
    """Decide si un mensaje debe enrutarse al modelo en cuarentena antes de
    llegar a un agente con autoridad para planear o invocar herramientas.
    """

    def evaluate(self, message: Message) -> ProvenanceVerdict:
        tag = message.provenance
        if tag is None:
            return ProvenanceVerdict(True, "sin etiqueta de procedencia: se trata como no confiable")

        if not tag.trusted:
            return ProvenanceVerdict(
                True, f"origen no confiable ({tag.source.value}:{tag.origin_id}): requiere cuarentena"
            )

        if message.action is not None and tag.source in UNTRUSTED_BY_DEFAULT:
            return ProvenanceVerdict(
                True, "contenido de fuente no confiable intenta disparar una accion directamente"
            )

        return ProvenanceVerdict(False, "procedencia confiable")


def check_action_capability(token: CapabilityToken | None, action: str | None) -> tuple[bool, str]:
    """Autorización por acción: cada llamada a herramienta se valida contra el token."""
    if action is None:
        return True, "sin accion asociada"
    if token is None:
        return False, f"accion '{action}' solicitada sin token de capacidad"
    if token.is_expired():
        return False, "token de capacidad expirado"
    if not token.allows(action):
        return False, f"token no autoriza la accion '{action}'"
    return True, "accion autorizada por token de capacidad"
