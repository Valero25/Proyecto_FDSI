import time

from trust_mas.identity import NonceStore
from trust_mas.models import AgentRole, CapabilityToken, Message, ProvenanceSource
from trust_mas.provenance import QuarantineEngine, check_action_capability, tag_provenance


def make_message(provenance=None, action=None) -> Message:
    return Message(
        sender_id="a1",
        recipient_id="a2",
        declared_role=AgentRole.WORKER,
        body="cuerpo",
        conversation_digest="d",
        nonce=NonceStore.new_nonce(),
        timestamp=time.time(),
        action=action,
        provenance=provenance,
    )


def test_documento_externo_no_confiable_requiere_cuarentena():
    tag = tag_provenance(ProvenanceSource.EXTERNAL_DOC, "doc.pdf")
    verdict = QuarantineEngine().evaluate(make_message(provenance=tag))
    assert verdict.requires_quarantine


def test_agente_confiable_no_requiere_cuarentena():
    tag = tag_provenance(ProvenanceSource.AGENT, "orchestrator")
    verdict = QuarantineEngine().evaluate(make_message(provenance=tag))
    assert not verdict.requires_quarantine


def test_mensaje_sin_etiqueta_se_trata_como_no_confiable():
    verdict = QuarantineEngine().evaluate(make_message(provenance=None))
    assert verdict.requires_quarantine


def test_fuente_no_confiable_no_puede_disparar_accion_directa():
    tag = tag_provenance(ProvenanceSource.TOOL_OUTPUT, "tool1", trusted=True)
    verdict = QuarantineEngine().evaluate(make_message(provenance=tag, action="transfer_funds"))
    assert verdict.requires_quarantine


def test_accion_sin_token_se_rechaza():
    ok, _ = check_action_capability(None, "transfer_funds")
    assert not ok


def test_accion_sin_token_pero_sin_accion_pasa():
    ok, _ = check_action_capability(None, None)
    assert ok


def test_accion_fuera_de_alcance_del_token_se_rechaza():
    token = CapabilityToken(
        issuer="orchestrator",
        subject="worker_a",
        actions=frozenset({"read_file"}),
        max_delegation_depth=0,
        expiry=time.time() + 3600,
    )
    ok, reason = check_action_capability(token, "transfer_funds")
    assert not ok
    assert "no autoriza" in reason


def test_token_expirado_se_rechaza():
    token = CapabilityToken(
        issuer="orchestrator",
        subject="worker_a",
        actions=frozenset({"read_file"}),
        max_delegation_depth=0,
        expiry=time.time() - 1,
    )
    ok, _ = check_action_capability(token, "read_file")
    assert not ok


def test_accion_autorizada_con_token_valido_pasa():
    token = CapabilityToken(
        issuer="orchestrator",
        subject="worker_a",
        actions=frozenset({"read_file"}),
        max_delegation_depth=0,
        expiry=time.time() + 3600,
    )
    ok, reason = check_action_capability(token, "read_file")
    assert ok
    assert "autorizada" in reason


def test_tag_provenance_agente_es_confiable_por_defecto():
    tag = tag_provenance(ProvenanceSource.AGENT, "orchestrator")
    assert tag.trusted is True


def test_tag_provenance_documento_externo_no_es_confiable_por_defecto():
    tag = tag_provenance(ProvenanceSource.EXTERNAL_DOC, "doc.pdf")
    assert tag.trusted is False


def test_fuente_no_confiable_marcada_confiable_sin_accion_no_va_a_cuarentena():
    # trusted=True explicito anula el default de UNTRUSTED_BY_DEFAULT; sin accion
    # asociada, tampoco aplica la regla de "no puede disparar accion directamente".
    tag = tag_provenance(ProvenanceSource.TOOL_OUTPUT, "tool1", trusted=True)
    verdict = QuarantineEngine().evaluate(make_message(provenance=tag, action=None))
    assert not verdict.requires_quarantine
