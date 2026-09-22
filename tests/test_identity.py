import time

import pytest

from trust_mas.identity import (
    IdentityRegistry,
    KeyPair,
    NonceStore,
    _token_signing_payload,
    attenuate_capability_token,
    issue_capability_token,
    sign_message,
    verify_capability_token,
    verify_message,
)
from trust_mas.models import AgentRole, CapabilityToken, Message, ProvenanceSource
from trust_mas.provenance import tag_provenance


def make_registry_with_agent(agent_id: str, role: AgentRole) -> tuple[IdentityRegistry, KeyPair]:
    registry = IdentityRegistry()
    kp = KeyPair.generate()
    registry.register_agent(agent_id, kp.verify_key_bytes(), role)
    return registry, kp


def make_message(sender_id: str, role: AgentRole, body: str = "hola") -> Message:
    return Message(
        sender_id=sender_id,
        recipient_id="dest",
        declared_role=role,
        body=body,
        conversation_digest="digest",
        nonce=NonceStore.new_nonce(),
        timestamp=time.time(),
    )


def test_firma_valida_pasa_verificacion():
    registry, kp = make_registry_with_agent("a1", AgentRole.WORKER)
    msg = sign_message(kp, make_message("a1", AgentRole.WORKER))
    result = verify_message(registry, NonceStore(), msg)
    assert result.ok, result.reason


def test_cuerpo_alterado_invalida_firma():
    registry, kp = make_registry_with_agent("a1", AgentRole.WORKER)
    msg = sign_message(kp, make_message("a1", AgentRole.WORKER))
    msg.body = "cuerpo modificado tras firmar"
    result = verify_message(registry, NonceStore(), msg)
    assert not result.ok


def test_suplantacion_de_rol_se_rechaza():
    registry, kp = make_registry_with_agent("a1", AgentRole.WORKER)
    msg = sign_message(kp, make_message("a1", AgentRole.ORCHESTRATOR))  # declara rol falso
    result = verify_message(registry, NonceStore(), msg)
    assert not result.ok
    assert "suplantacion de rol" in result.reason


def test_replay_de_nonce_se_bloquea():
    registry, kp = make_registry_with_agent("a1", AgentRole.WORKER)
    nonce_store = NonceStore()
    msg = sign_message(kp, make_message("a1", AgentRole.WORKER))
    first = verify_message(registry, nonce_store, msg)
    second = verify_message(registry, nonce_store, msg)
    assert first.ok
    assert not second.ok
    assert "repetido" in second.reason


def test_timestamp_fuera_de_ventana_se_rechaza():
    registry, kp = make_registry_with_agent("a1", AgentRole.WORKER)
    msg = make_message("a1", AgentRole.WORKER)
    msg.timestamp -= 10_000  # muy en el pasado
    msg = sign_message(kp, msg)
    result = verify_message(registry, NonceStore(), msg)
    assert not result.ok
    assert "ventana" in result.reason


def test_atenuacion_no_puede_escalar_privilegios():
    issuer_kp = KeyPair.generate()
    parent = issue_capability_token(
        issuer_kp, "orchestrator", "worker_a", frozenset({"read_file"}), max_delegation_depth=1
    )
    with pytest.raises(ValueError):
        attenuate_capability_token(
            parent, issuer_kp, "worker_a", "worker_b", frozenset({"read_file", "transfer_funds"})
        )


def test_atenuacion_valida_reduce_alcance():
    issuer_kp = KeyPair.generate()
    delegator_kp = KeyPair.generate()
    parent = issue_capability_token(
        issuer_kp, "orchestrator", "worker_a", frozenset({"read_file", "send_email"}), max_delegation_depth=1
    )
    child = attenuate_capability_token(parent, delegator_kp, "worker_a", "worker_b", frozenset({"read_file"}))
    assert child.actions == frozenset({"read_file"})
    assert child.max_delegation_depth == 0


def test_atenuacion_agotada_falla():
    issuer_kp = KeyPair.generate()
    parent = issue_capability_token(
        issuer_kp, "orchestrator", "worker_a", frozenset({"read_file"}), max_delegation_depth=0
    )
    with pytest.raises(ValueError):
        attenuate_capability_token(parent, issuer_kp, "worker_a", "worker_b", frozenset({"read_file"}))


def test_verify_capability_token_detecta_firma_invalida():
    registry = IdentityRegistry()
    issuer_kp = KeyPair.generate()
    registry.register_agent("orchestrator", issuer_kp.verify_key_bytes(), AgentRole.ORCHESTRATOR)
    token = issue_capability_token(issuer_kp, "orchestrator", "worker_a", frozenset({"read_file"}), 1)
    token.signature = b"\x00" * len(token.signature)
    result = verify_capability_token(registry, token)
    assert not result.ok


def test_emisor_desconocido_se_rechaza():
    registry = IdentityRegistry()  # ningun agente registrado
    kp = KeyPair.generate()
    msg = sign_message(kp, make_message("fantasma", AgentRole.WORKER))
    result = verify_message(registry, NonceStore(), msg)
    assert not result.ok
    assert "desconocido" in result.reason


def test_nonce_de_distintos_emisores_no_colisiona():
    nonce_store = NonceStore()
    nonce = NonceStore.new_nonce()
    assert nonce_store.check_and_record("a1", nonce)
    # mismo nonce pero de otro emisor: no debe tratarse como repeticion
    assert nonce_store.check_and_record("a2", nonce)


def test_capability_token_expirado_se_rechaza():
    registry = IdentityRegistry()
    issuer_kp = KeyPair.generate()
    registry.register_agent("orchestrator", issuer_kp.verify_key_bytes(), AgentRole.ORCHESTRATOR)
    token = issue_capability_token(
        issuer_kp, "orchestrator", "worker_a", frozenset({"read_file"}), 1, ttl_seconds=-10.0
    )
    result = verify_capability_token(registry, token)
    assert not result.ok
    assert "expirado" in result.reason


def test_capability_token_emisor_desconocido_se_rechaza():
    registry = IdentityRegistry()  # el emisor del token nunca se registro
    issuer_kp = KeyPair.generate()
    token = issue_capability_token(issuer_kp, "orchestrator", "worker_a", frozenset({"read_file"}), 1)
    result = verify_capability_token(registry, token)
    assert not result.ok
    assert "desconocido" in result.reason


def test_firma_invalida_no_quema_el_nonce_del_mensaje_legitimo():
    # Un atacante que ve un mensaje legitimo en transito envia antes una
    # falsificacion con el mismo nonce: no debe provocar que el legitimo se
    # rechace despues como replay.
    registry, kp = make_registry_with_agent("a1", AgentRole.WORKER)
    nonce_store = NonceStore()
    legit = sign_message(kp, make_message("a1", AgentRole.WORKER))
    forged = make_message("a1", AgentRole.WORKER, body="falsificado")
    forged.nonce = legit.nonce
    forged.signature = b"\x00" * 64

    assert not verify_message(registry, nonce_store, forged).ok
    assert verify_message(registry, nonce_store, legit).ok


def test_procedencia_alterada_en_transito_invalida_firma():
    registry, kp = make_registry_with_agent("a1", AgentRole.WORKER)
    msg = make_message("a1", AgentRole.WORKER)
    msg.provenance = tag_provenance(ProvenanceSource.EXTERNAL_DOC, "doc.pdf")
    msg = sign_message(kp, msg)
    msg.provenance = tag_provenance(ProvenanceSource.AGENT, "a1")  # "lavada" tras firmar
    assert not verify_message(registry, NonceStore(), msg).ok


def test_nonce_store_depura_entradas_fuera_de_ventana():
    store = NonceStore(window_seconds=10.0)
    for i in range(100):
        assert store.check_and_record("a1", f"n{i}", timestamp=0.0, now=0.0)
    assert len(store) == 100
    assert store.check_and_record("a1", "nuevo", timestamp=100.0, now=100.0)
    assert len(store) == 1


def test_nonce_store_no_depura_nonces_aun_reutilizables():
    store = NonceStore(window_seconds=10.0)
    assert store.check_and_record("a1", "n", timestamp=0.0, now=0.0)
    # 5 s despues el mensaje original seguiria dentro de ventana: el replay debe fallar
    assert not store.check_and_record("a1", "n", timestamp=0.0, now=5.0)


def make_token_registry():
    registry = IdentityRegistry()
    keys = {name: KeyPair.generate() for name in ("orchestrator", "worker_a", "worker_b")}
    registry.register_agent("orchestrator", keys["orchestrator"].verify_key_bytes(), AgentRole.ORCHESTRATOR)
    registry.register_agent("worker_a", keys["worker_a"].verify_key_bytes(), AgentRole.WORKER)
    registry.register_agent("worker_b", keys["worker_b"].verify_key_bytes(), AgentRole.WORKER)
    return registry, keys


def test_token_autoemitido_por_worker_no_es_valido():
    registry, keys = make_token_registry()
    token = issue_capability_token(keys["worker_a"], "worker_a", "worker_a", frozenset({"transfer_funds"}), 0)
    result = verify_capability_token(registry, token)
    assert not result.ok
    assert "sin autoridad" in result.reason


def test_cadena_de_delegacion_valida_se_acepta():
    registry, keys = make_token_registry()
    root = issue_capability_token(
        keys["orchestrator"], "orchestrator", "worker_a", frozenset({"read_file", "send_email"}), 1
    )
    child = attenuate_capability_token(root, keys["worker_a"], "worker_a", "worker_b", frozenset({"read_file"}))
    result = verify_capability_token(registry, child)
    assert result.ok, result.reason


def test_cadena_de_delegacion_con_padre_ajeno_se_rechaza():
    # worker_b no es titular del token raiz: no puede colgar un hijo de el
    # aunque firme el hijo con su propia clave registrada.
    registry, keys = make_token_registry()
    root = issue_capability_token(keys["orchestrator"], "orchestrator", "worker_a", frozenset({"read_file"}), 1)
    forged = CapabilityToken("worker_b", "worker_b", frozenset({"read_file"}), 0, root.expiry, parent=root)
    forged.signature = keys["worker_b"].sign(_token_signing_payload(forged))
    result = verify_capability_token(registry, forged)
    assert not result.ok
    assert "cadena de delegacion rota" in result.reason


def test_cadena_de_delegacion_que_amplia_acciones_se_rechaza():
    registry, keys = make_token_registry()
    root = issue_capability_token(keys["orchestrator"], "orchestrator", "worker_a", frozenset({"read_file"}), 1)
    forged = CapabilityToken(
        "worker_a", "worker_b", frozenset({"read_file", "transfer_funds"}), 0, root.expiry, parent=root
    )
    forged.signature = keys["worker_a"].sign(_token_signing_payload(forged))
    result = verify_capability_token(registry, forged)
    assert not result.ok
    assert "amplia acciones" in result.reason


def test_atenuacion_por_quien_no_es_titular_falla():
    _, keys = make_token_registry()
    root = issue_capability_token(keys["orchestrator"], "orchestrator", "worker_a", frozenset({"read_file"}), 1)
    with pytest.raises(ValueError):
        attenuate_capability_token(root, keys["worker_b"], "worker_b", "worker_b", frozenset({"read_file"}))


def test_atenuacion_de_token_expirado_falla():
    _, keys = make_token_registry()
    root = issue_capability_token(
        keys["orchestrator"], "orchestrator", "worker_a", frozenset({"read_file"}), 1, ttl_seconds=-1
    )
    with pytest.raises(ValueError):
        attenuate_capability_token(root, keys["worker_a"], "worker_a", "worker_b", frozenset({"read_file"}))


def test_mensaje_sin_firma_se_rechaza_sin_excepcion():
    registry, _ = make_registry_with_agent("a1", AgentRole.WORKER)
    msg = make_message("a1", AgentRole.WORKER)  # signature = b"" por defecto
    result = verify_message(registry, NonceStore(), msg)
    assert not result.ok
    assert "firma invalida" in result.reason
