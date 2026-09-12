import hashlib
import json

from trust_mas.audit import AuditLog


def test_cadena_integra_por_defecto():
    log = AuditLog()
    log.append("a1", "a2", "accept", 0.9, 0.5, "agent", True, ["ok"], "hola")
    log.append("a2", "a1", "accept", 0.9, 0.5, "agent", True, ["ok"], "respuesta")
    ok, _ = log.verify_chain()
    assert ok


def test_alterar_una_entrada_rompe_la_cadena():
    log = AuditLog()
    log.append("a1", "a2", "accept", 0.9, 0.5, "agent", True, ["ok"], "hola")
    log.append("a2", "a1", "accept", 0.9, 0.5, "agent", True, ["ok"], "respuesta")

    log.entries[0].score = 0.1  # manipulacion retroactiva del historial
    ok, reason = log.verify_chain()
    assert not ok
    assert "alterada" in reason


def test_seq_incrementa_y_prev_hash_encadena():
    log = AuditLog()
    e1 = log.append("a1", "a2", "accept", 0.9, 0.5, "agent", True, ["ok"], "m1")
    e2 = log.append("a1", "a2", "accept", 0.9, 0.5, "agent", True, ["ok"], "m2")
    assert e2.seq == e1.seq + 1
    assert e2.prev_hash == e1.entry_hash


def test_prev_hash_alterado_rompe_la_cadena():
    log = AuditLog()
    log.append("a1", "a2", "accept", 0.9, 0.5, "agent", True, ["ok"], "hola")
    log.append("a2", "a1", "accept", 0.9, 0.5, "agent", True, ["ok"], "respuesta")

    log.entries[1].prev_hash = "f" * 64  # se intenta reescribir el enlace a la entrada anterior
    ok, reason = log.verify_chain()
    assert not ok
    assert "rota" in reason


def test_cadena_vacia_es_integra():
    log = AuditLog()
    ok, _ = log.verify_chain()
    assert ok


def test_content_hash_es_sha256_del_contenido():
    log = AuditLog()
    entry = log.append("a1", "a2", "accept", 0.9, 0.5, "agent", True, ["ok"], "contenido de prueba")
    assert entry.content_hash == hashlib.sha256("contenido de prueba".encode("utf-8")).hexdigest()


def test_append_escribe_en_disco_cuando_hay_path(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path=path)
    log.append("a1", "a2", "accept", 0.9, 0.5, "agent", True, ["ok"], "hola")
    log.append("a2", "a1", "accept", 0.9, 0.5, "agent", True, ["ok"], "respuesta")

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    record = json.loads(lines[0])
    assert record["sender_id"] == "a1"
    assert record["seq"] == 0
