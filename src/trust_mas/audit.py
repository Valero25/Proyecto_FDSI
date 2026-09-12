"""Registro de auditoría append-only con encadenamiento de hashes (estilo ledger).

Cada entrada incluye el hash de la anterior, de modo que alterar o borrar un
registro pasado invalida la cadena completa a partir de ese punto.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

GENESIS_HASH = "0" * 64


@dataclass
class AuditEntry:
    seq: int
    timestamp: float
    sender_id: str
    recipient_id: str
    decision: str
    score: float
    threshold: float
    provenance_source: str
    provenance_trusted: bool
    reasons: list[str]
    content_hash: str
    prev_hash: str
    entry_hash: str = field(default="")

    def canonical_body(self) -> str:
        body = asdict(self)
        body.pop("entry_hash", None)
        return json.dumps(body, sort_keys=True)


class AuditLog:
    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path
        self._entries: list[AuditEntry] = []
        self._last_hash = GENESIS_HASH

    def append(
        self,
        sender_id: str,
        recipient_id: str,
        decision: str,
        score: float,
        threshold: float,
        provenance_source: str,
        provenance_trusted: bool,
        reasons: list[str],
        content: str,
    ) -> AuditEntry:
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        entry = AuditEntry(
            seq=len(self._entries),
            timestamp=time.time(),
            sender_id=sender_id,
            recipient_id=recipient_id,
            decision=decision,
            score=score,
            threshold=threshold,
            provenance_source=provenance_source,
            provenance_trusted=provenance_trusted,
            reasons=reasons,
            content_hash=content_hash,
            prev_hash=self._last_hash,
        )
        entry.entry_hash = hashlib.sha256(entry.canonical_body().encode("utf-8")).hexdigest()
        self._last_hash = entry.entry_hash
        self._entries.append(entry)

        if self.path is not None:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(entry), sort_keys=True) + "\n")

        return entry

    @property
    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def verify_chain(self) -> tuple[bool, str]:
        prev_hash = GENESIS_HASH
        for entry in self._entries:
            if entry.prev_hash != prev_hash:
                return False, f"cadena rota en seq={entry.seq}: prev_hash no coincide"
            expected_hash = hashlib.sha256(entry.canonical_body().encode("utf-8")).hexdigest()
            if expected_hash != entry.entry_hash:
                return False, f"entrada alterada en seq={entry.seq}: hash no coincide"
            prev_hash = entry.entry_hash
        return True, "cadena de auditoria integra"
