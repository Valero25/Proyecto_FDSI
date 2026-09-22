"""Chat models simulados (deterministas, sin red) para el banco de pruebas.

Cumplen el mismo protocolo que `ChatGoogleGenerativeAI`/`ChatOllama`
(`.invoke(prompt) -> objeto con .content`). Sirven para medir la
sobrecarga de tokens y latencia de un juez LLM y de un modelo en cuarentena
LLM sin pagar llamadas reales: la calidad del juicio es la del juez
heurístico, pero el costo contabilizado es el de una llamada de verdad.
"""

from __future__ import annotations

import re
from types import SimpleNamespace

from ..judge import HeuristicJudge
from ..quarantine_model import RuleBasedQuarantineModel

_BODY_RE = re.compile(r"<<<\n(.*)\n>>>", re.DOTALL)


def _extract_body(prompt: str) -> str:
    match = _BODY_RE.search(prompt)
    return match.group(1) if match else prompt


class SimulatedJudgeLLM:
    def __init__(self) -> None:
        self._judge = HeuristicJudge()
        self.calls = 0

    def invoke(self, prompt: str):
        self.calls += 1
        verdict = self._judge.judge(_extract_body(prompt))
        risk = min(1.0, verdict.penalty * 2)
        cats = ", ".join(verdict.categories) or "ninguna"
        return SimpleNamespace(content=f"RIESGO: {risk:.2f} | CATEGORIAS: {cats}")


class SimulatedQuarantineLLM:
    def __init__(self) -> None:
        self._rules = RuleBasedQuarantineModel()
        self.calls = 0

    def invoke(self, prompt: str):
        self.calls += 1
        sanitized = self._rules.sanitize(_extract_body(prompt))
        claim = sanitized.claim or "NINGUNA"
        conf = f"{sanitized.confidence:.2f}" if sanitized.confidence is not None else "NINGUNA"
        return SimpleNamespace(content=f"RESPUESTA: {claim} | CONFIANZA: {conf}")
