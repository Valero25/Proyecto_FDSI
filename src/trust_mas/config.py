"""Configuración de defensas: qué capas están activas en el bus.

Permite la línea base sin defensas y las 8 configuraciones de la ablación
(2^3 combinaciones de las capas A, B y C) que pide la fase F4 de la
propuesta, sin tocar el código de cada capa.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product


@dataclass(frozen=True)
class DefenseConfig:
    identity: bool = True  # Capa A: firma, rol del registro, ventana, anti-replay, integridad de flujo
    provenance: bool = True  # Capa B: procedencia efectiva, taint, cuarentena, capacidad por acción
    trust: bool = True  # Capa C: juez, reputación, grafo, umbral adaptativo, validación cruzada
    remediation: bool = True  # remediación selectiva (requiere Capa C: actúa sobre la reputación)
    quarantine_model: bool = True  # sanitizar lo que va a cuarentena en vez de solo descartarlo

    @property
    def name(self) -> str:
        layers = "".join(flag for flag, on in (("A", self.identity), ("B", self.provenance), ("C", self.trust)) if on)
        return layers or "ninguna"

    @classmethod
    def none(cls) -> "DefenseConfig":
        return cls(identity=False, provenance=False, trust=False, remediation=False, quarantine_model=False)

    @classmethod
    def full(cls) -> "DefenseConfig":
        return cls()

    @classmethod
    def from_name(cls, name: str) -> "DefenseConfig":
        name = name.upper()
        if name in ("NINGUNA", "NONE", "BASELINE", ""):
            return cls.none()
        unknown = set(name) - set("ABC")
        if unknown:
            raise ValueError(f"configuracion desconocida: {name!r} (usa combinaciones de A, B y C)")
        has_c = "C" in name
        return cls(
            identity="A" in name,
            provenance="B" in name,
            trust=has_c,
            remediation=has_c,
            quarantine_model="B" in name,
        )


def ablation_configs() -> list[DefenseConfig]:
    """Las 8 combinaciones de capas, empezando por la línea base sin defensas."""
    configs = []
    for identity, provenance, trust in product((False, True), repeat=3):
        configs.append(
            DefenseConfig(
                identity=identity,
                provenance=provenance,
                trust=trust,
                remediation=trust,
                quarantine_model=provenance,
            )
        )
    return sorted(configs, key=lambda c: (len(c.name) if c.name != "ninguna" else 0, c.name))
