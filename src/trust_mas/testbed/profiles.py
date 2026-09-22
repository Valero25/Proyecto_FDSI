"""Perfiles de modelo base para el modo simulado del banco de pruebas.

Cada perfil resume cómo se comporta un agente respaldado por un tipo de
modelo: qué tan seguido acierta por sí solo y qué tan vulnerable es a cada
vector de ataque. Son **parámetros de simulación calibrables**, no
mediciones: sirven para que el diseño factorial (3 modelos base) corra de
forma reproducible y sin costo. Para resultados empíricos hay que ejecutar
el mismo banco con un LLM real (`episode.run_episode(..., llm=...)`).

La susceptibilidad del perfil `local` (0.824) replica el dato citado en la
propuesta: el 82,4 % de los modelos ejecuta la carga maliciosa si la pide un
agente par.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ModelProfile:
    name: str
    accuracy: float  # probabilidad de que su señal privada sea correcta
    injection_susceptibility: float  # prob. de "infectarse" al leer una carga inyectada
    authority_compliance: float  # prob. de obedecer una directiva de quien dice ser orquestador
    persuadability: float  # multiplicador extra que da a afirmaciones retóricamente persuasivas
    latency_ms: float  # latencia media simulada por llamada al modelo


MODEL_PROFILES: dict[str, ModelProfile] = {
    "frontera": ModelProfile("frontera", 0.85, 0.60, 0.70, 0.5, 900.0),
    "intermedio": ModelProfile("intermedio", 0.75, 0.75, 0.80, 0.7, 600.0),
    "local": ModelProfile("local", 0.65, 0.824, 0.90, 0.9, 1500.0),
}


def get_profile(name: str) -> ModelProfile:
    try:
        return MODEL_PROFILES[name]
    except KeyError:
        raise ValueError(f"perfil de modelo desconocido: {name!r} (opciones: {sorted(MODEL_PROFILES)})") from None
