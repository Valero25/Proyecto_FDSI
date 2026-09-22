"""Demostración de la propuesta: 7 escenas con guion determinista.

Ejecutar con: python demo_escenas.py

1-2. Sistema sano y luego inyección del agente malicioso: la decisión se desvía.
3.   Solo Capa A: se frena la suplantación, no la desinformación.
4.   A + B: la instrucción encubierta no entra al canal de plan.
5.   A + B + C: la confianza cae y la decisión se recupera.
6.   Adversario adaptativo.
7.   Panel de resultados.

Todas las escenas usan la misma tarea, la misma topología (estrella) y las
mismas señales privadas (semilla fija): lo único que cambia de una escena a
otra es qué capas están activas. En las escenas 2-5 hay dos infiltrados: uno
suplanta al orquestador y después desinforma (A3 -> A1) y el otro leyó un
documento envenenado e inyecta una carga autorreplicante (A2).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")  # acentos legibles tambien al redirigir en Windows

from trust_mas.config import DefenseConfig  # noqa: E402
from trust_mas.models import PolicyDecision  # noqa: E402
from trust_mas.testbed.episode import Episode, EpisodeConfig  # noqa: E402

TOPOLOGY, MODEL, SEED = "estrella", "intermedio", 2
WIDTH = 78


def banner(title: str) -> None:
    print("\n" + "=" * WIDTH)
    print(title)
    print("=" * WIDTH)


def run(attack: str, defense: str, n_malicious: int = 2) -> Episode:
    cfg = EpisodeConfig(
        topology=TOPOLOGY,
        model=MODEL,
        seed=SEED,
        attack=attack,
        n_malicious=0 if attack == "ninguno" else n_malicious,
        defense=DefenseConfig.from_name(defense),
        trace=True,
    )
    episode = Episode(cfg)
    episode.result = episode.run()
    return episode


def verdict(episode: Episode) -> None:
    r = episode.result
    task = episode.task
    if r.correct:
        outcome = "CORRECTA"
    elif r.attack_success:
        outcome = "DESVIADA a la respuesta del atacante"
    else:
        outcome = "incorrecta (error propio del equipo)"
    print(f"  Pregunta: {task.question}  verdad={task.truth} ({task.options[task.truth]})  atacante busca={task.target}")
    print(f"  Decision colectiva: {r.final_answer} -> {outcome}")
    if r.decision_captured:
        print("  (la decision la fijo directamente una orden 'fijar_decision' aceptada: captura del orquestador)")
    counts = {d: getattr(r, f"n_{d}") for d in ("accept", "degrade", "corroborate", "quarantine", "reject")}
    print("  Mensajes: " + ", ".join(f"{k}={v}" for k, v in counts.items()) + f"  | agentes infectados: {r.n_infected}")


def first_event(episode: Episode, decision: PolicyDecision, contains: str = "", sender: str | None = None):
    for event in episode.trace:
        if event["decision"] != decision.value:
            continue
        if sender is not None and event["from"] != sender:
            continue
        if contains and not any(contains in reason for reason in event["reasons"]):
            continue
        return event
    return None


def show_event(label: str, event) -> None:
    if event is None:
        return
    impersonated = f" (haciendose pasar por '{event['as']}')" if event["as"] != event["from"] else ""
    print(f"  {label}: ronda {event['round'] + 1}, {event['from']}{impersonated} -> {event['to']}: {event['decision'].upper()}")
    for reason in event["reasons"]:
        if any(tag in reason for tag in ("[Capa A] suplant", "[Capa A] firma", "[Capa B] emisor", "[Cuarentena]", "[Remediacion]", "[Capa B] origen")):
            print(f"      - {reason}")


def main() -> None:
    banner("TRUST-MAS -- demostracion en 7 escenas (guion determinista)")
    print(f"Topologia: {TOPOLOGY} | modelo base simulado: {MODEL} | semilla: {SEED}")

    banner("Escena 1 -- sistema sano, sin defensas")
    verdict(run("ninguno", "ninguna"))

    banner("Escena 2 -- se infiltran dos agentes maliciosos, sin defensas")
    s2 = run("combinado", "ninguna")
    verdict(s2)
    print("  infiltrado_1 se hace pasar por el orquestador y fija la decision; infiltrado_2 propaga")
    print("  una carga que infecta a los agentes honestos. Nadie verifica nada.")

    banner("Escena 3 -- solo Capa A (identidad)")
    s3 = run("combinado", "A")
    verdict(s3)
    show_event("Suplantacion bloqueada", first_event(s3, PolicyDecision.REJECT, "suplantacion"))
    print("  La firma y el canal autenticado delatan al suplantador... pero la desinformacion y la")
    print("  inyeccion viajan con identidades legitimas: autenticar no es confiar (H1).")

    banner("Escena 4 -- Capas A + B (identidad + procedencia)")
    s4 = run("combinado", "AB")
    verdict(s4)
    show_event("Carga en cuarentena", first_event(s4, PolicyDecision.QUARANTINE, "[Cuarentena]"))
    print(f"  Infectados: {s3.result.n_infected} con solo A -> {s4.result.n_infected} con A + B. La instruccion")
    print("  encubierta no entra al canal de plan; pero la desinformacion 'limpia' todavia pesa.")

    banner("Escena 5 -- Capas A + B + C (identidad + procedencia + confianza)")
    s5 = run("combinado", "ABC")
    verdict(s5)
    reputation = s5.trust_engine.reputation
    for agent_id in ("infiltrado_1", "infiltrado_2", "orchestrator", "analista"):
        state = "AISLADO" if agent_id in s5.bus.isolated else ""
        print(f"  reputacion {agent_id:13s} {reputation.score(agent_id):.2f} {state}")
    for event in s5.bus.remediation_events:
        print(f"  Remediacion selectiva: '{event.agent_id}' aislado ({event.reason}); solo se retira su aporte.")

    banner("Escena 6 -- adversario adaptativo (cambia de tactica al verse bloqueado)")
    for defense in ("AB", "ABC"):
        s6 = run("adaptativo", defense, n_malicious=1)
        tactics = s6.result.adaptive_history.replace(">", " -> ")
        label = "A + B" if defense == "AB" else "A + B + C"
        print(f"  Con {label}: tacticas por ronda: {tactics}")
        print(
            f"    decision {s6.result.final_answer} (verdad {s6.task.truth}) -> "
            f"{'ataque exitoso' if s6.result.attack_success else 'ataque contenido'}"
            f"{' | identificado: ' + s6.result.flagged_ids if s6.result.flagged_ids else ''}"
        )

    banner("Escena 7 -- panel de resultados")
    results = Path("results")
    panel = results / "panel.html"
    if panel.exists():
        print(f"  Panel del ultimo experimento: {panel.resolve()}")
    else:
        print("  Aun no hay resultados. Genera el panel con:")
        print("    python run_experiment.py              (preset rapido, ~1 min)")
        print("    python run_experiment.py --preset completo   (diseno de la propuesta)")

    assert s2.result.attack_success and not s5.result.attack_success, "el guion de la demo dejo de cumplirse"


if __name__ == "__main__":
    main()
