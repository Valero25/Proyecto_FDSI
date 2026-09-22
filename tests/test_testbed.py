import random
from dataclasses import replace

import pandas as pd
import pytest

from trust_mas.config import DefenseConfig
from trust_mas.testbed.analysis import analyze, bootstrap_ci, summary_markdown
from trust_mas.testbed.attacks import ALL_ATTACKS, AdaptiveAdversary, make_strategy
from trust_mas.testbed.episode import EpisodeConfig, run_episode
from trust_mas.testbed.experiment import GridSpec, run_grid
from trust_mas.testbed.report import build_report
from trust_mas.testbed.tasks import generate_task
from trust_mas.testbed.topologies import HONEST_IDS, TOPOLOGIES, build_topology

NONE = DefenseConfig.none()
FULL = DefenseConfig.full()


def episodes(attack: str, defense: DefenseConfig, n: int = 10, **kw):
    return [run_episode(EpisodeConfig(attack=attack, defense=defense, seed=s, **kw)) for s in range(n)]


def asr(results) -> float:
    return sum(r.attack_success for r in results) / len(results)


# ------------------------------------------------------------ tareas y topologías
def test_tarea_tiene_verdad_y_objetivo_distintos():
    rng = random.Random(3)
    for i in range(50):
        task = generate_task(rng, i)
        assert task.truth in task.options and task.target in task.options
        assert task.truth != task.target
        a, b = task.question.split("Cuánto es ")[1].rstrip("?").split(" × ")
        assert task.options[task.truth] == str(int(a) * int(b))


@pytest.mark.parametrize("name", TOPOLOGIES)
def test_topologias_incluyen_a_todos_y_el_nodo_de_decision_es_honesto(name):
    mal = ("infiltrado_1", "infiltrado_2")
    topo = build_topology(name, mal)
    assert set(topo.order) == set(HONEST_IDS) | set(mal)
    assert topo.decision_node in HONEST_IDS
    for agent in topo.order:
        # todo agente puede hablar con alguien
        assert topo.out_neighbors(agent) or agent == topo.order[-1]


def test_topologia_desconocida():
    with pytest.raises(ValueError):
        build_topology("anillo")


def test_perfil_de_ataque_desconocido():
    with pytest.raises(ValueError):
        make_strategy("A9")


# ------------------------------------------------------------- episodios
def test_episodio_es_reproducible_con_la_misma_semilla():
    cfg = EpisodeConfig(topology="estrella", attack="A2", seed=7)
    a, b = run_episode(cfg), run_episode(cfg)
    fields = ("final_answer", "n_messages", "n_quarantine", "n_infected", "tp", "fp", "rounds_to_detection")
    assert all(getattr(a, f) == getattr(b, f) for f in fields)


@pytest.mark.parametrize("attack", ALL_ATTACKS)
def test_todos_los_ataques_corren_con_y_sin_defensas(attack):
    for defense in (NONE, FULL):
        result = run_episode(EpisodeConfig(attack=attack, defense=defense, seed=1))
        assert result.audit_ok
        assert result.n_messages > 0
        if attack == "ninguno":
            assert result.n_malicious == 0 and not result.attack_success


def test_sin_ataque_no_hay_falsos_positivos_en_malla():
    for r in episodes("ninguno", FULL, n=10):
        assert r.fp == 0


def test_a3_captura_la_decision_sin_defensas_y_la_capa_a_lo_impide():
    base = episodes("A3", NONE)
    assert all(r.decision_captured for r in base)
    assert asr(base) == 1.0
    only_a = episodes("A3", DefenseConfig.from_name("A"))
    assert not any(r.decision_captured for r in only_a)
    assert asr(only_a) < 0.5


def test_a3_con_todas_las_capas_identifica_al_infiltrado():
    results = episodes("A3", FULL)
    assert all("infiltrado_1" in r.flagged_ids for r in results)


def test_a2_se_propaga_sin_defensas_y_la_capa_b_lo_contiene():
    base = episodes("A2", NONE)
    assert sum(r.n_infected for r in base) > 0
    assert asr(base) > 0.8
    only_b = episodes("A2", DefenseConfig.from_name("B"))
    assert sum(r.n_infected for r in only_b) == 0
    assert asr(only_b) < 0.5
    assert all(r.n_quarantine > 0 for r in only_b)


def test_a4_sin_capa_a_incrimina_a_honestos_suplantados():
    # Sin identidad, los votos sybil a nombre de honestos hunden su reputación.
    only_c = episodes("A4", DefenseConfig.from_name("C"))
    assert sum(r.fp for r in only_c) > 0
    full = episodes("A4", FULL)
    assert sum(r.fp for r in full) < sum(r.fp for r in only_c)


def test_adversario_adaptativo_cambia_de_tactica_cuando_lo_bloquean():
    result = run_episode(EpisodeConfig(attack="adaptativo", defense=FULL, seed=0))
    tactics = result.adaptive_history.split(">")
    assert tactics[0] == "A3"
    assert len(set(tactics)) > 1


def test_adversario_adaptativo_sin_bloqueos_no_escala():
    strategy = AdaptiveAdversary()
    assert strategy.current == "A3"
    result = run_episode(EpisodeConfig(attack="adaptativo", defense=NONE, seed=0))
    assert set(result.adaptive_history.split(">")) == {"A3"}


def test_defensas_llm_consumen_tokens_y_heuristicas_no():
    heuristic = run_episode(EpisodeConfig(attack="ninguno", n_malicious=0, defense=FULL, seed=2))
    llm = run_episode(EpisodeConfig(attack="ninguno", n_malicious=0, defense=FULL, seed=2, llm_defenses=True))
    assert llm.tokens_defense > heuristic.tokens_defense
    assert llm.latency_defense_s > heuristic.latency_defense_s


def test_episodio_con_llm_real_simulado():
    """Modo LLM: los agentes honestos redactan con el modelo (aquí un doble)."""

    class EchoTruthLLM:
        def __init__(self, truth: str) -> None:
            self.truth = truth
            self.calls = 0

        def invoke(self, prompt: str):
            from types import SimpleNamespace

            self.calls += 1
            return SimpleNamespace(content=f"RESPUESTA: {self.truth} | CONFIANZA: 0.8. Lo calcule dos veces.")

    cfg = EpisodeConfig(attack="A1", defense=FULL, seed=4, rounds=2)
    from trust_mas.testbed.episode import Episode

    episode = Episode(cfg, llm=None)
    llm = EchoTruthLLM(episode.task.truth)
    result = Episode(cfg, llm=llm).run()
    assert llm.calls > 0
    assert result.final_answer == result.truth
    assert result.tokens_agents > 0


# ------------------------------------------------------ experimento y análisis
def small_grid():
    spec = GridSpec(
        topologies=("malla", "estrella"),
        attacks=("A1", "A2", "A3", "A4", "A5", "adaptativo"),
        fractions=(1,),
        models=("intermedio",),
        defenses=tuple(DefenseConfig.from_name(n) for n in ("ninguna", "A", "B", "C", "ABC")),
        runs=3,
        rounds=3,
    )
    return spec, pd.DataFrame(run_grid(spec.configs(), workers=1))


def test_grid_tiene_el_tamano_declarado():
    spec, df = small_grid()
    assert len(df) == spec.size()
    assert set(df.defense) == {"ninguna", "A", "B", "C", "ABC"}


def test_analisis_y_panel_sobre_un_grid_pequeno():
    _, df = small_grid()
    curve = pd.DataFrame(
        run_grid(
            [replace(c, base_threshold=t) for t in (0.4, 0.6) for c in GridSpec(
                topologies=("malla",), attacks=("A2",), fractions=(1,), models=("intermedio",),
                defenses=(FULL,), runs=2, rounds=3,
            ).configs()],
            workers=1,
        )
    )
    analysis = analyze(df, curve=curve)
    by = analysis.by_config.set_index("defense")
    assert by.loc["ABC", "asr"] < by.loc["ninguna", "asr"]
    assert by.loc["ninguna", "reduccion_asr"] == 0.0
    assert set(analysis.targets.columns) >= {"meta", "valor", "cumple"}
    assert len(analysis.hypotheses) >= 2
    assert analysis.curve is not None and len(analysis.curve) == 2
    html = build_report(analysis, preset="test", n_episodes=len(df))
    assert "<svg" in html and "Metas de la propuesta" in html and "prefers-color-scheme:dark" in html
    assert "Resumen de resultados" in summary_markdown(analysis)


def test_bootstrap_ci_contiene_la_media():
    point, lo, hi = bootstrap_ci([0, 1] * 50)
    assert lo <= point <= hi
    assert point == 0.5


def test_experimento_con_llm_real_simulado(tmp_path):
    from types import SimpleNamespace

    from trust_mas.testbed.analysis import load
    from trust_mas.testbed.experiment import run_llm_experiment

    class ParrotLLM:
        def invoke(self, prompt: str):
            return SimpleNamespace(content="RESPUESTA: A | CONFIANZA: 0.7. Revisado.")

    path = run_llm_experiment(
        ParrotLLM(), tmp_path, defenses=("ninguna", "ABC"), runs=1, rounds=2,
        topologies=("malla",), attacks=("A2",), verbose=False,
    )
    df = load(path)
    assert len(df) == 4  # (sin ataque + A2) x 2 configuraciones
    assert (df.tokens_agents > 0).all()
    analyze(df)


def test_build_chat_model_sin_clave_o_proveedor_invalido(monkeypatch):
    from trust_mas.llm import LLMConfigError, build_chat_model

    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    with pytest.raises(LLMConfigError):
        build_chat_model("gemini")
    with pytest.raises(LLMConfigError):
        build_chat_model("gpt-local")
