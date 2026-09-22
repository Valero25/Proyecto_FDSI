"""Ejecuta el banco de pruebas de TRUST-MAS y genera tablas y panel de resultados.

Uso:
    python run_experiment.py                      # preset "rapido" (minutos)
    python run_experiment.py --preset completo    # diseño de la propuesta (>= 30 corridas/celda)
    python run_experiment.py --solo-analisis      # rehace tablas y panel desde results/*.csv
    python run_experiment.py --workers 4 --out results/

Salida (en --out):
    factorial.csv, curva.csv, costo.csv   episodios crudos (una fila por corrida)
    tablas/*.csv, tablas/analisis.json    métricas agregadas con IC 95 %
    resumen.md                            metas, ablación e hipótesis
    panel.html                            panel de resultados (escena 7 de la demo)
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")  # acentos legibles tambien al redirigir en Windows

from trust_mas.testbed.analysis import analyze, load, summary_markdown, write_tables  # noqa: E402
from trust_mas.testbed.experiment import PRESETS, run_experiment  # noqa: E402
from trust_mas.testbed.report import write_report  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Banco de pruebas TRUST-MAS")
    parser.add_argument("--preset", choices=sorted(PRESETS), default="rapido")
    parser.add_argument("--out", type=Path, default=Path("results"))
    parser.add_argument("--workers", type=int, default=None, help="procesos en paralelo (por defecto: nucleos - 1)")
    parser.add_argument("--solo-analisis", action="store_true", help="no correr episodios; reanalizar los CSV existentes")
    parser.add_argument(
        "--llm",
        choices=("gemini", "ollama"),
        help="corre ADEMAS un grid reducido con agentes honestos respaldados por un LLM real (llm.csv, llm_resumen.md)",
    )
    parser.add_argument("--llm-corridas", type=int, default=2, help="corridas por celda en el grid con LLM real")
    args = parser.parse_args()

    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    if args.llm:
        from trust_mas.llm import LLMConfigError, build_chat_model
        from trust_mas.testbed.experiment import run_llm_experiment

        try:
            llm = build_chat_model(args.llm)
        except LLMConfigError as exc:
            raise SystemExit(str(exc)) from None
        print(f"== llm ({args.llm}) ==", flush=True)
        llm_path = run_llm_experiment(llm, out, runs=args.llm_corridas)
        llm_analysis = analyze(load(llm_path))
        write_tables(llm_analysis, out / "tablas_llm")
        (out / "llm_resumen.md").write_text(summary_markdown(llm_analysis), encoding="utf-8")
        print(f"   -> {llm_path}, {out / 'llm_resumen.md'}")
    if not args.solo_analisis:
        for name, spec in PRESETS[args.preset].items():
            started = time.time()
            print(f"== {name}: {spec.size()} episodios ==", flush=True)
            path = run_experiment(name, spec, out, workers=args.workers)
            print(f"   -> {path} ({time.time() - started:.0f} s)", flush=True)

    factorial = load(out / "factorial.csv")
    curve = load(out / "curva.csv") if (out / "curva.csv").exists() else None
    cost = load(out / "costo.csv") if (out / "costo.csv").exists() else None
    analysis = analyze(factorial, curve=curve, cost=cost)
    write_tables(analysis, out / "tablas")
    summary = summary_markdown(analysis)
    (out / "resumen.md").write_text(summary, encoding="utf-8")
    report_path = write_report(analysis, out / "panel.html", preset=args.preset, n_episodes=len(factorial))
    print()
    print(summary)
    print(f"Panel de resultados: {report_path}")


if __name__ == "__main__":
    main()
