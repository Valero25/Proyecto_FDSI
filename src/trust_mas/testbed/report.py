"""Panel de resultados (escena 7 de la demo) como HTML autocontenido.

Sin dependencias externas: SVG en línea, tokens de color con modo oscuro,
tooltip al pasar el cursor y vista de tabla para cada gráfico.
"""

from __future__ import annotations

import html
import math
from datetime import datetime
from pathlib import Path
from typing import Optional

import pandas as pd

from .analysis import CONFIG_ORDER, Analysis
from .attacks import ATTACK_NAMES

SEQ_LIGHT = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]
CONFIG_LABEL = {
    "ninguna": "Sin defensas",
    "A": "Solo A",
    "B": "Solo B",
    "C": "Solo C",
    "AB": "A + B",
    "AC": "A + C",
    "BC": "B + C",
    "ABC": "A + B + C",
}
TOPOLOGY_LABEL = {"lineal": "Lineal", "estrella": "Estrella", "malla": "Malla", "jerarquica": "Jerárquica"}


def _e(value) -> str:
    return html.escape(str(value), quote=True)


def _pct(value: float, digits: int = 0) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "n/d"
    return f"{100 * value:.{digits}f} %"


def _num(value: float, digits: int = 2) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "n/d"
    return f"{value:.{digits}f}"


def _table(df: pd.DataFrame, columns: list[tuple[str, str, callable]]) -> str:
    head = "".join(f"<th>{_e(label)}</th>" for _, label, _ in columns)
    body = []
    for row in df.to_dict("records"):
        cells = "".join(f"<td>{fmt(row.get(key))}</td>" for key, _, fmt in columns)
        body.append(f"<tr>{cells}</tr>")
    return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table></div>'


def _details(summary: str, content: str) -> str:
    return f"<details><summary>{_e(summary)}</summary>{content}</details>"


# ------------------------------------------------------------------ charts
def _bar_chart(rows: list[dict], value_key: str, lo_key: str, hi_key: str, label_key: str) -> str:
    """Barras horizontales, una serie, con IC como bigote."""
    width, bar_h, gap, left, right = 640, 20, 14, 120, 70
    height = len(rows) * (bar_h + gap) + 30
    plot_w = width - left - right

    def x(v: float) -> float:
        return left + plot_w * max(0.0, min(1.0, v))

    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" class="chart">']
    for tick in (0, 0.25, 0.5, 0.75, 1.0):
        parts.append(f'<line class="grid" x1="{x(tick):.1f}" x2="{x(tick):.1f}" y1="0" y2="{height - 22}"/>')
        parts.append(f'<text class="tick" x="{x(tick):.1f}" y="{height - 6}" text-anchor="middle">{int(tick * 100)} %</text>')
    for i, row in enumerate(rows):
        y = i * (bar_h + gap) + 4
        value = row[value_key]
        if value is None or math.isnan(value):
            continue
        w = max(0.0, x(value) - left)
        r = min(4.0, w / 2)
        path = (
            f"M{left},{y} H{left + w - r} Q{left + w},{y} {left + w},{y + r} "
            f"V{y + bar_h - r} Q{left + w},{y + bar_h} {left + w - r},{y + bar_h} H{left} Z"
        )
        tip = f"{row[label_key]}: {_pct(value, 1)} (IC 95 %: {_pct(row[lo_key], 1)} a {_pct(row[hi_key], 1)})"
        parts.append(f'<text class="label" x="{left - 10}" y="{y + bar_h / 2 + 4}" text-anchor="end">{_e(row[label_key])}</text>')
        parts.append(f'<g class="hit" data-tip="{_e(tip)}"><rect x="{left}" y="{y - 4}" width="{plot_w}" height="{bar_h + 8}" fill="transparent"/>')
        parts.append(f'<path class="bar s1" d="{path}"/>')
        if not math.isnan(row[lo_key]):
            cy = y + bar_h / 2
            parts.append(f'<line class="whisker" x1="{x(row[lo_key]):.1f}" x2="{x(row[hi_key]):.1f}" y1="{cy}" y2="{cy}"/>')
        parts.append(f'</g><text class="value" x="{x(max(value, row[hi_key] if not math.isnan(row[hi_key]) else value)) + 6:.1f}" y="{y + bar_h / 2 + 4}">{_pct(value)}</text>')
    parts.append("</svg>")
    return "".join(parts)


def _heatmap(by_attack: pd.DataFrame) -> str:
    attacks = [a for a in ("A1", "A2", "A3", "A4", "A5", "adaptativo") if a in set(by_attack.attack)]
    configs = [c for c in CONFIG_ORDER if c in set(by_attack.defense)]
    cell_w, cell_h, left, top = 64, 34, 210, 30
    width = left + cell_w * len(configs) + 4
    height = top + cell_h * len(attacks) + 4
    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" class="chart">']
    for j, config in enumerate(configs):
        parts.append(
            f'<text class="tick" x="{left + j * cell_w + cell_w / 2}" y="{top - 10}" text-anchor="middle">{_e(CONFIG_LABEL[config])}</text>'
        )
    lookup = {(r["attack"], r["defense"]): r for r in by_attack.to_dict("records")}
    for i, attack in enumerate(attacks):
        y = top + i * cell_h
        parts.append(
            f'<text class="label" x="{left - 10}" y="{y + cell_h / 2 + 4}" text-anchor="end">{_e(attack)} · {_e(ATTACK_NAMES[attack])}</text>'
        )
        for j, config in enumerate(configs):
            row = lookup.get((attack, config))
            if row is None:
                continue
            value = row["asr"]
            step = min(len(SEQ_LIGHT) - 1, int(value * len(SEQ_LIGHT))) if not math.isnan(value) else 0
            ink = "#ffffff" if step >= 3 else "#0b0b0b"
            x = left + j * cell_w
            tip = f"{attack} con {CONFIG_LABEL[config]}: éxito del ataque {_pct(value, 1)}"
            parts.append(
                f'<g class="hit" data-tip="{_e(tip)}"><rect x="{x + 1}" y="{y + 1}" width="{cell_w - 2}" height="{cell_h - 2}" '
                f'rx="3" fill="{SEQ_LIGHT[step]}"/>'
                f'<text x="{x + cell_w / 2}" y="{y + cell_h / 2 + 4}" text-anchor="middle" fill="{ink}" class="cell">{_pct(value)}</text></g>'
            )
    parts.append("</svg>")
    return "".join(parts)


def _line_chart(curve: pd.DataFrame) -> str:
    width, height, left, right, top, bottom = 640, 260, 50, 150, 16, 34
    plot_w, plot_h = width - left - right, height - top - bottom
    xs = sorted(curve.umbral_base)
    x_min, x_max = min(xs), max(xs)

    def x(v: float) -> float:
        return left + plot_w * ((v - x_min) / (x_max - x_min) if x_max > x_min else 0.5)

    def y(v: float) -> float:
        return top + plot_h * (1 - max(0.0, min(1.0, v)))

    series = [("asr", "Éxito del ataque", "s1"), ("exactitud_sin_ataque", "Exactitud sin ataque", "s2")]
    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" class="chart">']
    for tick in (0, 0.25, 0.5, 0.75, 1.0):
        parts.append(f'<line class="grid" x1="{left}" x2="{left + plot_w}" y1="{y(tick):.1f}" y2="{y(tick):.1f}"/>')
        parts.append(f'<text class="tick" x="{left - 8}" y="{y(tick) + 4:.1f}" text-anchor="end">{int(tick * 100)} %</text>')
    for v in xs:
        parts.append(f'<text class="tick" x="{x(v):.1f}" y="{height - 14}" text-anchor="middle">{v:.1f}</text>')
    parts.append(f'<text class="tick" x="{left + plot_w / 2}" y="{height}" text-anchor="middle">umbral base de la Capa C</text>')
    data = curve.sort_values("umbral_base").to_dict("records")
    for key, label, cls in series:
        points = " ".join(f"{x(r['umbral_base']):.1f},{y(r[key]):.1f}" for r in data)
        parts.append(f'<polyline class="line {cls}" points="{points}"/>')
        last = data[-1]
        parts.append(
            f'<text class="value" x="{x(last["umbral_base"]) + 10:.1f}" y="{y(last[key]) + 4:.1f}">{_e(label)} {_pct(last[key])}</text>'
        )
    for r in data:
        tip = (
            f"Umbral {r['umbral_base']:.1f}: éxito del ataque {_pct(r['asr'], 1)}, "
            f"exactitud sin ataque {_pct(r['exactitud_sin_ataque'], 1)}, FPR {_pct(r['fpr'], 1)}"
        )
        parts.append(f'<g class="hit" data-tip="{_e(tip)}"><rect x="{x(r["umbral_base"]) - 14:.1f}" y="{top}" width="28" height="{plot_h}" fill="transparent"/>')
        for key, _, cls in series:
            parts.append(f'<circle class="dot {cls}" cx="{x(r["umbral_base"]):.1f}" cy="{y(r[key]):.1f}" r="4"/>')
        parts.append("</g>")
    parts.append("</svg>")
    return "".join(parts)


def _grouped_bars(by_topology: pd.DataFrame) -> str:
    rows = by_topology.sort_values(["topology", "n_malicious"]).to_dict("records")
    width, bar_h, pair_gap, left, right = 640, 14, 16, 170, 60
    height = len(rows) * (2 * bar_h + 2 + pair_gap) + 30
    plot_w = width - left - right

    def x(v: float) -> float:
        return left + plot_w * max(0.0, min(1.0, v))

    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" class="chart">']
    for tick in (0, 0.25, 0.5, 0.75, 1.0):
        parts.append(f'<line class="grid" x1="{x(tick):.1f}" x2="{x(tick):.1f}" y1="0" y2="{height - 22}"/>')
        parts.append(f'<text class="tick" x="{x(tick):.1f}" y="{height - 6}" text-anchor="middle">{int(tick * 100)} %</text>')
    for i, row in enumerate(rows):
        y0 = i * (2 * bar_h + 2 + pair_gap) + 4
        label = f"{TOPOLOGY_LABEL.get(row['topology'], row['topology'])} · {row['n_malicious']} infiltrado(s)"
        parts.append(f'<text class="label" x="{left - 10}" y="{y0 + bar_h + 5}" text-anchor="end">{_e(label)}</text>')
        for k, (key, cls, name) in enumerate((("asr_ninguna", "s2", "Sin defensas"), ("asr_ABC", "s1", "A + B + C"))):
            value = row.get(key)
            if value is None or math.isnan(value):
                continue
            y = y0 + k * (bar_h + 2)
            w = max(0.0, x(value) - left)
            r = min(4.0, w / 2)
            path = (
                f"M{left},{y} H{left + w - r} Q{left + w},{y} {left + w},{y + r} "
                f"V{y + bar_h - r} Q{left + w},{y + bar_h} {left + w - r},{y + bar_h} H{left} Z"
            )
            tip = f"{label}, {name}: éxito del ataque {_pct(value, 1)}"
            parts.append(
                f'<g class="hit" data-tip="{_e(tip)}"><rect x="{left}" y="{y - 1}" width="{plot_w}" height="{bar_h + 2}" fill="transparent"/>'
                f'<path class="bar {cls}" d="{path}"/></g>'
                f'<text class="value" x="{x(value) + 6:.1f}" y="{y + bar_h - 3}">{_pct(value)}</text>'
            )
    parts.append("</svg>")
    return "".join(parts)


def _legend(items: list[tuple[str, str]]) -> str:
    return '<div class="legend">' + "".join(
        f'<span><i class="swatch {cls}"></i>{_e(label)}</span>' for cls, label in items
    ) + "</div>"


# ------------------------------------------------------------------- page
CSS = """
:root{color-scheme:light;--page:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;
--grid:#e1e0d9;--axis:#c3c2b7;--border:rgba(11,11,11,.10);--s1:#2a78d6;--s2:#eb6834;--good:#0ca30c;--bad:#d03b3b}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;
--ink:#fff;--ink2:#c3c2b7;--muted:#898781;--grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);--s1:#3987e5;--s2:#d95926}}
:root[data-theme="dark"]{color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--ink:#fff;--ink2:#c3c2b7;--muted:#898781;
--grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);--s1:#3987e5;--s2:#d95926}
*{box-sizing:border-box}body{margin:0;background:var(--page);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1040px;margin:0 auto;padding:28px 16px 64px}h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:0 0 4px}
.sub{color:var(--ink2);margin:0 0 20px}.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:18px;margin:0 0 18px}
.note{color:var(--ink2);font-size:13px;margin:4px 0 12px}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin:0 0 18px}
.tile{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px}.tile .l{color:var(--ink2);font-size:13px}
.tile .v{font-size:30px;font-weight:600}.tile .t{font-size:13px;color:var(--ink2)}.hero .v{font-size:48px}
.chart{width:100%;height:auto;display:block}.grid{stroke:var(--grid);stroke-width:1}.tick{fill:var(--muted);font-size:11px;font-variant-numeric:tabular-nums}
.label{fill:var(--ink2);font-size:12px}.value{fill:var(--ink);font-size:12px;font-variant-numeric:tabular-nums}.cell{font-size:12px;font-variant-numeric:tabular-nums}
.bar.s1{fill:var(--s1)}.bar.s2{fill:var(--s2)}.whisker{stroke:var(--ink2);stroke-width:1.5}
.line{fill:none;stroke-width:2;stroke-linejoin:round;stroke-linecap:round}.line.s1{stroke:var(--s1)}.line.s2{stroke:var(--s2)}
.dot{stroke:var(--surface);stroke-width:2}.dot.s1{fill:var(--s1)}.dot.s2{fill:var(--s2)}.hit{cursor:default}.hit:hover .bar,.hit:hover rect[rx]{opacity:.85}
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:13px;color:var(--ink2);margin:0 0 8px}.swatch{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:6px}
.swatch.s1{background:var(--s1)}.swatch.s2{background:var(--s2)}
.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px;margin-top:8px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--grid)}
td{font-variant-numeric:tabular-nums}th{color:var(--ink2);font-weight:600}details{margin-top:10px}summary{cursor:pointer;color:var(--ink2);font-size:13px}
.ok{color:var(--good);font-weight:600}.ko{color:var(--bad);font-weight:600}.na{color:var(--muted)}
#tip{position:fixed;pointer-events:none;background:var(--ink);color:var(--surface);font-size:12px;padding:6px 8px;border-radius:6px;max-width:320px;display:none;z-index:10}
"""

JS = """
const tip=document.getElementById('tip');
document.querySelectorAll('[data-tip]').forEach(el=>{
 el.addEventListener('mousemove',e=>{tip.textContent=el.dataset.tip;tip.style.display='block';
  const x=Math.min(e.clientX+14,window.innerWidth-tip.offsetWidth-8);tip.style.left=x+'px';tip.style.top=(e.clientY+14)+'px';});
 el.addEventListener('mouseleave',()=>{tip.style.display='none';});
});
"""


def _status(ok) -> str:
    if ok is None or (isinstance(ok, float) and math.isnan(ok)):
        return '<span class="na">— sin datos</span>'
    return '<span class="ok">✓ cumple</span>' if ok else '<span class="ko">✗ no cumple</span>'


def build_report(analysis: Analysis, preset: str = "", n_episodes: Optional[int] = None) -> str:
    by_config = analysis.by_config.copy()
    by_config["label"] = by_config.defense.map(CONFIG_LABEL)
    full = by_config[by_config.defense == "ABC"]
    full_row = full.iloc[0].to_dict() if not full.empty else {}

    tiles = [
        ("hero", "Reducción del éxito del ataque (A + B + C)", _pct(full_row.get("reduccion_asr", float("nan"))),
         f"IC 95 %: {_pct(full_row.get('reduccion_lo', float('nan')))} a {_pct(full_row.get('reduccion_hi', float('nan')))} · meta ≥ 70 %"),
        ("", "F1 identificando agentes comprometidos", _num(full_row.get("f1", float("nan"))), "meta ≥ 0,85"),
        ("", "Tasa de falsos positivos", _pct(full_row.get("fpr", float("nan")), 1), "meta ≤ 5 %"),
        ("", "Caída de exactitud sin ataque", f"{_num(full_row.get('caida_exactitud_pts', float('nan')), 1)} pts", "meta ≤ 5 pts"),
    ]
    tiles_html = '<div class="tiles">' + "".join(
        f'<div class="tile {cls}"><div class="l">{_e(l)}</div><div class="v">{_e(v)}</div><div class="t">{_e(t)}</div></div>'
        for cls, l, v, t in tiles
    ) + "</div>"

    targets = analysis.targets.copy()
    is_points = targets.meta.str.contains("pts")
    targets["valor_fmt"] = [
        f"{_num(v, 1)} pts" if pts else _pct(v, 1) for v, pts in zip(targets.valor, is_points)
    ]
    targets["objetivo_fmt"] = [
        f"{op} {_num(g, 0)} pts" if pts else (f"{op} {_num(g, 2)}" if "F1" in m else f"{op} {_pct(g)}")
        for op, g, pts, m in zip(targets.operador, targets.objetivo, is_points, targets.meta)
    ]
    targets.loc[targets.meta.str.contains("F1"), "valor_fmt"] = [
        _num(v) for v in targets[targets.meta.str.contains("F1")].valor
    ]
    targets_html = _table(
        targets,
        [
            ("meta", "Meta", _e),
            ("valor_fmt", "Valor", _e),
            ("objetivo_fmt", "Objetivo", _e),
            ("cumple", "Estado", _status),
        ],
    ) + '<p class="note">Una caída negativa significa que la defensa mejora la métrica.</p>'

    ablation_rows = by_config.to_dict("records")
    ablation_chart = _bar_chart(ablation_rows, "asr", "asr_lo", "asr_hi", "label")
    ablation_table = _table(
        by_config,
        [
            ("label", "Configuración", _e),
            ("asr", "Éxito del ataque", lambda v: _pct(v, 1)),
            ("reduccion_asr", "Reducción", lambda v: _pct(v, 1)),
            ("f1", "F1", _num),
            ("fpr", "FPR", lambda v: _pct(v, 1)),
            ("exactitud_sin_ataque", "Exactitud sin ataque", lambda v: _pct(v, 1)),
            ("sobrecarga_tokens", "Sobrecarga tokens", lambda v: _pct(v, 1)),
        ],
    )

    heatmap = _heatmap(analysis.by_attack)
    attack_table = _table(
        analysis.by_attack,
        [
            ("attack", "Ataque", _e),
            ("defense", "Config", lambda v: _e(CONFIG_LABEL.get(v, v))),
            ("asr", "Éxito", lambda v: _pct(v, 1)),
            ("recall", "Recall detección", _num),
            ("infectados_medios", "Infectados medios", _num),
            ("captura_decision", "Captura de la decisión", lambda v: _pct(v, 1)),
        ],
    )

    topology_chart = _grouped_bars(analysis.by_topology) if not analysis.by_topology.empty else ""

    curve_html = ""
    if analysis.curve is not None and not analysis.curve.empty:
        curve_html = f"""<section class="card"><h2>SP5 · Curva seguridad–utilidad</h2>
<p class="note">Barrido del umbral base de la Capa C con las tres capas activas. Subir el umbral endurece la defensa; el costo aparece como caída de la exactitud sin ataque.</p>
{_legend([("s1", "Éxito del ataque"), ("s2", "Exactitud sin ataque")])}{_line_chart(analysis.curve)}
{_details("Ver tabla", _table(analysis.curve, [("umbral_base", "Umbral", lambda v: _num(v, 1)), ("asr", "Éxito del ataque", lambda v: _pct(v, 1)), ("exactitud_sin_ataque", "Exactitud sin ataque", lambda v: _pct(v, 1)), ("fpr", "FPR", lambda v: _pct(v, 1)), ("recall", "Recall", _num)]))}</section>"""

    cost_html = ""
    if analysis.cost is not None and not analysis.cost.empty:
        cost_html = f"""<section class="card"><h2>Costo con juez y cuarentena LLM</h2>
<p class="note">Sin ataque. Juez de contenido y modelo en cuarentena implementados como llamadas a un modelo (simulado): tokens y latencia de una llamada real por mensaje.</p>
{_table(analysis.cost, [("defense", "Config", lambda v: _e(CONFIG_LABEL.get(v, v))), ("tokens_medios", "Tokens medios", lambda v: _num(v, 0)), ("sobrecarga_tokens", "Sobrecarga tokens", lambda v: _pct(v, 1)), ("latencia_p95_s", "Latencia p95 (s)", lambda v: _num(v, 1)), ("sobrecarga_latencia_p95", "Sobrecarga p95", lambda v: _pct(v, 1))])}</section>"""

    hyp_html = "".join(
        f"<li><strong>{_e(r['hipotesis'])}</strong> — {_status(r['soportada']).replace('cumple', 'soportada')}<br><span class='note'>{_e(r['evidencia'])}</span></li>"
        for r in analysis.hypotheses.to_dict("records")
    )
    super_table = _table(
        analysis.superadditivity,
        [
            ("attack", "Ataque", _e),
            ("delta_A", "Δ A", lambda v: _num(v, 3)),
            ("delta_B", "Δ B", lambda v: _num(v, 3)),
            ("delta_C", "Δ C", lambda v: _num(v, 3)),
            ("suma_individual", "Suma", lambda v: _num(v, 3)),
            ("delta_ABC", "Δ ABC", lambda v: _num(v, 3)),
            ("interaccion", "Interacción", lambda v: f"{v:+.3f}" if isinstance(v, (int, float)) and not math.isnan(v) else "n/d"),
        ],
    )
    detection_table = _table(
        analysis.detection_rounds,
        [
            ("attack", "Ataque", _e),
            ("tasa_deteccion", "Episodios con detección", lambda v: _pct(v, 1)),
            ("rondas_media", "Rondas hasta detectar (media)", lambda v: _num(v, 2)),
            ("rondas_mediana", "Mediana", lambda v: _num(v, 1)),
        ],
    )
    adaptive_table = _table(
        analysis.adaptive,
        [
            ("defense", "Config", lambda v: _e(CONFIG_LABEL.get(v, v))),
            ("asr_adaptativo", "Éxito adaptativo", lambda v: _pct(v, 1)),
            ("asr_mejor_estatico", "Mejor ataque estático", lambda v: _pct(v, 1)),
            ("mejor_estatico", "Cuál", _e),
        ],
    )

    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    meta = f"Preset «{_e(preset)}» · {n_episodes or '?'} episodios del diseño factorial · generado {stamp}"
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Resultados TRUST-MAS</title><style>{CSS}</style></head><body><main>
<h1>Resultados del banco de pruebas TRUST-MAS</h1><p class="sub">{meta}. Perfiles de modelo simulados y calibrables: los valores miden el mecanismo, no a un LLM concreto.</p>
{tiles_html}
<section class="card"><h2>Metas de la propuesta</h2><p class="note">Configuración A + B + C frente a la línea base sin defensas.</p>{targets_html}</section>
<section class="card"><h2>SP2 · Ablación: éxito del ataque por configuración</h2>
<p class="note">Promedio sobre los ataques A1–A5, todas las topologías, fracciones y modelos. El bigote es el IC 95 % por remuestreo.</p>
{ablation_chart}{_details("Ver tabla", ablation_table)}</section>
<section class="card"><h2>Éxito del ataque por perfil y configuración</h2><p class="note">Más oscuro = el ataque tuvo más éxito.</p>
{heatmap}{_details("Ver tabla", attack_table)}</section>
<section class="card"><h2>SP1 · Topología y fracción comprometida</h2>{_legend([("s2", "Sin defensas"), ("s1", "A + B + C")])}
{topology_chart}{_details("Ver tabla", _table(analysis.by_topology, [("topology", "Topología", _e), ("n_malicious", "Infiltrados", _e), ("asr_ninguna", "Sin defensas", lambda v: _pct(v, 1)), ("asr_ABC", "A + B + C", lambda v: _pct(v, 1))]))}</section>
{curve_html}
<section class="card"><h2>Hipótesis</h2><ul>{hyp_html}</ul><h2 style="margin-top:14px">H4 · Superaditividad</h2>
<p class="note">Δ = reducción absoluta del éxito del ataque frente a la línea base. Superaditiva si Δ ABC supera la suma de las capas aisladas.</p>{super_table}</section>
<section class="card"><h2>SP3 · Rondas hasta la detección (A + B + C)</h2>{detection_table}</section>
<section class="card"><h2>SP4 · Adversario adaptativo</h2>{adaptive_table}</section>
{cost_html}
</main><div id="tip" role="tooltip"></div><script>{JS}</script></body></html>"""


def write_report(analysis: Analysis, path: Path, preset: str = "", n_episodes: Optional[int] = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_report(analysis, preset=preset, n_episodes=n_episodes), encoding="utf-8")
    return path
