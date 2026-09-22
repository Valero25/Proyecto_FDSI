"""Las demos son parte del entregable: si su guion deja de cumplirse, falla."""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent


@pytest.mark.parametrize("script", ["demo.py", "demo_escenas.py"])
def test_demo_corre_y_cumple_su_guion(script):
    completed = subprocess.run(
        [sys.executable, str(ROOT / script)], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=120
    )
    assert completed.returncode == 0, completed.stderr
    assert "cadena integra: True" in completed.stdout or "Escena 7" in completed.stdout


def test_demo_orchestrator_sin_clave_falla_con_mensaje_claro():
    env = {k: v for k, v in __import__("os").environ.items() if k not in ("GOOGLE_API_KEY", "TRUSTMAS_LLM")}
    completed = subprocess.run(
        [sys.executable, str(ROOT / "demo_orchestrator.py")], cwd=ROOT, capture_output=True, text=True,
        encoding="utf-8", timeout=60, env=env,
    )
    assert completed.returncode != 0
    assert "GOOGLE_API_KEY" in completed.stderr
