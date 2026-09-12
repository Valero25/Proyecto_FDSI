# Proyecto_FDSI -- TRUST-MAS

Prototipo de defensa en profundidad para sistemas multiagente: detecta y frena
a un agente comprometido infiltrado entre agentes de confianza.

Implementa las tres capas propuestas:

- **Capa A (identidad)** -- `src/trust_mas/identity.py`: firma Ed25519 por
  agente, el rol lo certifica el registro (no el mensaje, lo que anula la
  suplantación de rol), tokens de capacidad atenuables (no se puede delegar
  más autoridad de la que se tiene) y anti-repetición por nonce.
- **Capa B (procedencia)** -- `src/trust_mas/provenance.py`: etiquetado de
  origen, enrutamiento a cuarentena para contenido no confiable (documentos
  externos, salidas de herramientas) y autorización por acción individual.
- **Capa C (confianza dinámica)** -- `src/trust_mas/trust.py`: puntaje por
  mensaje, reputación bayesiana (Beta) por agente, detección de anomalías
  sobre el grafo de comunicación (NetworkX) y umbral adaptativo.

Todo mensaje pasa por `MessageBus.route()` (`src/trust_mas/bus.py`), que
aplica A -> B -> C en orden y termina en `accept / degrade / corroborate /
quarantine / reject`, con cada decisión registrada en un log de auditoría
append-only encadenado por hash (`src/trust_mas/audit.py`).

## Uso

```bash
pip install -r requirements.txt

# Demo end-to-end con agentes simulados (texto fijo, sin llamadas a un LLM):
# 3 agentes honestos + 1 agente comprometido intentando suplantación de rol,
# repetición de mensaje e inyección de instrucciones.
python demo.py

# Demo con orquestador REAL (LangGraph + Gemini): cada agente es un modelo
# Gemini de verdad generando texto no determinista. Requiere una
# GOOGLE_API_KEY gratuita (https://aistudio.google.com/apikey), configurada
# como variable de entorno -- nunca la pegues en el código versionado.
#   PowerShell: $env:GOOGLE_API_KEY = "tu-clave"
python demo_orchestrator.py

# Suite de tests (no requiere GOOGLE_API_KEY: los tests del orquestador usan
# un LLM de prueba en vez de llamar a Gemini)
python -m pytest tests/ -q
```

### Orquestador real (`src/trust_mas/orchestrator.py`)

Grafo de estados de LangGraph donde cada nodo (`AgentNode`) es un agente
respaldado por un LLM (`.invoke(prompt) -> .content`, compatible con
`ChatGoogleGenerativeAI` o con un doble de prueba). Cada arista del grafo
sigue pasando obligatoriamente por `MessageBus.route()` antes de que el
contenido llegue al siguiente nodo: una decisión `QUARANTINE`/`CORROBORATE`/
`REJECT` bloquea la propagación al contexto compartido, aunque el texto ya
lo haya generado un modelo real. Esto es justamente lo que la diapositiva 3
señala como vector de propagación en AutoGen/LangGraph (historial/estado
compartido como canal de contaminación) -- aquí queda saneado por el bus
antes de escribirse en el estado del grafo.

La topología actual es lineal (`build_linear_graph`); estrella, malla y
jerárquica del diseño factorial se pueden montar reutilizando el mismo
`AgentNode` con otro orden de aristas.

## Qué no incluye todavía

Integración con AutoGen, protocolos MCP/A2A, dashboard en vivo, topologías
no lineales, y el banco de pruebas factorial completo (4 topologías x 5
perfiles de ataque x 2 fracciones comprometidas x 3 modelos, mínimo 30
corridas por celda) descrito en la propuesta.
