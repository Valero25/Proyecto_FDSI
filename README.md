# Proyecto_FDSI — TRUST-MAS

Prototipo de **defensa en profundidad para sistemas multiagente (MAS)**: detecta
y frena a un agente comprometido infiltrado entre agentes de confianza, incluso
cuando ese agente genera texto convincente con un LLM real, **y su banco de
pruebas reproducible** para medir cuánto aporta cada defensa y a qué costo.

La premisa de diseño es que **ninguna capa decide "aceptar" por sí sola**. Un
mensaje solo se propaga si supera, en orden, tres líneas de defensa
independientes: identidad criptográfica, procedencia del contenido y un
puntaje de confianza dinámico. Si cualquiera de las tres detecta un problema,
el mensaje se degrada, se retiene para corroboración, se pone en cuarentena o
se rechaza, y la decisión queda registrada en un log de auditoría inmutable.

---

## Índice

- [Estado frente a la propuesta](#estado-frente-a-la-propuesta)
- [Resultados](#resultados)
- [Arquitectura general](#arquitectura-general)
- [Estructura del repositorio](#estructura-del-repositorio)
- [Capa A — Identidad](#capa-a--identidad)
- [Capa B — Procedencia](#capa-b--procedencia)
- [Capa C — Confianza dinámica](#capa-c--confianza-dinámica)
- [El bus de mensajes](#el-bus-de-mensajes)
- [Log de auditoría](#log-de-auditoría)
- [Orquestador LangGraph](#orquestador-langgraph)
- [Protocolos: A2A y MCP](#protocolos-a2a-y-mcp)
- [Banco de pruebas](#banco-de-pruebas)
- [Instalación y uso](#instalación-y-uso)
- [Tests](#tests)
- [Decisiones de diseño relevantes](#decisiones-de-diseño-relevantes)
- [Limitaciones y trabajo futuro](#limitaciones-y-trabajo-futuro)

---

## Estado frente a la propuesta

| Elemento de la propuesta | Dónde está |
|---|---|
| Capa A: firma Ed25519, identidad registrada, token de capacidad, anti-repetición | `src/trust_mas/identity.py`, `bus.py` |
| Capa B: etiqueta de origen, control de flujo, modelo en cuarentena, capacidad por acción | `provenance.py`, `quarantine_model.py`, `bus.py` |
| Capa C: puntaje de mensaje, reputación bayesiana, detección sobre grafo, umbral adaptativo | `trust.py`, `judge.py` |
| Entrega o bloqueo: aceptar, degradar peso, exigir corroboración, cuarentena | `bus.py`, `orchestrator.py`, `testbed/episode.py` |
| Remediación selectiva | `MessageBus.isolate` / `check_remediation`, `Episode._retract` |
| Registro de auditoría append-only | `audit.py` |
| 4 topologías (lineal, estrella, malla, jerárquica) | `testbed/topologies.py` y `orchestrator.build_graph` |
| 5 perfiles de ataque A1–A5 + adversario adaptativo (SP4) | `testbed/attacks.py` |
| Roles Analista, Crítico, Verificador, Sintetizador + agente malicioso | `testbed/topologies.py` |
| Tareas con verdad de referencia objetiva | `testbed/tasks.py` |
| Línea base sin defensas y ablación de 8 configuraciones (F4, SP2) | `config.py` (`DefenseConfig`, `ablation_configs`) |
| Diseño factorial 4 × 5 × 2 × 3, ≥ 30 corridas por celda, IC 95 % por remuestreo | `testbed/experiment.py`, `testbed/analysis.py` |
| Métricas: reducción de éxito del ataque, F1 y FP de detección, exactitud, utilidad, tokens, latencia p95 | `testbed/analysis.py` |
| SP1 topología y fracción · SP3 rondas hasta detección · SP5 curva seguridad-utilidad | `testbed/analysis.py`, panel |
| Hipótesis H1, H4, H5 | `testbed/analysis.py` (tabla `hipotesis`) |
| Demostración de 7 escenas con guion determinista | `demo_escenas.py` |
| Panel de resultados | `testbed/report.py` → `results/panel.html` |
| Modelado de amenazas MAESTRO × OWASP y matriz de trazabilidad (P6) | `docs/modelo_de_amenazas.md` |
| Orquestación LangGraph · modelos de frontera (Gemini) y locales (Ollama) | `orchestrator.py`, `llm.py` |
| Protocolos MCP y A2A | `protocols.py` (adaptadores) |
| Reproducibilidad: Docker, DVC | `Dockerfile`, `dvc.yaml` |

Lo que **no** está (y por qué) se resume en
[Limitaciones y trabajo futuro](#limitaciones-y-trabajo-futuro).

## Resultados

Preset `completo`: 37 440 episodios factoriales (30 corridas por celda), 9 360
de la curva y 8 640 de costo. Unos 4 minutos en 11 procesos. Se regeneran con
`python run_experiment.py --preset completo`; el detalle está en
`results/panel.html` y `results/tablas/`. **Los perfiles de modelo son
simulados**: las cifras miden el mecanismo, no a un LLM concreto.

**Metas de la propuesta (A + B + C frente a la línea base):**

| Meta | Resultado | Objetivo | |
|---|---|---|---|
| Reducción del éxito del ataque (A1–A5) | 88,9 % [IC 95 %: 87,6 – 90,1] | ≥ 70 % | ✓ |
| F1 identificando agentes comprometidos | 0,78 | ≥ 0,85 | ✗ |
| Tasa de falsos positivos | 0,7 % | ≤ 5 % | ✓ |
| Caída de exactitud sin ataque | −1,9 pts (mejora) | ≤ 5 pts | ✓ |
| Caída de la utilidad de colaboración | −17,6 % (mejora) | ≤ 10 % | ✓ |
| Sobrecarga de tokens (juez y cuarentena LLM) | 13,8 % | ≤ 25 % | ✓ |
| Sobrecarga de latencia p95 (juez y cuarentena LLM) | 20,7 % | ≤ 20 % | ✗ (por poco) |

**Ablación (SP2): éxito del ataque por configuración**, promedio de A1–A5:
sin defensas 69,1 % · A 43,8 % · B 49,9 % · C 12,6 % · A+B 24,6 % · A+C 7,6 % ·
B+C 13,5 % · **A+B+C 7,7 %**.

**Qué frena a qué** (éxito del ataque):

| Ataque | Sin defensas | Solo A | Solo B | Solo C | A+B+C |
|---|---|---|---|---|---|
| A1 desinformación persuasiva | 40 % | 40 % | 40 % | 24 % | 24 % |
| A2 inyección autorreplicante | 100 % | 100 % | 4 % | 4 % | 4 % |
| A3 suplantación de rol | 100 % | 4 % | 100 % | 13 % | 3 % |
| A4 manipulación de consenso | 100 % | 69 % | 100 % | 18 % | 4 % |
| A5 baja intensidad | 5 % | 5 % | 5 % | 4 % | 4 % |
| Adaptativo | 100 % | 100 % | 100 % | 27 % | 3 % |

(El ~4 % residual es el error propio del equipo cuando coincide con la
respuesta que buscaba el atacante.)

**Hallazgos:**

- **H1 soportada: autenticar no es confiar.** La Capa A sola no mueve la
  desinformación persuasiva (40 % → 40 %).
- **H4 no soportada: las capas son redundantes, no superaditivas.** Cada
  ataque lo frena más de una capa (A2: B y C; A3: A y C), así que la suma de
  los efectos aislados (1,01) supera el efecto combinado (0,61). El valor de la
  combinación está en la cobertura: ninguna capa sola baja de 12 %, y el
  adversario adaptativo solo se contiene con A + C (3 %).
- **H5 soportada: la baja intensidad degrada la Capa C.** Recall 0,11 frente
  a A5 (1,00 para A2, A3 y A4). A5 casi no logra su objetivo (5 %), pero pasa
  desapercibido. A1 también se identifica mal (recall 0,15): es lo que baja el
  F1 por debajo de la meta.
- **La Capa C sin Capa A incrimina a honestos.** Frente a los votos sybil
  (A4), solo C aísla por error al 78 % de los agentes honestos; con A + C, al
  0,7 %. La regla de
  "solo se castiga lo atribuible" necesita la identidad para funcionar.
- **La Capa B no ve la inyección que escribe un agente deshonesto por su
  cuenta.** B protege contra el agente secuestrado por un documento, pero con
  A + B el adversario adaptativo gana usando A2 (100 %); solo C lo frena.
- **SP1:** con dos infiltrados la malla es la topología más expuesta, tanto
  sin defensas (81 %) como con A + B + C (15 %).
- **SP3:** A4 se detecta en la primera ronda, A3 en la segunda y A2 hacia la
  tercera.
- **SP5:** subir el umbral base de 0,5 a 0,8 baja el éxito del ataque de 8,7 %
  a 5,7 %, a cambio de 6,7 pts de exactitud sin ataque y una tasa de falsos
  positivos del 13 %. El umbral por defecto (0,5) está en el codo de la curva.

## Arquitectura general

Todo mensaje entre agentes pasa obligatoriamente por `MessageBus.route()`,
que aplica las capas activas **en orden estricto** y termina emitiendo una de
cinco decisiones de política:

```
                 Message (firmado por el emisor, llega por un canal autenticado)
                                    |
                                    v
                     +----------------------------------+
                     |  CAPA A -- Identidad              |
                     |  1. emisor conocido en el registro|
                     |  2. firma Ed25519 valida          |
                     |  3. el canal es del emisor        |
                     |  4. rol declarado == rol oficial  |
                     |  5. timestamp dentro de ventana   |
                     |  6. nonce no visto (anti-replay)  |
                     |  7. digest del flujo vigente      |
                     +----------------------------------+
                          falla -> REJECT (se penaliza al emisor solo si
                                   el fallo le es atribuible)
                                    v
                     +----------------------------------+
                     |  CAPA B -- Procedencia            |
                     |  1. procedencia efectiva (el bus  |
                     |     solo puede QUITAR confianza)  |
                     |  2. taint de quien leyo contenido |
                     |     no confiable                  |
                     |  3. capacidad por accion (token,  |
                     |     titular, cadena de delegacion)|
                     +----------------------------------+
                                    v
                     +----------------------------------+
                     |  CAPA C -- Confianza dinamica     |
                     |  1. reputacion bayesiana (Beta)   |
                     |  2. -0.30 si procedencia no conf. |
                     |  3. juez de contenido (heuristico |
                     |     o LLM)                        |
                     |  4. anomalias de grafo            |
                     |  5. umbral adaptativo             |
                     |  6. validacion cruzada por ronda  |
                     +----------------------------------+
                                    v
        ACCEPT / DEGRADE / CORROBORATE / QUARANTINE / REJECT
                                    |
            QUARANTINE -> modelo en cuarentena: solo datos, sin instrucciones
            reputacion baja o bloqueos repetidos -> remediacion selectiva
                                    v
                     +----------------------------------+
                     |  Log de auditoria append-only     |
                     |  encadenado por hash              |
                     +----------------------------------+
```

Puntos clave del flujo:

- Si la **Capa A** falla (emisor desconocido, firma inválida, canal ajeno, rol
  falso, replay, timestamp fuera de ventana, digest de otro flujo), el mensaje
  se **rechaza de inmediato** sin evaluar B/C. La reputación solo se castiga si
  el fallo es **atribuible**: firma válida con rol falso, o canal autenticado
  que delata al emisor real. Una falsificación a nombre de un honesto no lo
  incrimina.
- La **Capa B** fuerza `QUARANTINE` sobre un `ACCEPT` **o un `DEGRADE`** de la
  Capa C: la procedencia no confiable nunca queda "cubierta" por una buena
  reputación, y degradar el peso seguiría entregando el contenido.
- Una acción (`message.action`) sin un token de capacidad válido (firmado, del
  propio emisor y con cadena de delegación hasta el orquestador) fuerza
  `REJECT` sin importar el puntaje.
- Cada decisión se anota en el log de auditoría con su cadena de razones.

## Estructura del repositorio

```
Proyecto_FDSI/
├── README.md
├── requirements.txt · Dockerfile · dvc.yaml · .gitignore
├── demo.py                  # recorrido mensaje a mensaje (texto fijo)
├── demo_escenas.py          # las 7 escenas de la propuesta (guion determinista)
├── demo_orchestrator.py     # LangGraph + LLM real (Gemini u Ollama), 4 topologías
├── run_experiment.py        # banco de pruebas: factorial, curva, costo, panel
├── docs/
│   └── modelo_de_amenazas.md    # MAESTRO x OWASP, matriz de trazabilidad (P6)
├── src/trust_mas/
│   ├── models.py            # Message, ProvenanceTag, CapabilityToken, enums
│   ├── identity.py          # Capa A: claves, registro, nonces, tokens y su cadena
│   ├── provenance.py        # Capa B: etiquetado, cuarentena, capacidad por acción
│   ├── quarantine_model.py  # Capa B: modelo en cuarentena (reglas o LLM)
│   ├── judge.py             # Capa C: juez de contenido (heurístico o LLM)
│   ├── trust.py             # Capa C: reputación, grafo, umbral, validación cruzada
│   ├── config.py            # qué capas están activas (línea base / ablación)
│   ├── bus.py               # orquesta A -> B -> C, remediación, auditoría
│   ├── audit.py             # log encadenado por hash
│   ├── agent.py             # agente que compone y firma mensajes
│   ├── orchestrator.py      # nodos LangGraph y las 4 topologías
│   ├── protocols.py         # adaptadores A2A (message/send) y MCP (tools/call)
│   ├── llm.py               # construcción del chat model (Gemini / Ollama)
│   └── testbed/
│       ├── tasks.py         # tareas con verdad de referencia
│       ├── profiles.py      # perfiles de modelo base (simulados, calibrables)
│       ├── topologies.py    # lineal, estrella, malla, jerárquica
│       ├── attacks.py       # A1-A5, adaptativo, combinado (demo)
│       ├── simllm.py        # LLMs simulados para medir costo de defensas LLM
│       ├── episode.py       # un episodio: agentes + bus + decisión colectiva
│       ├── experiment.py    # diseño factorial y ejecución en paralelo
│       ├── analysis.py      # métricas, IC 95 %, hipótesis, metas
│       └── report.py        # panel HTML
└── tests/                   # 156 tests (ver sección Tests)
```

---

## Capa A — Identidad

Garantiza que un mensaje proviene de quien dice, con el rol que realmente
tiene, por el flujo que corresponde y que no es una repetición.

- **`KeyPair`** — par Ed25519 (`pynacl`) por agente.
- **`IdentityRegistry`** — fuente de verdad de qué agentes existen, con qué
  clave pública y **qué rol oficial**: *el rol lo certifica el registro, nunca
  el mensaje*.
- **`verify_message`** — en este orden: emisor conocido → **firma** válida
  (una firma vacía o malformada también se rechaza) → rol declarado == rol
  oficial (fallo *atribuible*) → timestamp en ventana (300 s) → nonce no visto.
  La firma va antes del nonce para que una falsificación no "queme" el nonce
  de un mensaje legítimo en tránsito (DoS), y antes del rol para que solo un
  fallo con firma válida cuente contra el emisor.
- **`NonceStore`** — recuerda `(emisor, nonce)` solo mientras el mensaje podría
  pasar la ventana; después lo depura (el replay lo frena el timestamp).
- **Canal autenticado** (`route(..., channel_sender=...)`) — si el transporte
  sabe qué agente entregó el mensaje y no coincide con `sender_id`, es
  suplantación de emisor y se atribuye al dueño del canal.
- **Integridad de flujo** (`route(..., expected_digest=...)`) — un mensaje de
  otra conversación o de una ronda vieja se rechaza (brecha B3).
- **Tokens de capacidad atenuables** — `attenuate_capability_token` solo deja
  delegar un subconjunto, si quien delega es el titular del padre y el padre
  está vigente; el hijo guarda su `parent` y su firma cubre la del padre.
  **`verify_capability_token`** recorre la cadena completa hasta una raíz que
  debe emitir un agente con rol `orchestrator` (si no, cualquier worker podría
  firmarse a sí mismo `transfer_funds`).

`Message.signing_payload()` cubre también la **etiqueta de procedencia
declarada**, para que nadie la cambie en tránsito; aun así, el bus la recalcula.

## Capa B — Procedencia

Que el contenido de fuentes no confiables nunca tenga la autoridad de un par
legítimo, y que ninguna acción se ejecute sin permiso explícito.

- **`tag_provenance`** — `external_doc` y `tool_output` son no confiables por
  defecto; `agent` y `user`, confiables.
- **Procedencia efectiva** (`MessageBus._effective_provenance`) — la etiqueta
  la declara el emisor, así que el bus **solo puede quitarle confianza**:
  `external_doc`/`tool_output` nunca se vuelven confiables; `agent` solo si el
  origen es el propio emisor; `user` solo si lo retransmite el orquestador.
- **Contaminación (taint)** — el runtime llama a `bus.record_ingestion(agente,
  etiqueta)` cuando un agente lee contenido no confiable; desde entonces todo
  lo que emita se trata como no confiable. Impide "lavar" un documento
  malicioso reenviándolo como propio. `bus.clear_taint` levanta la marca.
- **`QuarantineEngine`** — sin etiqueta → no confiable (fail-closed); etiqueta
  no confiable → cuarentena; fuente no confiable que intenta una acción →
  cuarentena.
- **Modelo en cuarentena** (`quarantine_model.py`, patrón CaMeL) — lo que va a
  cuarentena no se descarta a ciegas ni llega crudo: un modelo **sin
  herramientas ni capacidades** extrae solo el dato (p. ej. "afirma la
  respuesta B, confianza 0.9") y elimina las instrucciones embebidas. Versión
  por reglas (0 tokens) o `LLMQuarantineModel`.
- **Capacidad por acción** (`MessageBus.authorize_action`) — token vigente, del
  propio emisor y con cadena válida; un agente aislado no tiene capacidades.

## Capa C — Confianza dinámica

- **`BayesianReputation`** — Beta(α, β) por agente; el score es `α / (α + β)`.
  ACCEPT +0.2, DEGRADE +0.1, CORROBORATE +0.02, QUARANTINE −0.5, REJECT −0.6.
- **Juez de contenido** (`judge.py`) — `HeuristicJudge`: patrones normalizados
  (sin tildes, español e inglés) en seis categorías (anulación de
  instrucciones, autorreplicación, exfiltración, desactivar defensas, acciones
  de alto riesgo, reclamo de autoridad); 0,25 por categoría, máximo 0,5.
  `LLMJudge`: "LLM como juez", con caché por cuerpo (un mismo mensaje enviado
  a varios destinatarios se juzga una vez) y respaldo heurístico si la salida
  es ilegible.
- **`GraphAnomalyDetector`** — aristas fuera de la topología declarada (la
  señal más precisa), fan-out anómalo (z > 2) cuando no hay topología, y
  ráfagas por arista (relleno de votos) en una ventana deslizante, que no
  castigan al hub de una estrella por tener muchas aristas.
- **`AdaptiveThreshold`** — parte de 0,5 y sube (hasta 0,9) según la
  proporción de scores bajos en los **últimos 20 mensajes**; vuelve a
  relajarse cuando el tráfico sospechoso sale de la ventana.
- **Validación cruzada** (`TrustEngine.consistency_feedback`) — al cierre de
  cada ronda, cada afirmación se compara con lo que concluye el resto del
  sistema sin ese agente (voto ponderado por reputación). Es la única señal
  que puede atrapar desinformación sin marcadores (A1).
- **Decisión** (`_decide`) — score < umbral/2 → QUARANTINE; < umbral →
  CORROBORATE (o QUARANTINE si la procedencia no es confiable); < umbral+0,15
  → DEGRADE; si no, ACCEPT.

## El bus de mensajes

`MessageBus` es el único punto de entrada. Además de encadenar las capas:

- **Capas configurables** (`DefenseConfig`): con una capa apagada el bus se
  comporta como un MAS sin esa protección (sin A cree el emisor y el rol que
  diga el mensaje; sin B toda procedencia es confiable y no exige capacidades;
  sin C acepta sin puntaje). Es lo que permite la línea base y la ablación.
- **Remediación selectiva** (`RemediationPolicy`): si la reputación de un
  agente cae por debajo de 0,35 o acumula 3 bloqueos atribuibles, se le aísla:
  se revoca su token y todo lo que envíe va a cuarentena. Solo ese agente; el
  banco de pruebas retira además su aporte del contexto de los afectados.
- **`RoutingResult`** trae los datos saneados de la cuarentena, los agentes
  recién aislados, los tokens que consumieron las defensas y su latencia.
- **Seguro con hilos** (lock en `route`), para nodos de LangGraph en paralelo.

## Log de auditoría

`AuditLog` es un ledger **append-only encadenado por hash**: cada entrada
guarda `prev_hash` y su `entry_hash` sobre el cuerpo canónico en JSON.
`verify_chain()` detecta entradas insertadas, borradas o alteradas. Se guarda
el SHA-256 del contenido, no el contenido en claro. Con `AuditLog(path=...)`
cada entrada se persiste en JSONL.

## Orquestador LangGraph

`AgentNode` (`orchestrator.py`) es un agente respaldado por un LLM real
(`.invoke(prompt) -> .content`: `ChatGoogleGenerativeAI`, `ChatOllama` o un
doble de prueba). Cada salida se firma y pasa por `bus.route()` antes de
escribirse en el estado compartido, el canal de contaminación típico de
AutoGen/LangGraph:

| Decisión | Qué entra al contexto compartido |
|---|---|
| ACCEPT | el texto, peso 1 |
| DEGRADE | el texto, marcado "peso reducido 0.5" en el prompt de los siguientes |
| CORROBORATE | nada: queda en `pending_corroboration` |
| QUARANTINE | solo los datos que extrajo el modelo en cuarentena, marcados como no confiables |
| REJECT | nada |

Topologías: `build_linear_graph`, `build_star_graph` (hub → radios en
paralelo → cierre), `build_hierarchical_graph` (raíz → líderes → equipos →
cierre), `build_mesh_graph` (todos contra todos, N rondas) y el atajo
`build_graph(nombre, nodos)`. El estado usa reductores para que los nodos de
una misma etapa corran en paralelo.

## Protocolos: A2A y MCP

`protocols.py` muestra dónde se engancha TRUST-MAS sin reimplementar los
protocolos (su rediseño está fuera del alcance):

- **A2A**: `to_a2a` / `from_a2a` llevan un `Message` firmado en un sobre
  JSON-RPC 2.0 `message/send`, con firma, nonce, rol, digest y procedencia en
  `metadata.trustmas`. El receptor pasa el mensaje por `bus.route()`; un sobre
  sin esos metadatos se rechaza (fail-closed).
- **MCP**: `McpToolGuard` intercepta `tools/call`. Exige capacidad para la
  herramienta antes de ejecutar (error JSON-RPC −32001 si no la hay), audita
  la llamada y etiqueta el resultado como `tool_output` no confiable, lo que
  contamina al agente que lo leyó.

---

## Banco de pruebas

`src/trust_mas/testbed/` cierra la brecha **B7** (no existe banco de pruebas
reproducible).

**Episodio.** 5 agentes honestos (orquestador, analista, crítico, verificador,
sintetizador) y 0, 1 o 2 infiltrados deliberan durante 5 rondas sobre una
tarea con verdad de referencia (una multiplicación con 4 opciones). Cada
honesto tiene una señal privada, correcta con probabilidad `accuracy` según
el perfil de modelo, y comunica su creencia a sus vecinos de la topología.
Todo el tráfico pasa por el bus con las capas de la configuración. La
decisión colectiva es la creencia del nodo de decisión (sintetizador u
orquestador según la topología), salvo que una orden `fijar_decision`
aceptada la capture.

**Efecto de cada decisión en el receptor.** ACCEPT pesa 1; DEGRADE pesa 0,5;
CORROBORATE solo cuenta si otro emisor independiente afirma lo mismo;
QUARANTINE solo aporta el dato saneado, con peso 0,2; REJECT se descarta. El
contenido que entra al contexto tiene efectos de "LLM": una carga
autorreplicante infecta al receptor con probabilidad
`injection_susceptibility`, una directiva de quien parece ser el orquestador
se obedece con probabilidad `authority_compliance`, y la retórica persuasiva
multiplica el peso por `1 + persuadability`.

**Perfiles de ataque** (`attacks.py`, numeración de la propuesta): A1
desinformación persuasiva · A2 inyección autorreplicante (el infiltrado leyó
un documento envenenado) · A3 suplantación de rol con captura de la
decisión · A4 manipulación de consenso (inundación fuera de la topología,
votos repetidos y votos sybil) · A5 distribuido de baja intensidad ·
adaptativo (escala A3 → A4 → A2 → A1 → A5 cuando lo bloquean, y se duerme para
recuperar reputación).

**Perfiles de modelo** (`profiles.py`): `frontera`, `intermedio` y `local`.
Son **parámetros de simulación calibrables, no mediciones**; la
susceptibilidad del perfil `local` (0,824) replica el dato citado en la
propuesta. Con `--llm gemini|ollama`, los agentes honestos redactan con un
modelo real y esos efectos salen del propio modelo.

**Experimentos** (`run_experiment.py`):

| Experimento | Diseño |
|---|---|
| `factorial` | 4 topologías × (A1–A5 + adaptativo) × 2 fracciones × 3 modelos × 8 configuraciones × N corridas, más corridas sin ataque |
| `curva` | barrido del umbral base (0,3–0,8) con A+B+C (SP5) |
| `costo` | juez y cuarentena como llamadas LLM, para medir tokens y latencia realistas |

Las semillas son el índice de corrida, así que una misma semilla ve la misma
tarea y las mismas señales en todas las configuraciones: las comparaciones
contra la línea base son **pareadas** y los IC 95 % se calculan por
remuestreo pareado.

**Métricas** (`analysis.py`): tasa de éxito del ataque y su reducción frente
a la línea base; F1, precisión, recall y tasa de falsos positivos al
**identificar** agentes comprometidos (identificar = aislar; los infectados
cuentan como comprometidos); exactitud sin ataque; utilidad de colaboración
(exactitud del grupo menos la exactitud individual media); sobrecarga de
tokens y de latencia p95; rondas hasta la detección; superaditividad (H4);
comparación adaptativo frente al mejor ataque estático (SP4).

---

## Instalación y uso

```bash
pip install -r requirements.txt

# Recorrido mensaje a mensaje con texto fijo (sin LLM)
python demo.py

# Las 7 escenas de la propuesta (sin LLM, determinista)
python demo_escenas.py

# Banco de pruebas: preset rapido (~1 min) o el diseño completo (>= 30 corridas/celda)
python run_experiment.py
python run_experiment.py --preset completo
python run_experiment.py --solo-analisis          # rehace tablas y panel desde results/*.csv
# -> results/resumen.md, results/panel.html, results/tablas/*.csv

# Con un LLM real (variables de entorno, nunca claves en el código)
#   PowerShell: $env:GOOGLE_API_KEY = "tu-clave"     (o $env:TRUSTMAS_LLM = "ollama")
python demo_orchestrator.py --topologia estrella   # lineal | estrella | jerarquica | malla
python run_experiment.py --llm gemini --llm-corridas 2

# Tests (no requieren clave ni red)
python -m pytest tests -q

# Docker / DVC
docker build -t trust-mas . && docker run --rm trust-mas
dvc repro
```

Variables de entorno del LLM: `TRUSTMAS_LLM` (`gemini` | `ollama`),
`GOOGLE_API_KEY`, `GEMINI_MODEL` (por defecto `gemini-2.0-flash`; cámbiala si
ese modelo ya no está disponible), `OLLAMA_MODEL`, `OLLAMA_HOST`. Ollama
requiere `pip install langchain-ollama`.

## Tests

```
tests/test_identity.py               Capa A: firma, roles, nonces, cadena de tokens
tests/test_provenance.py             Capa B: cuarentena, autorización por acción
tests/test_trust.py                  Capa C: reputación, umbral adaptativo, grafo
tests/test_judge_quarantine.py       juez de contenido, modelo en cuarentena, DefenseConfig
tests/test_bus_integration.py        integración A -> B -> C, procedencia efectiva, taint, tokens
tests/test_bus_defenses.py           capas apagadas, atribución, flujo, remediación, hilos
tests/test_audit.py                  integridad de la cadena de hashes
tests/test_orchestrator.py           nodos LangGraph con un LLM de prueba
tests/test_orchestrator_topologies.py  DEGRADE / CORROBORATE / QUARANTINE y las 4 topologías
tests/test_protocols.py              adaptadores A2A y MCP
tests/test_testbed.py                tareas, topologías, ataques, episodios, análisis, panel
tests/test_demos.py                  las demos corren y cumplen su guion
```

## Decisiones de diseño relevantes

- **El rol lo certifica el registro, nunca el mensaje.**
- **Ninguna capa decide "aceptar" de forma unilateral.** B fuerza cuarentena
  sobre un score alto de C; una acción sin capacidad fuerza rechazo.
- **El bus solo puede quitar confianza a una etiqueta, nunca añadirla**, y la
  contaminación la registra el runtime, no el agente.
- **Solo se castiga lo atribuible.** Sin esta regla, la Capa C se vuelve un arma:
  un atacante hunde la reputación de un honesto enviando basura a su nombre.
  El banco de pruebas lo muestra (A4 sin Capa A → falsos positivos altos).
- **Fail-closed.** Sin etiqueta → no confiable; sin token → no autorizado; un
  sobre A2A sin metadatos → rechazado.
- **Identificar = aislar.** Una reputación baja es sospecha; la
  identificación que cuenta para F1 y falsos positivos es la decisión que el
  sistema ejecuta. Contar la sospecha disparaba los falsos positivos en
  topologías dispersas, donde un honesto en minoría persistente pierde
  reputación.
- **CORROBORATE es casi neutro para la reputación** (+0,02): pedir
  verificación no es evidencia de malicia.
- **El log guarda el hash del contenido, no el contenido.**
- **Se descartó escalar la validación cruzada por la confianza declarada**: sube
  el recall frente a A1 pero no baja su éxito y dispara los falsos positivos.

## Limitaciones y trabajo futuro

- **Perfiles de modelo simulados.** Las cifras del preset `completo` miden el
  mecanismo con perfiles calibrables, no a un LLM concreto; la comparación
  con modelos reales (`--llm`) está implementada pero requiere clave o un
  servidor Ollama y presupuesto de llamadas.
- **A1 y A5 siguen abiertos.** La desinformación persuasiva sin marcadores y
  el ataque de baja intensidad casi no se detectan: son los resultados
  negativos que la propuesta anticipaba (H1, H5). El juez LLM es la vía
  prevista para A1.
- **No se integró AutoGen**: el mecanismo es el mismo que en LangGraph (el bus
  entre el agente y el historial compartido); queda como adaptador pendiente.
- **Sin observabilidad externa** (Langfuse / OpenTelemetry): el registro de
  auditoría y `trace=True` del episodio cubren la trazabilidad del
  prototipo.
- **No se evaluó contra AgentDojo / InjecAgent** ni se usó PyG para la
  detección sobre grafo.
- **Corroboración sin protocolo de ida y vuelta**: en LangGraph lo que va a
  CORROBORATE queda retenido; en el banco de pruebas cuenta si otro emisor
  independiente lo respalda.
- **Auditoría sin anclaje externo**: el log detecta alteraciones pero vive en
  memoria o en un JSONL local.
- Ver también `docs/modelo_de_amenazas.md` (amenazas mitigadas, parciales y
  abiertas).
