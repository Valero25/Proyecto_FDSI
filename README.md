# Proyecto_FDSI — TRUST-MAS

Prototipo de **defensa en profundidad para sistemas multiagente (MAS)**: detecta
y frena a un agente comprometido infiltrado entre agentes de confianza, incluso
cuando ese agente genera texto convincente con un LLM real.

La premisa de diseño es que **ninguna capa decide "aceptar" por sí sola**. Un
mensaje solo se propaga si supera, en orden, tres líneas de defensa
independientes: identidad criptográfica, procedencia del contenido y un
puntaje de confianza dinámico. Si cualquiera de las tres detecta un problema,
el mensaje se degrada, se pone en cuarentena o se rechaza, y la decisión queda
registrada en un log de auditoría inmutable.

---

## Índice

- [Arquitectura general](#arquitectura-general)
- [Estructura del repositorio](#estructura-del-repositorio)
- [Capa A — Identidad](#capa-a--identidad-srctrust_masidentitypy)
- [Capa B — Procedencia](#capa-b--procedencia-srctrust_masprovenancepy)
- [Capa C — Confianza dinámica](#capa-c--confianza-dinámica-srctrust_mastrustpy)
- [El bus de mensajes](#el-bus-de-mensajes-srctrust_masbuspy)
- [Modelo de datos](#modelo-de-datos-srctrust_masmodelspy)
- [Log de auditoría](#log-de-auditoría-srctrust_masauditpy)
- [Agentes: simulados vs. orquestador real](#agentes-simulados-vs-orquestador-real)
- [Instalación y uso](#instalación-y-uso)
- [Tests](#tests)
- [Decisiones de diseño relevantes](#decisiones-de-diseño-relevantes)
- [Qué no incluye todavía](#qué-no-incluye-todavía)

---

## Arquitectura general

Todo mensaje entre agentes pasa obligatoriamente por `MessageBus.route()`,
que aplica las tres capas **en orden estricto** y termina emitiendo una de
cinco decisiones de política:

```
                         Message (firmado por el emisor)
                                    |
                                    v
                     +--------------------------------+
                     |   CAPA A -- Identidad           |
                     |   src/trust_mas/identity.py      |
                     |                                  |
                     |  1. ¿emisor conocido en el       |
                     |     registro?                    |
                     |  2. rol declarado == rol         |
                     |     oficial del registro          |
                     |  3. timestamp dentro de ventana  |
                     |  4. nonce no visto (anti-replay) |
                     |  5. firma Ed25519 válida          |
                     +--------------------------------+
                                    |
                     firma inválida |  identidad OK
                     -> REJECT      |
                     (fin)          v
                     +--------------------------------+
                     |   CAPA B -- Procedencia          |
                     |   src/trust_mas/provenance.py    |
                     |                                  |
                     |  1. ¿la etiqueta de origen es    |
                     |     confiable?                    |
                     |  2. ¿contenido no confiable        |
                     |     intenta disparar una acción?  |
                     |  3. ¿el token de capacidad         |
                     |     autoriza la acción pedida?    |
                     +--------------------------------+
                                    |
                                    v
                     +--------------------------------+
                     |   CAPA C -- Confianza dinámica    |
                     |   src/trust_mas/trust.py         |
                     |                                  |
                     |  1. reputación bayesiana previa   |
                     |     del emisor (Beta)             |
                     |  2. penalización por procedencia  |
                     |  3. penalización por contenido    |
                     |     sospechoso                    |
                     |  4. penalización por anomalía de  |
                     |     grafo (fan-out, NetworkX)     |
                     |  5. comparación contra umbral      |
                     |     adaptativo                     |
                     +--------------------------------+
                                    |
                                    v
        ACCEPT / DEGRADE / CORROBORATE / QUARANTINE / REJECT
                                    |
                                    v
                     +--------------------------------+
                     |  Log de auditoría append-only    |
                     |  encadenado por hash              |
                     |  src/trust_mas/audit.py           |
                     +--------------------------------+
```

Puntos clave del flujo (implementados en `MessageBus.route`,
`src/trust_mas/bus.py:41`):

- Si la **Capa A** falla (rol falso, replay, firma inválida, emisor
  desconocido, timestamp fuera de ventana), el mensaje se **rechaza de
  inmediato** y ni siquiera se evalúan las capas B/C — pero el intento en sí
  ya penaliza la reputación del emisor.
- La **Capa B** puede forzar `QUARANTINE` **incluso si la Capa C dio un score
  alto** (`bus.py:74`): la procedencia no confiable nunca queda "cubierta"
  por una buena reputación. Esta es la esencia de la defensa en profundidad:
  ninguna capa individual tiene autoridad de veto positivo sobre las otras.
- Una acción (`message.action`, p. ej. `transfer_funds`) sin un token de
  capacidad que la autorice fuerza `REJECT` sin importar qué tan bien haya
  puntuado el contenido.
- Cada decisión final —acepte, degrade o rechace— se anota en el log de
  auditoría con su cadena de razones, antes de devolver el resultado al
  llamador.

## Estructura del repositorio

```
Proyecto_FDSI/
├── README.md
├── requirements.txt
├── demo.py                      # demo con agentes simulados (texto fijo)
├── demo_orchestrator.py         # demo con LangGraph + Gemini (LLM real)
├── src/trust_mas/
│   ├── models.py                # tipos de datos compartidos (Message, tokens, enums)
│   ├── identity.py               # Capa A: firma, roles, nonces, tokens de capacidad
│   ├── provenance.py              # Capa B: etiquetado de origen y cuarentena
│   ├── trust.py                   # Capa C: reputación bayesiana, grafo, umbral adaptativo
│   ├── bus.py                     # orquesta A -> B -> C y decide la política final
│   ├── audit.py                    # log de auditoría encadenado por hash
│   ├── agent.py                    # agente simulado (compone y firma mensajes)
│   └── orchestrator.py             # grafo de LangGraph con agentes respaldados por LLM
└── tests/
    ├── test_identity.py           # Capa A
    ├── test_provenance.py          # Capa B
    ├── test_trust.py                # Capa C
    ├── test_bus_integration.py      # integración de las tres capas vía el bus
    ├── test_audit.py                 # integridad de la cadena de hashes
    └── test_orchestrator.py          # grafo LangGraph con un LLM de prueba (doble)
```

---

## Capa A — Identidad (`src/trust_mas/identity.py`)

Responsabilidad: garantizar que un mensaje realmente proviene de quien dice
provenir, con el rol que realmente tiene, y que no es una repetición de un
mensaje legítimo capturado antes.

**Componentes:**

- **`KeyPair`** — par de claves Ed25519 (vía `pynacl`) por agente. Cada
  agente firma sus mensajes con su clave privada; el bus verifica con la
  clave pública registrada.
- **`IdentityRegistry`** — la fuente de verdad de qué agentes existen, con
  qué clave pública y **qué rol oficial**. Este es el detalle de diseño más
  importante de la capa: *el rol lo certifica el registro, nunca el mensaje*.
  `verify_message` compara `message.declared_role` contra
  `registry.official_role(sender_id)`; si no coinciden, se rechaza con
  "suplantación de rol" — esto anula por completo que un agente comprometido
  se declare `orchestrator` para ganar autoridad que no le corresponde.
- **`NonceStore`** — registra pares `(sender_id, nonce)` ya vistos. Un
  mensaje con un nonce repetido (el mismo objeto reenviado, un ataque de
  *replay*) se rechaza aunque la firma sea perfectamente válida, porque de
  hecho lo es: es el mensaje original capturado y reenviado.
- **`verify_message`** — pipeline de verificación, en este orden:
  1. el emisor debe estar en el registro,
  2. el rol declarado debe coincidir con el rol oficial,
  3. el timestamp debe caer dentro de una ventana de validez
     (`NONCE_WINDOW_SECONDS = 300s`),
  4. el nonce no debe haberse visto antes,
  5. la firma Ed25519 sobre `message.signing_payload()` debe verificar
     correctamente.
- **`CapabilityToken` + `issue_capability_token` / `attenuate_capability_token`**
  — tokens de capacidad **atenuables**: un agente puede delegar en otro un
  subconjunto de sus propias acciones autorizadas, pero `attenuate_capability_token`
  lanza `ValueError` si se piden acciones fuera del token padre (escalamiento
  de privilegios) o si ya no queda profundidad de delegación
  (`max_delegation_depth`). Es decir: **nunca se puede delegar más autoridad
  de la que se tiene**.

`Message.signing_payload()` (`src/trust_mas/models.py:76`) serializa de forma
canónica los campos cubiertos por la firma — deliberadamente **excluye**
`provenance` (la asigna el bus, no el emisor) y la propia `signature`.

## Capa B — Procedencia (`src/trust_mas/provenance.py`)

Responsabilidad: que el sistema nunca trate contenido de fuentes no
confiables (documentos externos, salidas de herramientas) con la misma
autoridad que el mensaje de un agente par legítimo — y que ninguna acción
concreta se ejecute sin un permiso explícito para ella.

- **`tag_provenance(source, origin_id, trusted=None, chain=())`** — construye
  una `ProvenanceTag`. Por defecto, `ProvenanceSource.EXTERNAL_DOC` y
  `ProvenanceSource.TOOL_OUTPUT` se marcan **no confiables**
  (`UNTRUSTED_BY_DEFAULT`); `ProvenanceSource.AGENT` y `ProvenanceSource.USER`
  se marcan confiables.
- **`QuarantineEngine.evaluate`** — decide si un mensaje debe enrutarse a
  cuarentena antes de llegar a un agente con autoridad para planear o invocar
  herramientas:
  - sin etiqueta de procedencia → se trata como no confiable por defecto
    (fail-closed),
  - etiqueta explícitamente no confiable → cuarentena,
  - contenido no confiable que además intenta disparar una `action`
    directamente → cuarentena, incluso si en otro contexto ese contenido
    sería inocuo.
- **`check_action_capability(token, action)`** — autorización **por acción
  individual**: cada intento de disparar una `action` (p. ej.
  `transfer_funds`) se valida contra el `CapabilityToken` del emisor; sin
  token, con token expirado, o con una acción fuera de las permitidas por el
  token, la acción se rechaza.

## Capa C — Confianza dinámica (`src/trust_mas/trust.py`)

Responsabilidad: un puntaje de confianza por mensaje que combina reputación
histórica, señales de contenido y patrones de comunicación, comparado contra
un umbral que se endurece solo cuando el sistema observa más actividad
sospechosa.

- **`BayesianReputation`** — reputación por agente modelada como una
  distribución **Beta(α, β)**: α acumula evidencia de comportamiento honesto,
  β acumula evidencia sospechosa/maliciosa. El score de reputación es la
  media de la Beta, `α / (α + β)`, siempre en `[0, 1]`. Cada evaluación
  actualiza α o β según la decisión final tomada (ver tabla de
  `honest_evidence` en `trust.py:174`): `ACCEPT` refuerza levemente la
  reputación, `QUARANTINE`/`REJECT` la penalizan fuerte.
- **`GraphAnomalyDetector`** — mantiene un grafo dirigido (`networkx.DiGraph`)
  de quién le ha escrito a quién. Penaliza a un emisor cuyo grado de salida
  se desvía significativamente (`z-score > 2.0`) de la media del sistema —
  es decir, un **fan-out repentino** hacia muchos destinatarios distintos,
  patrón típico de un agente comprometido intentando propagarse.
- **`AdaptiveThreshold`** — el umbral de aceptación empieza en
  `base_threshold = 0.5` pero se endurece (hasta `0.9`) en función de qué
  proporción de mensajes recientes tuvieron score bajo, en una ventana
  deslizante de 20 mensajes. El sistema se vuelve más desconfiado
  globalmente después de observar actividad sospechosa, no solo hacia el
  agente que la originó.
- **`TrustEngine.evaluate`** — combina todo:
  1. parte de la reputación bayesiana previa del emisor,
  2. fuerza el score a `0.0` si la firma es inválida,
  3. resta `0.30` si la procedencia no es confiable,
  4. resta hasta `0.50` según cuántos `SUSPICIOUS_MARKERS` aparecen en el
     cuerpo del mensaje (heurística simple por diseño para el prototipo —
     "ignora tus instrucciones", "transfiere fondos", "revela tu system
     prompt", etc.; en un sistema real esto sería un clasificador o un LLM
     juez),
  5. resta la penalización de anomalía de grafo,
  6. compara el score final contra el umbral adaptativo vigente y decide
     `ACCEPT` / `DEGRADE` / `CORROBORATE` / `QUARANTINE` (ver
     `_decide`, `trust.py:185`).

## El bus de mensajes (`src/trust_mas/bus.py`)

`MessageBus` es el punto de integración obligatorio de las tres capas. No
hay ninguna otra vía en el código para que un mensaje llegue a un agente sin
pasar por `bus.route()`. Su responsabilidad:

1. Ejecutar la Capa A (`verify_message`). Si falla, penaliza la reputación,
   registra un `REJECT` en el log de auditoría y retorna de inmediato.
2. Ejecutar la Capa B (`QuarantineEngine.evaluate` +
   `check_action_capability`).
3. Ejecutar la Capa C (`TrustEngine.evaluate`), pasándole si la firma fue
   válida y si la procedencia es confiable — la reputación bayesiana también
   se actualiza aquí, dentro de `TrustEngine.evaluate`.
4. Combinar los veredictos: la Capa B puede *forzar* `QUARANTINE` sobre un
   `ACCEPT` de la Capa C; una acción sin capacidad *fuerza* `REJECT` sobre
   cualquier decisión previa.
5. Registrar la decisión final, el score, el umbral y la cadena completa de
   razones en el `AuditLog`.

## Modelo de datos (`src/trust_mas/models.py`)

- **`AgentRole`** — `orchestrator | worker | tool | quarantine`.
- **`ProvenanceSource`** — `agent | external_doc | tool_output | user`.
- **`PolicyDecision`** — `accept | degrade | corroborate | quarantine | reject`.
- **`ProvenanceTag`** — origen, id de origen, si es confiable, cadena de
  procedencia (`chain`) para trazar reenvíos.
- **`CapabilityToken`** — emisor, sujeto, conjunto de acciones permitidas,
  profundidad máxima de delegación, expiración, firma.
- **`Message`** — emisor, receptor, rol declarado, cuerpo, digest de
  conversación, nonce, timestamp, acción opcional, firma, etiqueta de
  procedencia opcional.

## Log de auditoría (`src/trust_mas/audit.py`)

`AuditLog` implementa un ledger **append-only encadenado por hash** (similar
a una blockchain simple, sin consenso distribuido): cada `AuditEntry`
incluye `prev_hash` (el hash de la entrada anterior) y su propio
`entry_hash`, calculado sobre el cuerpo canónico serializado en JSON con
claves ordenadas. `verify_chain()` recorre toda la cadena y detecta:

- una entrada cuyo `prev_hash` no coincide con el hash real de la anterior
  (entrada insertada o borrada), o
- una entrada cuyo contenido fue alterado después de escrita (su
  `entry_hash` recalculado ya no coincide con el guardado).

El contenido del mensaje no se guarda en texto plano en la entrada: se
guarda su `content_hash` (SHA-256), de modo que el log prueba integridad sin
necesariamente conservar el contenido sensible. Opcionalmente, si se
construye `AuditLog(path=...)`, cada entrada también se persiste como una
línea JSON en un archivo (formato JSONL).

## Agentes: simulados vs. orquestador real

Hay dos formas de generar los mensajes que fluyen por el bus:

- **`SimulatedAgent`** (`src/trust_mas/agent.py`) — usado por `demo.py` y en
  los tests. Compone mensajes con texto fijo y los firma con su `KeyPair`.
  Expone un parámetro `declared_role` independiente de `self.role`
  precisamente para poder simular, en la demo, un agente que miente sobre su
  rol.
- **`AgentNode` + `build_linear_graph`** (`src/trust_mas/orchestrator.py`,
  usado por `demo_orchestrator.py`) — cada nodo es un `SimulatedAgent`
  respaldado por un **LLM real** (`.invoke(prompt) -> objeto con
  `.content``, compatible con `ChatGoogleGenerativeAI` de
  `langchain-google-genai` o con un doble de prueba en los tests). El grafo
  de estados es de **LangGraph**: en cada nodo se construye un prompt con el
  contexto compartido acumulado, se invoca el LLM, el resultado se firma y
  se enruta por el mismo `MessageBus.route()`. Solo si la decisión es
  `ACCEPT` o `DEGRADE` (`PROPAGATING_DECISIONS`) el contenido se añade al
  `shared_context` que verán los siguientes nodos; una decisión
  `CORROBORATE`/`QUARANTINE`/`REJECT` bloquea la propagación **aunque el
  texto ya haya sido generado por un modelo real**.

  Esto ataca directamente un vector conocido en frameworks como
  AutoGen/LangGraph: el historial o estado compartido entre agentes como
  canal de contaminación. Aquí ese estado compartido queda saneado por el
  bus *antes* de escribirse, en vez de confiar en que el LLM "se dé cuenta"
  de que un mensaje es una inyección.

  La topología implementada es **lineal** (`build_linear_graph`:
  `START -> node_0 -> node_1 -> ... -> END`), la más simple de las 4
  topologías del diseño factorial de la propuesta (línea base sobre la que
  se pueden montar estrella, malla y jerárquica reutilizando el mismo
  `AgentNode` con otro orden de aristas).

---

## Instalación y uso

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

### `demo.py` — qué demuestra

Simula, en orden, tres perfiles de ataque básicos y muestra cómo cada uno
queda contenido por una capa distinta:

1. **Fase 1** — tráfico honesto entre agentes, construye reputación inicial.
2. **Fase 2 (A1 — suplantación de rol)** — `worker_c` declara ser
   `orchestrator` para intentar autorizar una transferencia de fondos. La
   **Capa A** lo rechaza porque el registro dice que `worker_c` es `worker`.
3. **Fase 3 (A2 — repetición de mensaje)** — un mensaje legítimo se reenvía
   tal cual (mismo nonce). La **Capa A** lo rechaza por nonce repetido.
4. **Fase 4 (A3 — inyección de instrucciones)** — contenido con instrucciones
   maliciosas etiquetado como proveniente de un documento externo no
   verificado, intentando disparar `transfer_funds`. La **Capa B** lo enruta
   a cuarentena o la **Capa C** lo rechaza por score bajo.
5. **Fase 5** — mensajes aparentemente normales del agente comprometido
   después de su historial sospechoso, mostrando cómo la reputación
   bayesiana ya degradada afecta las decisiones subsiguientes.
6. **Resumen final** — snapshot de reputación por agente y verificación de
   integridad de la cadena de auditoría.

### `demo_orchestrator.py` — qué demuestra

El mismo tipo de ataque de suplantación de rol (A1), pero con **texto
generado por Gemini en tiempo real** en vez de texto fijo, corriendo sobre
un grafo de LangGraph de 4 nodos:
`orchestrator -> analyst -> compromised -> synthesizer`. El nodo
`compromised` recibe un system prompt que lo instruye a redactar (en un
contexto de ejercicio de seguridad autorizado / red-team académico) un
mensaje convincente que se hace pasar por el orquestador — y aun así la
Capa A lo bloquea porque la verificación es contra el registro de identidad,
no contra lo que el texto generado por el LLM afirma ser.

## Tests

```
tests/test_identity.py           Capa A: firma, roles, nonces, tokens de capacidad
tests/test_provenance.py         Capa B: cuarentena, autorización por acción
tests/test_trust.py              Capa C: reputación bayesiana, umbral adaptativo, grafo
tests/test_bus_integration.py    integración A -> B -> C a través del bus
tests/test_audit.py               integridad y detección de manipulación de la cadena de hashes
tests/test_orchestrator.py        grafo de LangGraph con un LLM de prueba (doble determinista)
```

Los tests del orquestador **no** requieren `GOOGLE_API_KEY`: usan un doble
de prueba que implementa el mismo protocolo `.invoke(prompt) -> .content`
que `ChatGoogleGenerativeAI`, sin llamar a un LLM real.

## Decisiones de diseño relevantes

- **El rol lo certifica el registro, nunca el mensaje.** Es la defensa
  central contra suplantación de rol: aunque un atacante controle
  completamente el contenido y hasta la firma de sus propios mensajes,
  nunca puede hacer que el registro le atribuya un rol que no tiene.
- **Ninguna capa decide "aceptar" de forma unilateral.** La Capa B puede
  forzar cuarentena sobre un score alto de la Capa C; una acción sin
  capacidad fuerza rechazo sobre cualquier decisión previa. Esto es
  deliberado: es lo que hace que sea *defensa en profundidad* y no un único
  punto de fallo.
- **Fail-closed ante ausencia de información.** Un mensaje sin etiqueta de
  procedencia se trata como no confiable (Capa B); un token ausente para una
  acción se trata como no autorizado (Capa B); un score que no llega al
  umbral se trata como sospechoso, no como neutral (Capa C).
- **`CORROBORATE` es casi neutro para la reputación** (`honest_evidence =
  0.02`), a diferencia de `QUARANTINE`/`REJECT`: pedir verificación adicional
  no es en sí misma evidencia de malicia, así que no debería castigar
  fuertemente a un agente honesto que ocasionalmente cae cerca del umbral.
- **El log de auditoría guarda el hash del contenido, no el contenido en
  claro**, para poder probar integridad sin necesariamente conservar datos
  sensibles en el propio log.
- **Los marcadores de contenido sospechoso son una heurística deliberadamente
  simple** (`SUSPICIOUS_MARKERS` en `trust.py`), suficiente para demostrar el
  mecanismo del prototipo; en un sistema de producción esa señal la daría un
  clasificador entrenado o un LLM usado como juez.

## Qué no incluye todavía

- Integración con AutoGen o protocolos MCP/A2A.
- Dashboard en vivo para visualizar decisiones y reputación en tiempo real.
- Topologías no lineales (estrella, malla, jerárquica) — el mecanismo
  (`AgentNode`) ya está preparado para soportarlas, pero solo existe el
  ensamblador lineal (`build_linear_graph`).
- El banco de pruebas factorial completo descrito en la propuesta (4
  topologías × 5 perfiles de ataque × 2 fracciones de agentes comprometidos ×
  3 modelos, mínimo 30 corridas por celda).
