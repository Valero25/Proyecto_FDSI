# Modelo de amenazas y matriz de trazabilidad (MAESTRO × OWASP)

Producto **P6** de la propuesta. Cada amenaza del alcance se traza a:

- su capa en **MAESTRO** (marco de modelado de amenazas para IA agéntica de la
  Cloud Security Alliance, 7 capas: L1 modelos fundacionales, L2 operaciones de
  datos, L3 frameworks de agentes, L4 despliegue e infraestructura, L5
  evaluación y observabilidad, L6 seguridad y cumplimiento, L7 ecosistema de
  agentes);
- las entradas de **OWASP** que la cubren: *Agentic AI – Threats and
  Mitigations* (T1–T15) y *Top 10 for LLM Applications 2025* (LLM01–LLM10);
- el perfil de ataque del banco de pruebas que la ejercita (A1–A5);
- el control de TRUST-MAS que la mitiga y la evidencia (tests y experimentos).

El estado (mitigada / parcial / abierta) resume la evidencia del banco de
pruebas. Las cifras concretas salen de `results/resumen.md` y
`results/panel.html`, que se regeneran con `python run_experiment.py`.

## Supuestos del adversario

- **Interno**: controla por completo uno o dos agentes registrados (sus claves,
  su contenido, su momento de envío) o secuestró a uno por inyección indirecta.
- **No** controla el registro de identidad, el bus ni las claves de otros
  agentes (la seguridad de infraestructura está fuera del alcance).
- Puede observar qué les pasa a sus propios mensajes y adaptarse (SP4).
- Conoce la tarea y la respuesta que quiere imponer, no la verdad de las
  señales privadas de los demás.

## Matriz

| # | Amenaza | Perfil | MAESTRO | OWASP Agentic | OWASP LLM | Control TRUST-MAS | Evidencia | Estado |
|---|---|---|---|---|---|---|---|---|
| 1 | Suplantación de rol (un worker se declara orquestador) | A3 | L7, L3 | T9, T3 | LLM06 | Capa A: el rol lo certifica el registro, no el mensaje (`verify_message`) | `test_suplantacion_de_rol_se_rechaza`, `test_a3_captura_la_decision_sin_defensas_y_la_capa_a_lo_impide` | Mitigada |
| 2 | Suplantación de emisor (mensaje firmado por X a nombre de Y) | A3, A4 | L7 | T9 | — | Capa A: firma Ed25519 + canal autenticado (`channel_sender`) que atribuye al emisor real | `test_canal_autenticado_atribuye_la_suplantacion_al_emisor_real` | Mitigada |
| 3 | Captura del orquestador (orden `fijar_decision` falsa) | A3 | L3 | T3, T6 | LLM06 | Capa A + Capa B: la acción exige el token del orquestador y una identidad verificada | `test_a3_captura...`, escena 3 de `demo_escenas.py` | Mitigada |
| 4 | Repetición de un mensaje capturado | — | L7, L4 | T9 | — | Capa A: nonce + ventana temporal; el replay no se atribuye al firmante | `test_replay_de_nonce_se_bloquea`, `test_replay_no_se_atribuye_al_firmante` | Mitigada |
| 5 | Mensaje de otro flujo o de una ronda vieja | — | L3 | T12 | — | Capa A: `expected_digest` (integridad de flujo, brecha B3) | `test_digest_de_otro_flujo_se_rechaza` | Mitigada |
| 6 | DoS quemando nonces con firmas falsas | — | L4 | T4 | LLM10 | Capa A: el nonce se registra después de validar la firma | `test_firma_invalida_no_quema_el_nonce_del_mensaje_legitimo` | Mitigada |
| 7 | Inyección indirecta autorreplicante desde un documento o herramienta | A2 | L2, L3, L7 | T1, T12 | LLM01 | Capa B: taint del agente que leyó contenido no confiable, cuarentena y modelo en cuarentena que elimina instrucciones | `test_a2_se_propaga_sin_defensas_y_la_capa_b_lo_contiene`, `test_cuarentena_elimina_la_carga_y_conserva_el_dato` | Mitigada |
| 8 | Inyección escrita por un agente deshonesto (sin documento de por medio) | adaptativo | L7 | T12, T13 | LLM01 | Solo Capa C (juez de contenido): la procedencia es legítimamente del agente | escena 6 de `demo_escenas.py` (con A+B el adaptativo gana usando A2) | Parcial |
| 9 | "Lavado" de procedencia (etiquetar contenido externo como propio o confiable) | A2 | L2 | T1, T12 | LLM01 | Capa B: procedencia efectiva recalculada por el bus; solo puede quitar confianza | `test_autoetiqueta_confiable_de_fuente_externa_no_se_respeta`, `test_agente_contaminado_no_puede_lavar...` | Mitigada |
| 10 | Un worker "habla en nombre del usuario" | — | L7 | T9 | LLM01 | Capa B: `user` solo es confiable si lo retransmite el orquestador | `test_worker_no_puede_hablar_en_nombre_del_usuario` | Mitigada |
| 11 | Desinformación persuasiva sin marcadores | A1 | L7, L1 | T5, T6, T7 | LLM09 | Capa C: validación cruzada y reputación bayesiana (peso por reputación) | `por_ataque.csv` (A1), hipótesis H1 | Parcial |
| 12 | Manipulación de consenso: inundación y votos sybil | A4 | L7 | T13, T9 | LLM10 | Capa A (una identidad = un voto) + Capa C (aristas fuera de la topología, ráfagas por arista) | `test_a4_sin_capa_a_incrimina_a_honestos_suplantados`, `por_ataque.csv` (A4) | Mitigada con A+C |
| 13 | Ataque distribuido de baja intensidad | A5 | L7, L5 | T13, T7 | LLM09 | Capa C (reputación): la señal por mensaje es demasiado débil | hipótesis H5, `rondas_deteccion.csv` | Abierta |
| 14 | Incriminar a un agente honesto con mensajes falsificados a su nombre | A4 | L7 | T9 | — | Capa A: solo se penaliza un fallo atribuible (firma válida o canal autenticado) | `test_firma_falsificada_no_castiga_al_agente_suplantado` | Mitigada (sin Capa A, abierta) |
| 15 | Escalada de privilegios por delegación de tokens | — | L6, L3 | T3 | LLM06 | Capa A/B: atenuación que nunca amplía; verificación de la cadena hasta una raíz con rol orquestador | `test_cadena_de_delegacion_*`, `test_token_autoemitido_*` | Mitigada |
| 16 | Uso de herramientas no autorizado (MCP `tools/call`) | — | L3 | T2 | LLM06, LLM05 | `McpToolGuard`: capacidad por herramienta antes de ejecutar; resultado etiquetado `tool_output` y taint | `test_mcp_*` | Mitigada |
| 17 | Alteración o borrado del historial de decisiones | — | L5, L6 | T8 | — | Log de auditoría append-only encadenado por hash | `test_audit.py` | Mitigada (detección; sin anclaje externo) |
| 18 | Exfiltración del system prompt o de credenciales | — | L1, L6 | T3 | LLM07, LLM02 | Capa C: categoría `exfiltracion` del juez | `test_juez_heuristico_detecta_categorias...` | Parcial (no evaluada en el banco) |
| 19 | Adversario adaptativo que cambia de táctica | adaptativo | L7 | T13 | — | Combinación A + B + C + remediación selectiva | `adaptativo.csv`, escena 6 | Mitigada con ABC; abierta con cualquier subconjunto |

## Fuera del alcance (según la propuesta)

| Amenaza | MAESTRO | OWASP | Motivo |
|---|---|---|---|
| Envenenamiento del modelo base o de sus datos de entrenamiento | L1, L2 | LLM04 | Fuera del alcance de la propuesta |
| Cadena de suministro (dependencias, modelos de terceros) | L4 | LLM03 | Seguridad de infraestructura |
| Compromiso del bus, del registro o del host | L4 | — | Se asume una base de cómputo confiable |
| Debilidades de embeddings / RAG | L2 | LLM08 | No hay recuperación vectorial en el sistema |

## Limitaciones conocidas del prototipo

- **Perfiles de modelo simulados.** Las probabilidades de susceptibilidad,
  obediencia y persuasión de `testbed/profiles.py` son parámetros calibrables,
  no mediciones. Para resultados empíricos:
  `python run_experiment.py --llm gemini` (o `ollama`).
- **Juez heurístico.** Es barato (0 tokens) pero se evade con paráfrasis; el
  juez LLM (`LLMJudge`) es el reemplazo previsto, con su costo medido en el
  experimento `costo`.
- **Validación cruzada.** Castiga el desacuerdo con el resto del sistema, así
  que un honesto que se queda en minoría persistente en una topología dispersa
  pierde reputación. La identificación exige aislamiento (y no solo reputación
  baja) para contener esos falsos positivos.
- **Corroboración.** En el orquestador LangGraph, un mensaje en CORROBORATE
  queda retenido. En el banco de pruebas cuenta si otro emisor independiente
  afirma lo mismo. No hay todavía un protocolo de pedir y recibir
  confirmación.
- **Auditoría local.** El log detecta alteraciones, pero no está anclado a un
  almacenamiento externo inmutable.
