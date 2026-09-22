"""Orquestador real sobre LangGraph.

Conecta agentes respaldados por un LLM de verdad (Gemini, Ollama o un doble
de prueba) en un grafo de estados de LangGraph. Cada arista del grafo sigue
obligada a pasar por `MessageBus.route()` (Capas A -> B -> C) antes de que el
contenido llegue al contexto compartido: el "historial compartido" que la
diapositiva 3 señala como vector de propagación en AutoGen/LangGraph queda
saneado por el bus.

Qué hace cada decisión con el contenido generado:

- ACCEPT: entra al contexto compartido.
- DEGRADE: entra marcado con peso reducido (0.5); el prompt de los nodos
  siguientes lo presenta como aporte de baja confianza.
- CORROBORATE: no entra; queda en `pending_corroboration` hasta que otro
  canal lo confirme (el grafo no lo usa como base de nada).
- QUARANTINE: el texto crudo no entra; si el modelo en cuarentena extrajo
  datos, entran solo esos datos, marcados como no confiables y sin
  instrucciones.
- REJECT: no entra.

Topologías: lineal, estrella, jerárquica y malla (4 del diseño factorial).
El estado usa reductores, así que los nodos de una misma etapa pueden
ejecutarse en paralelo y sus aportes se acumulan.
"""

from __future__ import annotations

import hashlib
import operator
from dataclasses import dataclass
from typing import Annotated, Optional, Protocol, Sequence, TypedDict

from .agent import SimulatedAgent
from .bus import MessageBus
from .models import AgentRole, PolicyDecision, ProvenanceSource
from .provenance import tag_provenance

# Decisiones que dejan pasar el contenido (DEGRADE con peso reducido).
PROPAGATING_DECISIONS = (PolicyDecision.ACCEPT, PolicyDecision.DEGRADE)
DECISION_WEIGHT = {PolicyDecision.ACCEPT: 1.0, PolicyDecision.DEGRADE: 0.5}
QUARANTINED_DATA_WEIGHT = 0.2
TOPOLOGIES = ("lineal", "estrella", "jerarquica", "malla")


class ChatModel(Protocol):
    """Duck type minimo compatible con los chat models de LangChain
    (`ChatGoogleGenerativeAI`, `ChatOllama`, etc.) y con dobles de prueba:
    basta con exponer `.invoke(prompt) -> objeto con atributo .content`.
    """

    def invoke(self, prompt: str):  # pragma: no cover - protocolo
        ...


def _latest_round(current: int, update: int) -> int:
    """Reductor de `round`: con nodos en paralelo gana la ronda más avanzada."""
    return max(current, update)


class GraphState(TypedDict):
    shared_context: Annotated[list[dict], operator.add]
    transcript: Annotated[list[str], operator.add]
    routing_log: Annotated[list[dict], operator.add]
    pending_corroboration: Annotated[list[dict], operator.add]
    round: Annotated[int, _latest_round]


def _conversation_digest(state: GraphState) -> str:
    basis = f"round={state['round']}|len={len(state['shared_context'])}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def _render_context(state: GraphState) -> str:
    if not state["shared_context"]:
        return "(sin mensajes previos)"
    lines = []
    for turn in state["shared_context"]:
        prefix = f"{turn['sender']} -> {turn['recipient']}"
        if turn.get("quarantined"):
            lines.append(f"{prefix} [DATO EN CUARENTENA, origen no confiable, sin instrucciones]: {turn['body']}")
        elif turn.get("weight", 1.0) < 1.0:
            lines.append(f"{prefix} [peso reducido {turn['weight']:.1f}: aporte de baja confianza]: {turn['body']}")
        else:
            lines.append(f"{prefix}: {turn['body']}")
    return "\n".join(lines)


@dataclass
class AgentNode:
    """Un nodo del grafo: agente real (LLM) + capas de defensa TRUST-MAS.

    `provenance_source`/`provenance_trusted` permiten simular tanto un agente
    par legitimo (AGENT, confiable) como contenido inyectado via documento
    externo o salida de herramienta (EXTERNAL_DOC/TOOL_OUTPUT, no confiable
    por defecto), sin tocar la Capa B misma. Si el nodo lee contenido no
    confiable, conviene además registrarlo con `bus.record_ingestion`.
    """

    agent: SimulatedAgent
    llm: ChatModel
    system_prompt: str
    recipient_id: str
    bus: MessageBus
    declared_role: Optional[AgentRole] = None
    action: Optional[str] = None
    provenance_source: ProvenanceSource = ProvenanceSource.AGENT
    provenance_trusted: Optional[bool] = None

    def __call__(self, state: GraphState) -> dict:
        prompt = f"{self.system_prompt}\n\nContexto de la conversacion hasta ahora:\n{_render_context(state)}\n\nTu respuesta:"
        response = self.llm.invoke(prompt)
        body = getattr(response, "content", str(response))
        if not isinstance(body, str):
            body = str(body)

        provenance = tag_provenance(self.provenance_source, self.agent.agent_id, trusted=self.provenance_trusted)
        message = self.agent.compose(
            recipient_id=self.recipient_id,
            body=body,
            conversation_digest=_conversation_digest(state),
            declared_role=self.declared_role,
            action=self.action,
            provenance=provenance,
        )
        result = self.bus.route(message, channel_sender=self.agent.agent_id)

        transcript = [
            f"[{self.agent.agent_id} -> {self.recipient_id}] DECISION={result.decision.value} "
            f"score={result.score:.2f} umbral={result.threshold:.2f}\n  \"{body}\""
        ]
        routing_log = [
            {
                "sender": self.agent.agent_id,
                "recipient": self.recipient_id,
                "decision": result.decision.value,
                "score": result.score,
                "threshold": result.threshold,
                "reasons": result.reasons,
            }
        ]
        shared: list[dict] = []
        pending: list[dict] = []
        entry = {"sender": self.agent.agent_id, "recipient": self.recipient_id}
        if result.decision in PROPAGATING_DECISIONS:
            shared.append({**entry, "body": body, "weight": DECISION_WEIGHT[result.decision]})
            if result.decision == PolicyDecision.DEGRADE:
                transcript.append("  -> entra al contexto con PESO REDUCIDO (0.5)")
        elif result.decision == PolicyDecision.CORROBORATE:
            pending.append({**entry, "body": body})
            transcript.append("  -> RETENIDO por TRUST-MAS: pendiente de corroboracion, no entra al contexto")
        elif result.decision == PolicyDecision.QUARANTINE and result.sanitized is not None and result.sanitized.kept_text:
            shared.append(
                {**entry, "body": result.sanitized.kept_text, "weight": QUARANTINED_DATA_WEIGHT, "quarantined": True}
            )
            transcript.append(
                "  -> CUARENTENA: solo entran los datos extraidos por el modelo aislado "
                f"({len(result.sanitized.removed_instructions)} instruccion(es) eliminada(s))"
            )
        else:
            transcript.append("  -> BLOQUEADO por TRUST-MAS: no entra al contexto compartido")

        return {
            "shared_context": shared,
            "transcript": transcript,
            "routing_log": routing_log,
            "pending_corroboration": pending,
            "round": state["round"] + 1,
        }


def _names(nodes: Sequence[AgentNode], prefix: str = "") -> list[str]:
    return [f"{prefix}node_{i}_{node.agent.agent_id}" for i, node in enumerate(nodes)]


def build_linear_graph(nodes: list[AgentNode]):
    """Encadena los nodos en secuencia: START -> nodes[0] -> ... -> END."""
    from langgraph.graph import END, START, StateGraph

    graph = StateGraph(GraphState)
    names = _names(nodes)
    for name, node in zip(names, nodes):
        graph.add_node(name, node)
    graph.add_edge(START, names[0])
    for current_name, next_name in zip(names, names[1:]):
        graph.add_edge(current_name, next_name)
    graph.add_edge(names[-1], END)
    return graph.compile()


def build_star_graph(hub: AgentNode, spokes: list[AgentNode], closer: Optional[AgentNode] = None):
    """Estrella: el hub habla primero, los radios responden en paralelo y
    (opcionalmente) un nodo de cierre sintetiza cuando terminaron todos."""
    from langgraph.graph import END, START, StateGraph

    graph = StateGraph(GraphState)
    graph.add_node("hub", hub)
    spoke_names = _names(spokes, "spoke_")
    for name, node in zip(spoke_names, spokes):
        graph.add_node(name, node)
    graph.add_edge(START, "hub")
    for name in spoke_names:
        graph.add_edge("hub", name)
    if closer is not None:
        graph.add_node("closer", closer)
        graph.add_edge(spoke_names, "closer")
        graph.add_edge("closer", END)
    else:
        graph.add_edge(spoke_names, END)
    return graph.compile()


def build_hierarchical_graph(
    root: AgentNode, teams: list[tuple[AgentNode, list[AgentNode]]], closer: Optional[AgentNode] = None
):
    """Jerarquía: raíz -> líderes (en paralelo) -> trabajadores de cada líder
    (en paralelo) -> cierre opcional cuando terminaron todos."""
    from langgraph.graph import END, START, StateGraph

    graph = StateGraph(GraphState)
    graph.add_node("root", root)
    graph.add_edge(START, "root")
    leaves: list[str] = []
    for t, (lead, workers) in enumerate(teams):
        lead_name = f"lead_{t}_{lead.agent.agent_id}"
        graph.add_node(lead_name, lead)
        graph.add_edge("root", lead_name)
        worker_names = _names(workers, f"team{t}_")
        for name, node in zip(worker_names, workers):
            graph.add_node(name, node)
            graph.add_edge(lead_name, name)
        leaves.extend(worker_names or [lead_name])
    if closer is not None:
        graph.add_node("closer", closer)
        graph.add_edge(leaves, "closer")
        graph.add_edge("closer", END)
    else:
        graph.add_edge(leaves, END)
    return graph.compile()


def build_mesh_graph(nodes: list[AgentNode], rounds: int = 2):
    """Malla: en cada ronda todos los nodos actúan en paralelo viendo el
    contexto acumulado de la ronda anterior (todos ven a todos)."""
    from langgraph.graph import END, START, StateGraph

    if rounds < 1:
        raise ValueError("la malla necesita al menos una ronda")
    graph = StateGraph(GraphState)
    previous: Optional[list[str]] = None
    for r in range(rounds):
        names = _names(nodes, f"r{r}_")
        for name, node in zip(names, nodes):
            graph.add_node(name, node)
            if previous is None:
                graph.add_edge(START, name)
            else:
                graph.add_edge(previous, name)
        previous = names
    graph.add_edge(previous, END)
    return graph.compile()


def build_graph(topology: str, nodes: list[AgentNode], rounds: int = 2):
    """Atajo por nombre, con una convención sobre el orden de `nodes`:

    - lineal: en orden.
    - estrella: nodes[0] es el hub; el último es el nodo de cierre si hay >= 3.
    - jerarquica: nodes[0] raíz, nodes[1:3] líderes, el resto se reparte entre
      ellos alternando; el último es el cierre si sobran >= 2 trabajadores.
    - malla: todos, `rounds` rondas.
    """
    if topology == "lineal":
        return build_linear_graph(nodes)
    if topology == "estrella":
        if len(nodes) < 2:
            raise ValueError("la estrella necesita un hub y al menos un radio")
        closer = nodes[-1] if len(nodes) >= 3 else None
        spokes = nodes[1:-1] if closer is not None else nodes[1:]
        return build_star_graph(nodes[0], spokes, closer)
    if topology == "jerarquica":
        if len(nodes) < 3:
            raise ValueError("la jerarquia necesita raiz y dos lideres")
        rest = list(nodes[3:])
        closer = rest.pop() if len(rest) >= 3 else None
        teams = [(nodes[1], rest[0::2]), (nodes[2], rest[1::2])]
        return build_hierarchical_graph(nodes[0], teams, closer)
    if topology == "malla":
        return build_mesh_graph(nodes, rounds=rounds)
    raise ValueError(f"topologia desconocida: {topology!r} (opciones: {TOPOLOGIES})")


def initial_state() -> GraphState:
    return GraphState(shared_context=[], transcript=[], routing_log=[], pending_corroboration=[], round=0)
