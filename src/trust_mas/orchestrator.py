"""Orquestador real sobre LangGraph.

Conecta agentes respaldados por un LLM de verdad (por defecto Gemini) en un
grafo de estados de LangGraph. La diferencia con `demo.py` (agentes
simulados con texto fijo) es que aqui el contenido de cada mensaje lo genera
un modelo real -- pero cada arista del grafo sigue obligada a pasar por
`MessageBus.route()` (Capas A -> B -> C) antes de que el contenido llegue al
siguiente nodo. Un mensaje bloqueado (QUARANTINE/REJECT) nunca se agrega al
contexto compartido: el "historial compartido" que la diapositiva 3 senala
como vector de propagacion en AutoGen/LangGraph queda saneado por el bus.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable, Optional, Protocol, TypedDict

from .agent import SimulatedAgent
from .bus import MessageBus
from .identity import NonceStore
from .models import AgentRole, PolicyDecision, ProvenanceSource, ProvenanceTag
from .provenance import tag_provenance

# Decisiones de la Capa C que dejan pasar el contenido al contexto compartido.
# CORROBORATE/QUARANTINE/REJECT bloquean la propagacion, aunque el modelo
# real ya haya generado el texto.
PROPAGATING_DECISIONS = (PolicyDecision.ACCEPT, PolicyDecision.DEGRADE)


class ChatModel(Protocol):
    """Duck type minimo compatible con los chat models de LangChain
    (`ChatGoogleGenerativeAI`, etc.) y con dobles de prueba: basta con
    exponer `.invoke(prompt) -> objeto con atributo .content`.
    """

    def invoke(self, prompt: str):  # pragma: no cover - protocolo
        ...


class GraphState(TypedDict):
    shared_context: list[dict]
    transcript: list[str]
    routing_log: list[dict]
    round: int


def _conversation_digest(state: GraphState) -> str:
    basis = f"round={state['round']}|len={len(state['shared_context'])}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def _render_context(state: GraphState) -> str:
    if not state["shared_context"]:
        return "(sin mensajes previos)"
    lines = [f"{turn['sender']} -> {turn['recipient']}: {turn['body']}" for turn in state["shared_context"]]
    return "\n".join(lines)


@dataclass
class AgentNode:
    """Un nodo del grafo: agente real (LLM) + capas de defensa TRUST-MAS.

    `provenance_source`/`provenance_trusted` dejan simular tanto un agente
    par legitimo (AGENT, confiable) como contenido inyectado via documento
    externo o salida de herramienta (EXTERNAL_DOC/TOOL_OUTPUT, no confiable
    por defecto), sin tocar la Capa B misma.
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

    def __call__(self, state: GraphState) -> GraphState:
        prompt = f"{self.system_prompt}\n\nContexto de la conversacion hasta ahora:\n{_render_context(state)}\n\nTu respuesta:"
        response = self.llm.invoke(prompt)
        body = getattr(response, "content", str(response))

        provenance = tag_provenance(
            self.provenance_source, self.agent.agent_id, trusted=self.provenance_trusted
        )
        message = self.agent.compose(
            recipient_id=self.recipient_id,
            body=body,
            conversation_digest=_conversation_digest(state),
            declared_role=self.declared_role,
            action=self.action,
            provenance=provenance,
        )

        result = self.bus.route(message)

        transcript = list(state["transcript"])
        transcript.append(
            f"[{self.agent.agent_id} -> {self.recipient_id}] DECISION={result.decision.value} "
            f"score={result.score:.2f} umbral={result.threshold:.2f}\n  \"{body}\""
        )

        routing_log = list(state["routing_log"])
        routing_log.append(
            {
                "sender": self.agent.agent_id,
                "recipient": self.recipient_id,
                "decision": result.decision.value,
                "score": result.score,
                "threshold": result.threshold,
                "reasons": result.reasons,
            }
        )

        shared_context = list(state["shared_context"])
        if result.decision in PROPAGATING_DECISIONS:
            shared_context.append({"sender": self.agent.agent_id, "recipient": self.recipient_id, "body": body})
        else:
            transcript.append(f"  -> BLOQUEADO por TRUST-MAS: no entra al contexto compartido")

        return {
            "shared_context": shared_context,
            "transcript": transcript,
            "routing_log": routing_log,
            "round": state["round"] + 1,
        }


def build_linear_graph(nodes: list[AgentNode]):
    """Encadena los nodos en secuencia: START -> nodes[0] -> ... -> END.

    Una topologia lineal es la mas simple de las 4 mencionadas en el diseno
    factorial de la propuesta (linea base sobre la que se pueden montar
    estrella, malla y jerarquica reutilizando el mismo `AgentNode`).
    """
    from langgraph.graph import END, StateGraph

    graph = StateGraph(GraphState)
    names = [f"node_{i}_{node.agent.agent_id}" for i, node in enumerate(nodes)]
    for name, node in zip(names, nodes):
        graph.add_node(name, node)

    graph.set_entry_point(names[0])
    for current_name, next_name in zip(names, names[1:]):
        graph.add_edge(current_name, next_name)
    graph.add_edge(names[-1], END)

    return graph.compile()


def initial_state() -> GraphState:
    return GraphState(shared_context=[], transcript=[], routing_log=[], round=0)
