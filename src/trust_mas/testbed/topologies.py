"""Las 4 topologías del diseño factorial.

Una topología fija quién puede escribirle a quién (aristas dirigidas), el
orden en que actúan los agentes dentro de una ronda y qué nodo toma la
decisión colectiva. Las aristas declaradas también alimentan al detector de
anomalías de grafo de la Capa C ("aristas fuera de la topología").
"""

from __future__ import annotations

from dataclasses import dataclass

HONEST_IDS = ("orchestrator", "analista", "critico", "verificador", "sintetizador")
TOPOLOGIES = ("lineal", "estrella", "malla", "jerarquica")


@dataclass(frozen=True)
class Topology:
    name: str
    order: tuple[str, ...]
    edges: frozenset[tuple[str, str]]
    decision_node: str

    def out_neighbors(self, agent_id: str) -> list[str]:
        return [r for (s, r) in sorted(self.edges) if s == agent_id]

    @property
    def agents(self) -> tuple[str, ...]:
        return self.order


def _both_ways(pairs: list[tuple[str, str]]) -> set[tuple[str, str]]:
    return {edge for a, b in pairs for edge in ((a, b), (b, a))}


def build_topology(name: str, malicious_ids: tuple[str, ...] = ()) -> Topology:
    """Construye la topología con los agentes honestos fijos y los infiltrados
    insertados en posiciones de trabajador (nunca como nodo de decisión)."""
    mal = list(malicious_ids)
    orch, analista, critico, verificador, sintetizador = HONEST_IDS

    if name == "lineal":
        # Cadena: el infiltrado queda en medio, como un eslabón más del pipeline.
        chain = [orch, analista]
        if mal:
            chain.append(mal[0])
        chain.append(critico)
        if len(mal) > 1:
            chain.append(mal[1])
        chain += [verificador, sintetizador]
        chain += mal[2:]
        edges = {(a, b) for a, b in zip(chain, chain[1:])}
        return Topology(name, tuple(chain), frozenset(edges), sintetizador)

    if name == "estrella":
        spokes = [analista, critico, verificador, sintetizador, *mal]
        edges = _both_ways([(orch, s) for s in spokes])
        return Topology(name, tuple(spokes + [orch]), frozenset(edges), orch)

    if name == "malla":
        agents = [orch, analista, critico, *mal, verificador, sintetizador]
        edges = {(a, b) for a in agents for b in agents if a != b}
        return Topology(name, tuple(agents), frozenset(edges), sintetizador)

    if name == "jerarquica":
        # orquestador -> 2 lideres -> trabajadores; los infiltrados son trabajadores.
        team_critico = [analista] + mal[0:1] + mal[2::2]
        team_verificador = [sintetizador] + mal[1:2] + mal[3::2]
        pairs = [(orch, critico), (orch, verificador)]
        pairs += [(critico, w) for w in team_critico]
        pairs += [(verificador, w) for w in team_verificador]
        order = team_critico + team_verificador + [critico, verificador, orch]
        return Topology(name, tuple(order), frozenset(_both_ways(pairs)), orch)

    raise ValueError(f"topologia desconocida: {name!r} (opciones: {TOPOLOGIES})")
