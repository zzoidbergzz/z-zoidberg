from __future__ import annotations
import networkx as nx

def build_graph(relationships: list[dict]) -> nx.Graph:
    graph = nx.Graph()
    for rel in relationships:
        graph.add_edge(rel["source_entity"], rel["target_entity"],
                      relation=rel["relation_type"], confidence=rel.get("confidence", 1.0))
    return graph

def shortest_path(relationships: list[dict], source: str, target: str) -> list[str]:
    graph = build_graph(relationships)
    try:
        return nx.shortest_path(graph, source, target)
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []

def connected_clusters(relationships: list[dict]) -> list[list[str]]:
    graph = build_graph(relationships)
    components = [list(c) for c in nx.connected_components(graph)]
    components.sort(key=len, reverse=True)
    return components
