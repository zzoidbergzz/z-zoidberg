from app.models.entities import Entity
from app.models.relationships import Relationship
from app.graph.palette import ENTITY_COLORS, DEFAULT_COLOR


def _entity_name(e) -> str:
    return getattr(e, "name", None) or getattr(e, "canonical_name", "?")


def to_vis_js(entities: list, relationships: list) -> dict:
    nodes = [
        {
            "id": str(e.id),
            "label": _entity_name(e),
            "group": e.kind.value if hasattr(e.kind, "value") else str(e.kind),
            "color": ENTITY_COLORS.get(
                e.kind.value if hasattr(e.kind, "value") else str(e.kind), DEFAULT_COLOR
            ),
        }
        for e in entities
    ]
    edges = [
        {
            "id": str(r.id),
            "from": str(r.from_entity_id),
            "to": str(r.to_entity_id),
            "label": r.kind,
        }
        for r in relationships
    ]
    return {"nodes": nodes, "edges": edges}


def to_cytoscape(entities: list, relationships: list) -> list[dict]:
    elements = []
    for e in entities:
        elements.append({
            "data": {
                "id": str(e.id),
                "label": _entity_name(e),
                "kind": e.kind.value if hasattr(e.kind, "value") else str(e.kind),
            }
        })
    for r in relationships:
        elements.append({
            "data": {"id": str(r.id), "source": str(r.from_entity_id), "target": str(r.to_entity_id), "label": r.kind}
        })
    return elements
