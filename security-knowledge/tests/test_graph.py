import pytest
from unittest.mock import MagicMock
from app.graph.palette import ENTITY_COLORS, DEFAULT_COLOR
from app.graph.formats import to_vis_js, to_cytoscape
from app.models.entities import EntityKind
import uuid


def make_entity(kind, name):
    e = MagicMock()
    e.id = uuid.uuid4()
    e.name = name
    e.canonical_name = name
    e.kind = kind
    return e


def make_rel(source_id, target_id, kind="uses"):
    r = MagicMock()
    r.id = uuid.uuid4()
    r.source_id = source_id
    r.target_id = target_id
    r.kind = kind
    return r


def test_entity_colors_keys():
    assert "cve" in ENTITY_COLORS
    assert "malware" in ENTITY_COLORS
    assert "actor" in ENTITY_COLORS


def test_to_vis_js_empty():
    result = to_vis_js([], [])
    assert result == {"nodes": [], "edges": []}


def test_to_vis_js_entities():
    e1 = make_entity(EntityKind.cve, "CVE-2024-1")
    e2 = make_entity(EntityKind.malware, "AgentTesla")
    r = make_rel(e1.id, e2.id)
    result = to_vis_js([e1, e2], [r])
    assert len(result["nodes"]) == 2
    assert len(result["edges"]) == 1


def test_to_cytoscape():
    e = make_entity(EntityKind.actor, "APT28")
    result = to_cytoscape([e], [])
    assert len(result) == 1
    assert result[0]["data"]["label"] == "APT28"
