"""Register all 31 MITRE ATT&CK tools into the MCP registry."""

from __future__ import annotations

from app.mcp.registry import register_tool
from app.services import mitre_attack

# Each entry: (tool_name, required_args, defaults, schema_properties, description)
_MITRE_DEFS: list[tuple] = [
    (
        "get_object_by_attack_id",
        ["attack_id"],
        {"domain": "enterprise"},
        {"attack_id": {"type": "string"}, "domain": {"type": "string"}},
        "Get a MITRE ATT&CK object by ATT&CK ID",
    ),
    (
        "get_object_by_stix_id",
        ["stix_id"],
        {"domain": "enterprise"},
        {"stix_id": {"type": "string"}, "domain": {"type": "string"}},
        "Get a MITRE ATT&CK object by STIX ID",
    ),
    (
        "get_objects_by_name",
        ["name"],
        {"domain": "enterprise"},
        {"name": {"type": "string"}, "domain": {"type": "string"}},
        "Get MITRE ATT&CK objects matching a name",
    ),
    (
        "get_objects_by_content",
        ["content"],
        {"domain": "enterprise"},
        {"content": {"type": "string"}, "domain": {"type": "string"}},
        "Search MITRE ATT&CK objects by content",
    ),
    (
        "get_techniques_used_by_group",
        ["group_id"],
        {"domain": "enterprise"},
        {"group_id": {"type": "string"}, "domain": {"type": "string"}},
        "Get techniques used by a threat group",
    ),
    (
        "get_software_used_by_group",
        ["group_id"],
        {"domain": "enterprise"},
        {"group_id": {"type": "string"}, "domain": {"type": "string"}},
        "Get software used by a threat group",
    ),
    (
        "get_campaigns_attributed_to_group",
        ["group_id"],
        {"domain": "enterprise"},
        {"group_id": {"type": "string"}, "domain": {"type": "string"}},
        "Get campaigns attributed to a threat group",
    ),
    (
        "get_groups_using_technique",
        ["technique_id"],
        {"domain": "enterprise"},
        {"technique_id": {"type": "string"}, "domain": {"type": "string"}},
        "Get groups that use a given technique",
    ),
    (
        "get_groups_using_software",
        ["software_id"],
        {"domain": "enterprise"},
        {"software_id": {"type": "string"}, "domain": {"type": "string"}},
        "Get groups that use a given software",
    ),
    (
        "get_techniques_used_by_software",
        ["software_id"],
        {"domain": "enterprise"},
        {"software_id": {"type": "string"}, "domain": {"type": "string"}},
        "Get techniques used by a software",
    ),
    (
        "get_all_techniques",
        [],
        {"domain": "enterprise", "include_description": False},
        {"domain": {"type": "string"}, "include_description": {"type": "boolean"}},
        "Get all MITRE ATT&CK techniques",
    ),
    (
        "get_all_subtechniques",
        [],
        {"domain": "enterprise", "include_description": False},
        {"domain": {"type": "string"}, "include_description": {"type": "boolean"}},
        "Get all MITRE ATT&CK sub-techniques",
    ),
    (
        "get_all_groups",
        [],
        {"domain": "enterprise", "include_description": False},
        {"domain": {"type": "string"}, "include_description": {"type": "boolean"}},
        "Get all MITRE ATT&CK groups",
    ),
    (
        "get_all_software",
        [],
        {"domain": "enterprise", "include_description": False},
        {"domain": {"type": "string"}, "include_description": {"type": "boolean"}},
        "Get all MITRE ATT&CK software",
    ),
    (
        "get_all_mitigations",
        [],
        {"domain": "enterprise", "include_description": False},
        {"domain": {"type": "string"}, "include_description": {"type": "boolean"}},
        "Get all MITRE ATT&CK mitigations",
    ),
    (
        "get_all_tactics",
        [],
        {"domain": "enterprise"},
        {"domain": {"type": "string"}},
        "Get all MITRE ATT&CK tactics",
    ),
    (
        "get_all_campaigns",
        [],
        {"domain": "enterprise", "include_description": False},
        {"domain": {"type": "string"}, "include_description": {"type": "boolean"}},
        "Get all MITRE ATT&CK campaigns",
    ),
    (
        "get_subtechniques_of_technique",
        ["technique_id"],
        {"domain": "enterprise"},
        {"technique_id": {"type": "string"}, "domain": {"type": "string"}},
        "Get sub-techniques of a technique",
    ),
    (
        "get_parent_technique_of_subtechnique",
        ["subtechnique_id"],
        {"domain": "enterprise"},
        {"subtechnique_id": {"type": "string"}, "domain": {"type": "string"}},
        "Get parent technique of a sub-technique",
    ),
    (
        "get_techniques_by_tactic",
        ["tactic"],
        {"domain": "enterprise", "include_description": False},
        {
            "tactic": {"type": "string"},
            "domain": {"type": "string"},
            "include_description": {"type": "boolean"},
        },
        "Get techniques associated with a tactic",
    ),
    (
        "get_techniques_by_platform",
        ["platform"],
        {"domain": "enterprise", "include_description": False},
        {
            "platform": {"type": "string"},
            "domain": {"type": "string"},
            "include_description": {"type": "boolean"},
        },
        "Get techniques targeting a platform",
    ),
    (
        "get_mitigations_mitigating_technique",
        ["technique_id"],
        {"domain": "enterprise"},
        {"technique_id": {"type": "string"}, "domain": {"type": "string"}},
        "Get mitigations that address a technique",
    ),
    (
        "get_datacomponents_detecting_technique",
        ["technique_id"],
        {"domain": "enterprise"},
        {"technique_id": {"type": "string"}, "domain": {"type": "string"}},
        "Get data components that detect a technique",
    ),
    (
        "get_procedure_examples_by_technique",
        ["technique_id"],
        {"domain": "enterprise"},
        {"technique_id": {"type": "string"}, "domain": {"type": "string"}},
        "Get procedure examples for a technique",
    ),
    (
        "get_techniques_used_by_campaign",
        ["campaign_id"],
        {"domain": "enterprise"},
        {"campaign_id": {"type": "string"}, "domain": {"type": "string"}},
        "Get techniques used in a campaign",
    ),
    (
        "get_campaigns_using_technique",
        ["technique_id"],
        {"domain": "enterprise"},
        {"technique_id": {"type": "string"}, "domain": {"type": "string"}},
        "Get campaigns that use a technique",
    ),
    (
        "get_techniques_mitigated_by_mitigation",
        ["mitigation_id"],
        {"domain": "enterprise"},
        {"mitigation_id": {"type": "string"}, "domain": {"type": "string"}},
        "Get techniques mitigated by a mitigation",
    ),
    (
        "get_objects_created_after",
        ["date"],
        {"domain": "enterprise"},
        {"date": {"type": "string"}, "domain": {"type": "string"}},
        "Get MITRE ATT&CK objects created after a date",
    ),
    (
        "get_objects_modified_after",
        ["date"],
        {"domain": "enterprise"},
        {"date": {"type": "string"}, "domain": {"type": "string"}},
        "Get MITRE ATT&CK objects modified after a date",
    ),
    (
        "get_revoked_techniques",
        [],
        {"domain": "enterprise"},
        {"domain": {"type": "string"}},
        "Get all revoked MITRE ATT&CK techniques",
    ),
    (
        "get_groups_by_alias",
        ["alias"],
        {"domain": "enterprise"},
        {"alias": {"type": "string"}, "domain": {"type": "string"}},
        "Get groups by alias",
    ),
    (
        "get_software_by_alias",
        ["alias"],
        {"domain": "enterprise"},
        {"alias": {"type": "string"}, "domain": {"type": "string"}},
        "Get software by alias",
    ),
]


def _make_mitre_fn(fn, required_args: list[str], defaults: dict):
    """Wrap a MITRE function into the standard MCP tool signature."""

    async def _tool(args: dict, db, auth) -> dict:
        kwargs = {**defaults, **args}
        for req in required_args:
            if req not in kwargs:
                return {"error": {"code": "missing_arg", "message": f"Missing required arg: {req}"}}
        result = await fn(**kwargs)
        return {"result": result}

    return _tool


def _register_all() -> None:
    for tool_name, required_args, defaults, schema_props, description in _MITRE_DEFS:
        fn = getattr(mitre_attack, tool_name)
        wrapped = _make_mitre_fn(fn, required_args, defaults)
        register_tool(
            name=tool_name,
            fn=wrapped,
            schema={"type": "object", "properties": schema_props},
            description=description,
            scope="read",
        )


_register_all()
