from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from app.auth.dependencies import AuthContext, Scope, get_auth, require_scope
from app.services import mitre_attack

router = APIRouter(prefix="/mcp", tags=["MCP"])

require_read = require_scope(Scope.read)


class ToolCall(BaseModel):
    tool: str
    args: dict = {}


# (function, required_positional_args, default_kwargs)
MITRE_TOOLS: dict[str, tuple] = {
    "get_object_by_attack_id": (mitre_attack.get_object_by_attack_id, ["attack_id"], {"domain": "enterprise"}),
    "get_object_by_stix_id": (mitre_attack.get_object_by_stix_id, ["stix_id"], {"domain": "enterprise"}),
    "get_objects_by_name": (mitre_attack.get_objects_by_name, ["name"], {"domain": "enterprise"}),
    "get_objects_by_content": (mitre_attack.get_objects_by_content, ["content"], {"domain": "enterprise"}),
    "get_techniques_used_by_group": (mitre_attack.get_techniques_used_by_group, ["group_id"], {"domain": "enterprise"}),
    "get_software_used_by_group": (mitre_attack.get_software_used_by_group, ["group_id"], {"domain": "enterprise"}),
    "get_campaigns_attributed_to_group": (mitre_attack.get_campaigns_attributed_to_group, ["group_id"], {"domain": "enterprise"}),
    "get_groups_using_technique": (mitre_attack.get_groups_using_technique, ["technique_id"], {"domain": "enterprise"}),
    "get_groups_using_software": (mitre_attack.get_groups_using_software, ["software_id"], {"domain": "enterprise"}),
    "get_techniques_used_by_software": (mitre_attack.get_techniques_used_by_software, ["software_id"], {"domain": "enterprise"}),
    "get_all_techniques": (mitre_attack.get_all_techniques, [], {"domain": "enterprise", "include_description": False}),
    "get_all_subtechniques": (mitre_attack.get_all_subtechniques, [], {"domain": "enterprise", "include_description": False}),
    "get_all_groups": (mitre_attack.get_all_groups, [], {"domain": "enterprise", "include_description": False}),
    "get_all_software": (mitre_attack.get_all_software, [], {"domain": "enterprise", "include_description": False}),
    "get_all_mitigations": (mitre_attack.get_all_mitigations, [], {"domain": "enterprise", "include_description": False}),
    "get_all_tactics": (mitre_attack.get_all_tactics, [], {"domain": "enterprise"}),
    "get_all_campaigns": (mitre_attack.get_all_campaigns, [], {"domain": "enterprise", "include_description": False}),
    "get_subtechniques_of_technique": (mitre_attack.get_subtechniques_of_technique, ["technique_id"], {"domain": "enterprise"}),
    "get_parent_technique_of_subtechnique": (mitre_attack.get_parent_technique_of_subtechnique, ["subtechnique_id"], {"domain": "enterprise"}),
    "get_techniques_by_tactic": (mitre_attack.get_techniques_by_tactic, ["tactic"], {"domain": "enterprise", "include_description": False}),
    "get_techniques_by_platform": (mitre_attack.get_techniques_by_platform, ["platform"], {"domain": "enterprise", "include_description": False}),
    "get_mitigations_mitigating_technique": (mitre_attack.get_mitigations_mitigating_technique, ["technique_id"], {"domain": "enterprise"}),
    "get_datacomponents_detecting_technique": (mitre_attack.get_datacomponents_detecting_technique, ["technique_id"], {"domain": "enterprise"}),
    "get_procedure_examples_by_technique": (mitre_attack.get_procedure_examples_by_technique, ["technique_id"], {"domain": "enterprise"}),
    "get_techniques_used_by_campaign": (mitre_attack.get_techniques_used_by_campaign, ["campaign_id"], {"domain": "enterprise"}),
    "get_campaigns_using_technique": (mitre_attack.get_campaigns_using_technique, ["technique_id"], {"domain": "enterprise"}),
    "get_techniques_mitigated_by_mitigation": (mitre_attack.get_techniques_mitigated_by_mitigation, ["mitigation_id"], {"domain": "enterprise"}),
    "get_objects_created_after": (mitre_attack.get_objects_created_after, ["date"], {"domain": "enterprise"}),
    "get_objects_modified_after": (mitre_attack.get_objects_modified_after, ["date"], {"domain": "enterprise"}),
    "get_revoked_techniques": (mitre_attack.get_revoked_techniques, [], {"domain": "enterprise"}),
    "get_groups_by_alias": (mitre_attack.get_groups_by_alias, ["alias"], {"domain": "enterprise"}),
    "get_software_by_alias": (mitre_attack.get_software_by_alias, ["alias"], {"domain": "enterprise"}),
}

MITRE_TOOL_SCHEMAS = {
    "get_object_by_attack_id": {"attack_id": "string", "domain": "string"},
    "get_object_by_stix_id": {"stix_id": "string", "domain": "string"},
    "get_objects_by_name": {"name": "string", "domain": "string"},
    "get_objects_by_content": {"content": "string", "domain": "string"},
    "get_techniques_used_by_group": {"group_id": "string", "domain": "string"},
    "get_software_used_by_group": {"group_id": "string", "domain": "string"},
    "get_campaigns_attributed_to_group": {"group_id": "string", "domain": "string"},
    "get_groups_using_technique": {"technique_id": "string", "domain": "string"},
    "get_groups_using_software": {"software_id": "string", "domain": "string"},
    "get_techniques_used_by_software": {"software_id": "string", "domain": "string"},
    "get_all_techniques": {"domain": "string", "include_description": "boolean"},
    "get_all_subtechniques": {"domain": "string", "include_description": "boolean"},
    "get_all_groups": {"domain": "string", "include_description": "boolean"},
    "get_all_software": {"domain": "string", "include_description": "boolean"},
    "get_all_mitigations": {"domain": "string", "include_description": "boolean"},
    "get_all_tactics": {"domain": "string"},
    "get_all_campaigns": {"domain": "string", "include_description": "boolean"},
    "get_subtechniques_of_technique": {"technique_id": "string", "domain": "string"},
    "get_parent_technique_of_subtechnique": {"subtechnique_id": "string", "domain": "string"},
    "get_techniques_by_tactic": {"tactic": "string", "domain": "string", "include_description": "boolean"},
    "get_techniques_by_platform": {"platform": "string", "domain": "string", "include_description": "boolean"},
    "get_mitigations_mitigating_technique": {"technique_id": "string", "domain": "string"},
    "get_datacomponents_detecting_technique": {"technique_id": "string", "domain": "string"},
    "get_procedure_examples_by_technique": {"technique_id": "string", "domain": "string"},
    "get_techniques_used_by_campaign": {"campaign_id": "string", "domain": "string"},
    "get_campaigns_using_technique": {"technique_id": "string", "domain": "string"},
    "get_techniques_mitigated_by_mitigation": {"mitigation_id": "string", "domain": "string"},
    "get_objects_created_after": {"date": "string", "domain": "string"},
    "get_objects_modified_after": {"date": "string", "domain": "string"},
    "get_revoked_techniques": {"domain": "string"},
    "get_groups_by_alias": {"alias": "string", "domain": "string"},
    "get_software_by_alias": {"alias": "string", "domain": "string"},
}


@router.post("/call")
async def call_tool(body: ToolCall, auth: AuthContext = Depends(get_auth)):
    auth.require_scope(Scope.read)

    if body.tool == "enrich_entity":
        from app.mcp.tools.enrich_entity import EnrichEntityInput, enrich_entity_tool
        inp = EnrichEntityInput(tenant_id=str(auth.tenant_id), **body.args)
        result = await enrich_entity_tool(inp)
        return result.model_dump()

    if body.tool in MITRE_TOOLS:
        fn, required_args, defaults = MITRE_TOOLS[body.tool]
        kwargs = {**defaults, **body.args}
        for req in required_args:
            if req not in kwargs:
                raise HTTPException(status_code=422, detail=f"Missing required arg: {req}")
        result = await fn(**kwargs)
        return {"result": result}

    return {"error": f"Unknown tool: {body.tool}"}


@router.get("/tools")
async def list_tools(auth: AuthContext = Depends(get_auth)):
    auth.require_scope(Scope.read)
    mitre_tool_list = [
        {"name": name, "parameters": schema}
        for name, schema in MITRE_TOOL_SCHEMAS.items()
    ]
    return {
        "tools": ["enrich_entity"] + [t["name"] for t in mitre_tool_list],
        "tool_schemas": [
            {"name": "enrich_entity", "parameters": {"entity_kind": "string", "entity_value": "string", "tenant_id": "string"}},
            *mitre_tool_list,
        ],
    }
