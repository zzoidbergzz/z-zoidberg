def normalize_sdo(node: dict) -> dict:
    return {
        "opencti_id": node.get("id"),
        "entity_type": node.get("entity_type"),
        "name": node.get("name", ""),
        "description": node.get("description", ""),
    }
