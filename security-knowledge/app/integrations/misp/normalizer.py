def normalize_misp_event(event: dict) -> dict:
    return {
        "misp_id": event.get("id"),
        "info": event.get("info"),
        "date": event.get("date"),
        "attributes": event.get("attributes", []),
    }
