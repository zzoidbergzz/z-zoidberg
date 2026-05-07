def normalize_euvd_entry(entry: dict) -> dict:
    return {
        "id": entry.get("id"),
        "description": entry.get("description"),
        "severity": entry.get("severity"),
        "published": entry.get("publishedDate"),
        "modified": entry.get("modifiedDate"),
    }
