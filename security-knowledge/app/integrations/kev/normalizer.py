def normalize_kev_entry(entry: dict) -> dict:
    ransomware_str = entry.get("knownRansomwareCampaignUse", "Unknown")
    return {
        "cve_id": entry.get("cveID"),
        "vendor": entry.get("vendorProject"),
        "product": entry.get("product"),
        "name": entry.get("vulnerabilityName"),
        "date_added": entry.get("dateAdded"),
        "short_description": entry.get("shortDescription"),
        "action": entry.get("requiredAction"),
        "due_date": entry.get("dueDate"),
        "ransomware": ransomware_str.lower() not in ("unknown", "no", ""),
        "known_ransomware": ransomware_str,
    }
