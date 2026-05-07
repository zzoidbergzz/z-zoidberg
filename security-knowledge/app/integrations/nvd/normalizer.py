def normalize_cve(vuln: dict) -> dict:
    cve = vuln.get("cve", {})
    descs = cve.get("descriptions", [])
    desc_en = next((d["value"] for d in descs if d.get("lang") == "en"), "")
    metrics = cve.get("metrics", {})
    cvss = {}
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if k in metrics and metrics[k]:
            cvss = metrics[k][0].get("cvssData", {})
            break
    return {
        "cve_id": cve.get("id"),
        "description": desc_en,
        "cvss": cvss,
        "published": cve.get("published"),
        "modified": cve.get("lastModified"),
        "references": [r.get("url") for r in cve.get("references", [])],
        "weaknesses": [w.get("description", [{}])[0].get("value", "") for w in cve.get("weaknesses", [])],
    }
