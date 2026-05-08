def normalize_advisory(node: dict) -> dict:
    return {
        "ghsa_id": node.get("ghsaId"),
        "severity": node.get("severity"),
        "summary": node.get("summary"),
        "description": node.get("description"),
        "published_at": node.get("publishedAt"),
        "updated_at": node.get("updatedAt"),
        "identifiers": node.get("identifiers", []),
        "packages": [
            {
                "name": v["package"]["name"],
                "ecosystem": v["package"]["ecosystem"],
                "vulnerable_range": v.get("vulnerableVersionRange"),
                "patched_version": (v.get("firstPatchedVersion") or {}).get("identifier"),
            }
            for v in node.get("vulnerabilities", {}).get("nodes", [])
        ],
    }
