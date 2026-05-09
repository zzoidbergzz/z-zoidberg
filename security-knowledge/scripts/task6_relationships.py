#!/usr/bin/env python3
"""Task 6: Cross-link relationships, search vectors, and gap analysis"""
import psycopg, uuid, json

TENANT = uuid.UUID('bcc8ab78-0982-4ea3-81d3-7e4bd166881a')
conn = psycopg.connect('postgresql://sk:sk@localhost:5433/sk', autocommit=True)
conn.execute('SET app.bypass = true')

# ── Build cross-entity relationships ────────────────────────────
print("\n=== Building Cross-Entity Relationships ===")

with conn.cursor() as cur:
    cur.execute("SELECT id, kind, canonical_name, mitre_attack_id, external_refs FROM entities WHERE tenant_id = %s", (TENANT,))
    entities = cur.fetchall()

# Build lookups
by_mitre = {}
by_name = {}
by_kind = {}
for eid, kind, name, mid, refs in entities:
    if mid: by_mitre.setdefault(mid, []).append(eid)
    by_name[name] = eid
    by_kind.setdefault(kind, []).append(eid)

print(f"  {len(entities)} entities, {len(by_mitre)} MITRE IDs, {len(by_kind)} kinds")

rc = 0
with conn.cursor() as cur:
    # 1. ATT&CK techniques ↔ MITRE mitigations
    print("  Linking techniques ↔ mitigations...")
    techniques = [e for e in entities if e[1] == "attack_pattern"]
    mitigations = [e for e in entities if e[1] == "course_of_action"]
    for tech in techniques[:200]:
        tech_mid = tech[3]
        if not tech_mid: continue
        # Mitigations that reference this technique
        for mit in mitigations[:200]:
            mit_refs = mit[4] or {}
            if isinstance(mit_refs, str): mit_refs = json.loads(mit_refs) if mit_refs else {}
            # Check if mitigation mentions this technique
            if tech_mid in str(mit_refs) or tech_mid in (mit[2] or ""):
                try:
                    cur.execute("SELECT 1 FROM relationships WHERE from_entity_id=%s AND to_entity_id=%s AND kind=%s AND tenant_id=%s",
                               (tech[0], mit[0], "mitigated_by", TENANT))
                    if not cur.fetchone():
                        cur.execute("INSERT INTO relationships (id,tenant_id,from_entity_id,to_entity_id,kind,confidence) VALUES(%s,%s,%s,%s,%s,%s)",
                                   (uuid.uuid4(), TENANT, tech[0], mit[0], "mitigated_by", 0.9))
                        rc += 1
                except: pass

    # 2. CVEs → CWEs (already done in NVD phase)
    # 3. Detection rules → techniques via attack_ids
    print("  Linking detections ↔ techniques...")
    detections = [e for e in entities if e[1] == "detection"]
    for det in detections[:500]:
        det_refs = det[4] or {}
        if isinstance(det_refs, str): det_refs = json.loads(det_refs) if det_refs else {}
        attack_ids = det_refs.get("attack_ids", [])
        for aid in attack_ids:
            # Find technique with this MITRE ID
            tech_eids = by_mitre.get(aid, [])
            for teid in tech_eids:
                try:
                    cur.execute("SELECT 1 FROM relationships WHERE from_entity_id=%s AND to_entity_id=%s AND kind=%s AND tenant_id=%s",
                               (det[0], teid, "detects", TENANT))
                    if not cur.fetchone():
                        cur.execute("INSERT INTO relationships (id,tenant_id,from_entity_id,to_entity_id,kind,confidence) VALUES(%s,%s,%s,%s,%s,%s)",
                                   (uuid.uuid4(), TENANT, det[0], teid, "detects", 0.9))
                        rc += 1
                except: pass

    # 4. Threat actors → techniques they use (via attack_ids in tool claims)
    print("  Linking actors ↔ techniques via shared MITRE IDs...")
    actors = [e for e in entities if e[1] == "threat_actor"]
    for actor in actors[:200]:
        actor_mid = actor[3]
        if not actor_mid: continue
        # Techniques with same MITRE ID
        for tech_eid in by_mitre.get(actor_mid, []):
            try:
                cur.execute("SELECT 1 FROM relationships WHERE from_entity_id=%s AND to_entity_id=%s AND kind=%s AND tenant_id=%s",
                           (actor[0], tech_eid, "uses_technique", TENANT))
                if not cur.fetchone():
                    cur.execute("INSERT INTO relationships (id,tenant_id,from_entity_id,to_entity_id,kind,confidence) VALUES(%s,%s,%s,%s,%s,%s)",
                               (uuid.uuid4(), TENANT, actor[0], tech_eid, "uses_technique", 0.85))
                    rc += 1
            except: pass

print(f"  New relationships: {rc}")

# ── Update search vectors ────────────────────────────────────────
print("\n=== Updating Search Vectors ===")
with conn.cursor() as cur:
    cur.execute("UPDATE entities SET search_vector = to_tsvector('english', COALESCE(canonical_name,'') || ' ' || COALESCE(mitre_attack_id,'') || ' ' || COALESCE(kind,'')) WHERE search_vector IS NULL OR updated_at > created_at")
    print(f"  Entity vectors: {cur.rowcount}")
    cur.execute("UPDATE claims SET search_vector = to_tsvector('english', COALESCE(value::text,'')) WHERE search_vector IS NULL")
    print(f"  Claim vectors: {cur.rowcount}")

# ── Gap Analysis ─────────────────────────────────────────────────
print("\n=== Gap Analysis ===")
with conn.cursor() as cur:
    # Techniques without detection rules
    cur.execute("""
        SELECT count(*) FROM entities e
        WHERE e.kind='attack_pattern' AND e.tenant_id=%s
        AND NOT EXISTS (SELECT 1 FROM relationships r WHERE r.to_entity_id=e.id AND r.kind='detects')
    """, (TENANT,))
    no_detect = cur.fetchone()[0]

    # CVEs without EPSS
    cur.execute("""
        SELECT count(*) FROM entities e
        WHERE e.kind='cve' AND e.tenant_id=%s
        AND NOT EXISTS (SELECT 1 FROM claims c WHERE c.entity_id=e.id AND c.value::text LIKE '%epss%')
    """, (TENANT,))
    no_epss = cur.fetchone()[0]

    # CVEs without NVD enrichment
    cur.execute("""
        SELECT count(*) FROM entities e
        WHERE e.kind='cve' AND e.tenant_id=%s
        AND NOT EXISTS (SELECT 1 FROM claims c WHERE c.entity_id=e.id AND c.value::text LIKE '%cvss_v31%')
    """, (TENANT,))
    no_nvd = cur.fetchone()[0]

    # Total counts
    cur.execute("SELECT kind, count(*) FROM entities WHERE tenant_id=%s GROUP BY kind ORDER BY count DESC LIMIT 20", (TENANT,))
    kind_stats = cur.fetchall()

print(f"  Techniques without detection: {no_detect}")
print(f"  CVEs without EPSS: {no_epss}")
print(f"  CVEs without NVD enrichment: {no_nvd}")
print(f"  Entity kind breakdown:")
for kind, c in kind_stats:
    print(f"    {kind}: {c}")

conn.close()
print(f"\n✅ Task 6 complete")
