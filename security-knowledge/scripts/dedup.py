#!/usr/bin/env python3
"""Deduplicate and consolidate entities. Merge duplicates, consolidate tags, fix kinds."""
import psycopg, uuid, json
from collections import defaultdict

TENANT = uuid.UUID('bcc8ab78-0982-4ea3-81d3-7e4bd166881a')
conn = psycopg.connect('postgresql://sk:sk@localhost:5433/sk', autocommit=True)
conn.execute('SET app.bypass = true')

# Find entities with same MITRE ATT&CK ID (dedup key)
with conn.cursor() as cur:
    cur.execute("""
        SELECT mitre_attack_id, array_agg(id), array_agg(canonical_name), array_agg(kind), count(*)
        FROM entities
        WHERE mitre_attack_id IS NOT NULL AND mitre_attack_id != '' AND tenant_id = %s
        GROUP BY mitre_attack_id
        HAVING count(*) > 1
        ORDER BY count(*) DESC
    """, (TENANT,))
    dupes = cur.fetchall()

print(f"Duplicate MITRE IDs: {len(dupes)}")

merged_count = 0
for mitre_id, eids, names, kinds, cnt in dupes:
    # Keep the entity with the "best" kind (threat_actor > actor > attack_pattern > other)
    kind_priority = {"threat_actor": 1, "actor": 2, "attack_pattern": 3, "malware": 4, "tool": 5, "other": 99}
    
    # Sort by kind priority, then by number of claims (most complete first)
    best_idx = 0
    best_pri = 999
    for i, k in enumerate(kinds):
        pri = kind_priority.get(k, 50)
        if pri < best_pri:
            best_pri = pri
            best_idx = i
    
    keep_id = eids[best_idx]
    remove_ids = [eid for i, eid in enumerate(eids) if i != best_idx]
    keep_name = names[best_idx]
    
    # Collect all aliases
    all_names = list(set(names))
    aliases = [n for n in all_names if n != keep_name]
    
    # Update the keeper with merged aliases
    with conn.cursor() as cur:
        cur.execute("UPDATE entities SET external_refs = COALESCE(external_refs, '{}') || %s WHERE id = %s",
                   (json.dumps({"aliases": aliases, "also_known_as": aliases}), keep_id))
    
    # For each duplicate, re-point claims and relationships to the keeper, then delete
    for old_id in remove_ids:
        with conn.cursor() as cur:
            # Re-point claims
            cur.execute("UPDATE claims SET entity_id = %s WHERE entity_id = %s", (keep_id, old_id))
            # Re-point relationships
            cur.execute("UPDATE relationships SET from_entity_id = %s WHERE from_entity_id = %s", (keep_id, old_id))
            cur.execute("UPDATE relationships SET to_entity_id = %s WHERE to_entity_id = %s", (keep_id, old_id))
            # Delete the duplicate
            cur.execute("DELETE FROM claims WHERE entity_id = %s", (old_id,))
            cur.execute("DELETE FROM relationships WHERE from_entity_id = %s OR to_entity_id = %s", (old_id, old_id))
            cur.execute("DELETE FROM entities WHERE id = %s", (old_id,))
    
    merged_count += 1

print(f"Merged {merged_count} duplicate groups")

# Also find name-based duplicates (case-insensitive, same kind)
with conn.cursor() as cur:
    cur.execute("""
        SELECT lower(canonical_name), kind, array_agg(id), array_agg(canonical_name), count(*)
        FROM entities
        WHERE tenant_id = %s
        GROUP BY lower(canonical_name), kind
        HAVING count(*) > 1
        ORDER BY count(*) DESC
        LIMIT 100
    """, (TENANT,))
    name_dupes = cur.fetchall()

print(f"Name-based duplicates: {len(name_dupes)}")
name_merged = 0
for lower_name, kind, eids, names, cnt in name_dupes:
    if cnt < 2: continue
    keep_id = eids[0]
    remove_ids = eids[1:]
    aliases = list(set(names[1:]))
    
    with conn.cursor() as cur:
        cur.execute("UPDATE entities SET external_refs = COALESCE(external_refs, '{}') || %s WHERE id = %s",
                   (json.dumps({"aliases": aliases}), keep_id))
    
    for old_id in remove_ids:
        with conn.cursor() as cur:
            cur.execute("UPDATE claims SET entity_id = %s WHERE entity_id = %s", (keep_id, old_id))
            cur.execute("UPDATE relationships SET from_entity_id = %s WHERE from_entity_id = %s", (keep_id, old_id))
            cur.execute("UPDATE relationships SET to_entity_id = %s WHERE to_entity_id = %s", (keep_id, old_id))
            cur.execute("DELETE FROM claims WHERE entity_id = %s", (old_id))
            cur.execute("DELETE FROM relationships WHERE from_entity_id = %s OR to_entity_id = %s", (old_id, old_id))
            cur.execute("DELETE FROM entities WHERE id = %s", (old_id))
    name_merged += 1

print(f"Name-merged: {name_merged}")

# Final stats
with conn.cursor() as cur:
    cur.execute("SELECT count(*) FROM entities WHERE tenant_id = %s", (TENANT,))
    total = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM claims")
    claims = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM relationships WHERE tenant_id = %s", (TENANT,))
    rels = cur.fetchone()[0]
    cur.execute("SELECT count(DISTINCT mitre_attack_id) FROM entities WHERE mitre_attack_id IS NOT NULL AND tenant_id = %s", (TENANT,))
    unique_mitre = cur.fetchone()[0]

print(f"\nAfter dedup: {total} entities, {claims} claims, {rels} relationships, {unique_mitre} unique MITRE IDs")
conn.close()
