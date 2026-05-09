#!/usr/bin/env python3
"""Import YARA rules from signature-base and other repos into SK DB."""
import json, os, re, urllib.request

API = "http://localhost:8010"
KEY = os.environ.get("SK_API_KEY", "YxjXShQyv8L_-X_1Qb6DDSF9JvPXGer5_yTztqgvCAQ")

YARA_DIRS = [
    "/home/openclaw/.openclaw/workspace/repos/signature-base/yara",
]

def mcp_call(tool, args, timeout=30):
    data = json.dumps({"tool": tool, "args": args}).encode()
    req = urllib.request.Request(f"{API}/api/v1/mcp/call", data=data, headers={"X-API-Key": KEY, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())

def create_entity(name, kind):
    try:
        r = mcp_call("create_entity", {"name": name, "kind": kind})
        return r.get("id")
    except:
        return None

def add_claim(eid, ctype, value, conf=1.0):
    if not eid: return
    try: mcp_call("create_claim", {"entity_id": eid, "claim_type": ctype, "value": value, "confidence": conf})
    except: pass

def parse_yara(filepath):
    """Parse a YARA file and extract rule metadata."""
    with open(filepath, 'r', errors='replace') as f:
        content = f.read()

    rules = []
    # Simple rule parser - extract rule name, tags, and metadata
    rule_pattern = re.compile(
        r'(?:import\s+"[^"]+"\s*)*'
        r'(?:include\s+"[^"]+"\s*)*'
        r'rule\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        r'(?:\s*:\s*([a-zA-Z0-9_\s]+))?'
        r'\s*\{',
        re.MULTILINE
    )

    for m in rule_pattern.finditer(content):
        rule_name = m.group(1)
        tags = m.group(2).split() if m.group(2) else []

        # Extract metadata from within the rule
        rule_start = m.end()
        # Find the matching closing brace
        brace_count = 1
        pos = rule_start
        while pos < len(content) and brace_count > 0:
            if content[pos] == '{': brace_count += 1
            elif content[pos] == '}': brace_count -= 1
            pos += 1
        rule_body = content[rule_start:pos-1]

        # Parse meta section
        meta = {}
        meta_match = re.search(r'meta\s*:(.*?)(?=strings|condition|\Z)', rule_body, re.DOTALL)
        if meta_match:
            for line in meta_match.group(1).strip().split('\n'):
                line = line.strip()
                kv = re.match(r'(\w+)\s*=\s*"([^"]*)"', line)
                if kv:
                    meta[kv.group(1)] = kv.group(2)
                else:
                    kv = re.match(r'(\w+)\s*=\s*(\S+)', line)
                    if kv:
                        meta[kv.group(1)] = kv.group(2)

        # Compute a simple hash of the rule for dedup
        rule_text = content[m.start():pos]
        import hashlib
        rule_hash = hashlib.sha256(rule_text.encode()).hexdigest()[:16]

        rules.append({
            "name": rule_name,
            "tags": tags,
            "meta": meta,
            "hash": rule_hash,
            "source_file": os.path.basename(filepath),
            "description": meta.get("description", meta.get("desc", "")),
            "author": meta.get("author", ""),
            "reference": meta.get("reference", meta.get("ref", "")),
            "date": meta.get("date", ""),
        })

    return rules

def main():
    print("=== YARA Rule Import ===")
    total_rules = 0
    imported = 0

    for yara_dir in YARA_DIRS:
        if not os.path.exists(yara_dir):
            print(f"  SKIP: {yara_dir} not found")
            continue

        for root, dirs, files in os.walk(yara_dir):
            for fname in files:
                if not fname.endswith(('.yar', '.yara')):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    rules = parse_yara(fpath)
                except Exception as e:
                    print(f"  ERROR parsing {fname}: {e}")
                    continue

                total_rules += len(rules)

                for rule in rules:
                    eid = create_entity(f"YARA:{rule['name']}", "yara_rule")
                    if not eid:
                        continue

                    add_claim(eid, "capability", {
                        "text": f"YARA rule: {rule['name']}. {rule['description']}. Tags: {', '.join(rule['tags'])}. Author: {rule['author']}.",
                        "rule_name": rule["name"],
                        "tags": rule["tags"],
                        "canonical_rule_hash": rule["hash"],
                        "source_file": rule["source_file"],
                    }, 1.0)

                    if rule.get("reference"):
                        add_claim(eid, "evidence", {
                            "text": f"Reference: {rule['reference']}",
                            "links": [rule["reference"]],
                        }, 1.0)

                    if rule["tags"]:
                        # Map tags to threat actors/families
                        for tag in rule["tags"][:3]:
                            tag_lower = tag.lower()
                            if any(x in tag_lower for x in ['apt', 'threat', 'actor']):
                                add_claim(eid, "relationship", {
                                    "text": f"YARA rule targets threat actor/family: {tag}",
                                    "related_entity": tag,
                                    "relationship": "targets",
                                }, 0.7)

                    imported += 1

        print(f"  {yara_dir}: {total_rules} rules found, {imported} imported")

    print(f"\nTotal: {total_rules} YARA rules found, {imported} imported")

if __name__ == "__main__":
    main()
