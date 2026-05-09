#!/usr/bin/env python3
"""Ingest ThreatIntelReport.com articles into Security Knowledge DB.

Fetches all posts from sitemap, extracts content, creates entities + claims.
Enriches against existing knowledge (links to known actors, CVEs, techniques).
"""
import psycopg, uuid, json, re, urllib.request, html
from xml.etree import ElementTree

TENANT = uuid.UUID('bcc8ab78-0982-4ea3-81d3-7e4bd166881a')
conn = psycopg.connect('postgresql://sk:sk@localhost:5433/sk', autocommit=True)
conn.execute('SET app.bypass = true')

def upsert(kind, name, refs=None, mitre_id=None):
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM entities WHERE canonical_name=%s AND tenant_id=%s", (name, TENANT))
        r = cur.fetchone()
        if r:
            if refs:
                cur.execute("UPDATE entities SET external_refs=COALESCE(external_refs,'{}')||%s, updated_at=NOW() WHERE id=%s", (json.dumps(refs), r[0]))
            return r[0]
        eid = uuid.uuid4()
        cur.execute("INSERT INTO entities (id,tenant_id,kind,canonical_name,mitre_attack_id,external_refs,created_at,updated_at) VALUES(%s,%s,%s,%s,%s,%s,NOW(),NOW())", (eid,TENANT,kind,name,mitre_id,json.dumps(refs or {})))
        return eid

def add_claim(eid, ctype, val, conf=0.9):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO claims (id,entity_id,tenant_id,claim_type,value,confidence,status,created_at,updated_at) VALUES(%s,%s,%s,%s,%s,%s,'approved',NOW(),NOW()) ON CONFLICT DO NOTHING", (uuid.uuid4(),eid,TENANT,ctype,json.dumps(val),conf))

def add_rel(f, t, k, c=1.0):
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM relationships WHERE from_entity_id=%s AND to_entity_id=%s AND kind=%s AND tenant_id=%s", (f,t,k,TENANT))
        if cur.fetchone(): return
        cur.execute("INSERT INTO relationships (id,tenant_id,from_entity_id,to_entity_id,kind,confidence) VALUES(%s,%s,%s,%s,%s,%s)", (uuid.uuid4(),TENANT,f,t,k,c))

def fetch(url, timeout=15):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "zoidberg/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode(errors='replace')
    except Exception as e:
        print(f"  FETCH {url}: {e}")
        return None

def extract_article(html_text):
    """Extract title, date, categories, tags, and content from WP article."""
    title = ""
    date = ""
    categories = []
    tags = []
    content = ""

    # Title
    m = re.search(r'<title>(.*?)</title>', html_text)
    if m: title = html.unescape(m.group(1)).split(' - ')[0].strip()

    # Date
    m = re.search(r'<time[^>]*datetime="([^"]*)"', html_text)
    if m: date = m.group(1)[:10]
    m2 = re.search(r'datePublished["\s:]+["\']?(\d{4}-\d{2}-\d{2})', html_text)
    if m2 and not date: date = m2.group(1)

    # Categories
    cats = re.findall(r'class="[^"]*category-[^"]*"[^>]*>(.*?)</a>', html_text)
    categories = [html.unescape(c.strip()) for c in cats if c.strip()]

    # Tags
    tag_matches = re.findall(r'class="[^"]*tag-[^"]*"[^>]*>(.*?)</a>', html_text)
    tags = [html.unescape(t.strip()) for t in tag_matches if t.strip()]
    # Also try rel=tag
    tag_matches2 = re.findall(r'rel="tag"[^>]*>(.*?)</a>', html_text)
    tags.extend(html.unescape(t.strip()) for t in tag_matches2 if t.strip())

    # Content - try article body
    m = re.search(r'<article[^>]*>(.*?)</article>', html_text, re.DOTALL)
    if m:
        raw = m.group(1)
    else:
        m = re.search(r'class="entry-content[^"]*"[^>]*>(.*?)</div>', html_text, re.DOTALL)
        raw = m.group(1) if m else ""

    # Strip HTML
    content = re.sub(r'<script[^>]*>.*?</script>', '', raw, flags=re.DOTALL)
    content = re.sub(r'<style[^>]*>.*?</style>', '', content, flags=re.DOTALL)
    content = re.sub(r'<[^>]+>', ' ', content)
    content = html.unescape(content)
    content = re.sub(r'\s+', ' ', content).strip()

    return title, date, categories, tags, content

def classify_article(title, categories, tags, content):
    """Determine entity kind and extract IOCs from article."""
    kind = "report"
    combined = f"{title} {' '.join(categories)} {' '.join(tags)}".lower()

    if any(x in combined for x in ["threat actor", "apt", "threat group", "fin7", "apt28", "apt29", "lazarus"]):
        kind = "threat_actor"
    elif any(x in combined for x in ["malware", "ransomware", "trojan", "backdoor", "rat ", "loader", "stealer"]):
        kind = "malware"
    elif any(x in combined for x in ["vulnerability", "cve-", "zero-day", "patch"]):
        kind = "vulnerability"
    elif any(x in combined for x in ["tool", "framework", "cobalt strike", "metasploit"]):
        kind = "tool"

    # Extract CVEs
    cves = re.findall(r'CVE-\d{4}-\d{4,7}', content, re.IGNORECASE)
    # Extract MITRE techniques
    techniques = re.findall(r'\b(T\d{4}(?:\.\d{3})?)\b', content)
    # Extract SHA256
    hashes = re.findall(r'\b[a-fA-F0-9]{64}\b', content)
    # Extract IPs
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
    # Extract domains
    domains = re.findall(r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?\b', content)

    return kind, cves, techniques, hashes, ips, domains

# Load existing entity names for cross-referencing
with conn.cursor() as cur:
    cur.execute("SELECT canonical_name, id, kind FROM entities WHERE tenant_id=%s", (TENANT,))
    entity_map = {r[0].lower(): r[1] for r in cur.fetchall()}

# Get all article URLs from sitemap
print("Fetching sitemap...")
sitemap_xml = fetch("https://www.threatintelreport.com/sitemap-posttype-post.xml")
if not sitemap_xml:
    print("Failed to fetch sitemap")
    sys.exit(1)

urls = re.findall(r'<loc>(.*?)</loc>', sitemap_xml)
print(f"Found {len(urls)} articles")

count = 0
for url in urls:
    html_text = fetch(url)
    if not html_text:
        continue

    title, date, categories, tags, content = extract_article(html_text)
    if not title or len(content) < 100:
        continue

    kind, cves, techniques, hashes, ips, domains = classify_article(title, categories, tags, content)

    # Truncate content for storage
    content_stored = content[:3000]

    eid = upsert(kind, f"TIR: {title}", refs={
        "url": url, "date": date,
        "categories": categories, "tags": tags[:20],
        "source": "ThreatIntelReport", "trust_tier": 2,
        "cves_mentioned": cves[:10],
        "techniques_mentioned": techniques[:10],
    })

    add_claim(eid, "report_detail", {
        "assertion": f"ThreatIntelReport: {title}. {content_stored[:500]}",
        "full_content": content_stored,
        "date": date, "categories": categories, "tags": tags[:20],
        "cves": cves, "techniques": techniques,
        "hashes": hashes[:5], "ips": ips[:5], "domains": domains[:5],
        "tags_search": ["threatintelreport"] + tags[:5] + categories[:3],
    }, conf=0.85)

    # Cross-reference: link to existing CVE entities
    for cve_id in cves:
        cve_key = cve_id.lower()
        if cve_key in entity_map:
            add_rel(eid, entity_map[cve_key], "mentions", 0.85)
        else:
            cve_eid = upsert("cve", cve_id, refs={"source": "ThreatIntelReport", "trust_tier": 2})
            add_rel(eid, cve_eid, "mentions", 0.85)
            entity_map[cve_id.lower()] = cve_eid

    # Cross-reference: link to existing technique entities
    for tech_id in techniques:
        tech_key = tech_id.lower()
        # Find technique by MITRE ID
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM entities WHERE mitre_attack_id=%s AND tenant_id=%s LIMIT 1", (tech_id, TENANT))
            r = cur.fetchone()
            if r:
                add_rel(eid, r[0], "references_technique", 0.85)

    # Cross-reference: link to known threat actors/malware mentioned in title/tags
    for tag in tags[:10]:
        tag_lower = tag.lower()
        if tag_lower in entity_map:
            add_rel(eid, entity_map[tag_lower], "references", 0.8)

    count += 1
    if count % 20 == 0:
        print(f"  ... {count}/{len(urls)}")

    # Be polite
    import time
    time.sleep(0.5)

conn.close()
print(f"\n✅ Ingested {count} ThreatIntelReport articles")
