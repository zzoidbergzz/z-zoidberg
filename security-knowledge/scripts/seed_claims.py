#!/usr/bin/env python3
"""Seed threat intel claims and evidence via the local API."""
import json
import urllib.request

API = "http://localhost:8010"
KEY = "YxjXShQyv8L_-X_1Qb6DDSF9JvPXGer5_yTztqgvCAQ"

def mcp_call(tool, args):
    data = json.dumps({"tool": tool, "args": args}).encode()
    req = urllib.request.Request(f"{API}/api/v1/mcp/call", data=data, headers={
        "X-API-Key": KEY, "Content-Type": "application/json"
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())

def get_entities():
    req = urllib.request.Request(f"{API}/api/v1/entities/?limit=200", headers={"X-API-Key": KEY})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())

# Build entity lookup
entities = {e["canonical_name"]: e["id"] for e in get_entities()}
print(f"Found {len(entities)} entities")

# Claims data: entity_name -> list of claims
CLAIMS = {
    "Shadow Brokers": [
        {"type": "attribution", "value": {"text": "Mysterious group that leaked NSA Equation Group tools in 2016-2017. Released EternalBlue, EternalRomance, DoublePulsar and other Windows SMB exploits. Identity never confirmed.", "country": "Unknown"}, "confidence": 0.7, "source": "The Shadow Brokers GitHub releases, Kaspersky analysis"},
        {"type": "technique", "value": {"text": "Obtained NSA Equation Group tools likely through insider access or compromise of NSA operations server. Auctioned additional tools for 10,000 BTC.", "method": "Insider/Supply Chain"}, "confidence": 0.6, "source": "NSA TAO operations analysis"},
        {"type": "relationship", "value": {"text": "EternalBlue leak directly enabled WannaCry and NotPetya attacks", "related_entity": "EternalBlue", "relationship": "leaked_tool"}, "confidence": 1.0, "source": "Public reporting"},
    ],
    "Lazarus Group": [
        {"type": "attribution", "value": {"text": "North Korean state-sponsored group. Operates under RGB (Reconnaissance General Bureau). Responsible for Bangladesh Bank SWIFT heist, WannaCry, Sony Pictures hack.", "country": "DPRK", "affiliation": "RGB"}, "confidence": 0.95, "source": "US Treasury OFAC, FBI, UK NCSC"},
        {"type": "technique", "value": {"text": "Used fraudulent SWIFT messages to attempt $951M transfer from Bangladesh Bank. Successfully moved $81M through Philippines casinos via Rizal Commercial Banking Corporation.", "method": "SWIFT compromise, Money laundering"}, "confidence": 0.95, "source": "BAE Systems, FireEye, Bangladesh Bank investigation"},
        {"type": "technique", "value": {"text": "WannaCry ransomware used EternalBlue (from Shadow Brokers leak) for self-propagation. Kill switch domain iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com registered by Marcus Hutchins halted spread.", "method": "Self-propagating ransomware, SMB exploit"}, "confidence": 0.9, "source": "US Treasury, UK NCSC joint attribution"},
        {"type": "financial", "value": {"text": "Stole $1.7B+ in cryptocurrency through exchange hacks 2017-2023. Major heists: Coincheck ($534M), Bithumb ($250M), KuCoin ($281M), Ronin Bridge ($625M).", "total_estimated": "$1.7B+"}, "confidence": 0.85, "source": "Chainalysis, UN Panel of Experts reports"},
    ],
    "APT29": [
        {"type": "attribution", "value": {"text": "Russian SVR-linked APT. Responsible for SolarWinds supply chain compromise, DNC hack (2016), COVID-19 vaccine research targeting.", "country": "Russia", "affiliation": "SVR"}, "confidence": 0.95, "source": "US Treasury, FireEye, Microsoft attribution"},
        {"type": "technique", "value": {"text": "SolarWinds attack: compromised build system, inserted SUNBURST backdoor into Orion 2019.4-2020.2.1 updates. 18,000+ orgs received trojanized updates. Dormant 9+ months before C2 activation.", "method": "Supply chain compromise, Living off the land"}, "confidence": 0.95, "source": "SolarWinds advisory, Microsoft, FireEye SUNBURST analysis"},
    ],
    "APT28": [
        {"type": "attribution", "value": {"text": "Russian GRU Unit 26165. Responsible for DNC hack, NotPetya contribution, Olympic Destroyer, Fancy Bear phishing campaigns. Multiple indictments by US DOJ.", "country": "Russia", "affiliation": "GRU Unit 26165"}, "confidence": 0.95, "source": "US DOJ indictments, Mueller Report"},
        {"type": "technique", "value": {"text": "NotPetya: destructive wiper disguised as ransomware. Used EternalBlue and EternalRomance for lateral movement. Overwrote MBR making recovery impossible. $10B+ damages globally.", "method": "Wiper, SMB lateral movement"}, "confidence": 0.95, "source": "US Treasury, UK NCSC, White House statement"},
    ],
    "DarkSide": [
        {"type": "attribution", "value": {"text": "Ransomware-as-a-service operation. Colonial Pipeline attack forced 6-day shutdown of US East Coast fuel supply. Operated affiliate model taking 25% cut.", "country": "Eastern Europe", "model": "RaaS"}, "confidence": 0.85, "source": "FBI, Colonial Pipeline SEC filing"},
        {"type": "financial", "value": {"text": "Colonial Pipeline paid $4.4M ransom (77.7 BTC). FBI recovered 63.7 BTC (~$2.3M at time). Total DarkSide operations estimated $90M+ in ransom payments before shutdown.", "ransom_paid": "$4.4M"}, "confidence": 0.9, "source": "Colonial Pipeline CEO testimony, FBI"},
    ],
    "EternalBlue": [
        {"type": "vulnerability", "value": {"text": "NSA-developed SMB exploit targeting MS17-010. Buffer overflow in SMBv1 _NET_SESSION_SETUP_ANDX parsing. Reliable RCE on unpatched Windows 7/Server 2008. CVSS 9.8. Patches available since March 2017.", "cve": "CVE-2017-0144", "cvss": 9.8, "affected": "Windows SMBv1"}, "confidence": 1.0, "source": "MSRC, Shadow Brokers dump"},
    ],
    "Mimikatz": [
        {"type": "capability", "value": {"text": "Extracts plaintext passwords, NTLM hashes, Kerberos tickets from LSASS memory. Supports pass-the-hash, pass-the-ticket, golden ticket, silver ticket attacks. Written by Benjamin Delpy. Core tool in nearly every Windows post-exploitation chain.", "author": "Benjamin Delpy", "language": "C", "features": ["sekurlsa", "kerberos", "crypto", "privilege"]}, "confidence": 1.0, "source": "gentilkiwi/mimikatz GitHub"},
    ],
}

# Create claims and evidence
for entity_name, claims in CLAIMS.items():
    eid = entities.get(entity_name)
    if not eid:
        print(f"  SKIP: {entity_name} not found")
        continue
    for c in claims:
        try:
            result = mcp_call("create_claim", {
                "entity_id": eid,
                "claim_type": c["type"],
                "value": c["value"],
                "confidence": c.get("confidence", 1.0),
            })
            # Add evidence
            if "source" in c:
                claim_id = result.get("id", result.get("claim_id"))
                if claim_id:
                    try:
                        mcp_call("create_evidence", {
                            "claim_id": claim_id,
                            "title": f"Source: {c['source']}",
                            "content": c["value"].get("text", ""),
                            "source_url": "",
                        })
                    except:
                        pass
            print(f"  + {entity_name}: {c['type']} claim")
        except Exception as e:
            print(f"  FAIL {entity_name}: {e}")

# Verify
print("\n=== Verification ===")
for name in ["Shadow Brokers", "Lazarus Group", "EternalBlue", "Mimikatz"]:
    eid = entities.get(name)
    if not eid:
        continue
    result = mcp_call("get_entity", {"entity_id": eid})
    claims_count = len(result.get("claims", []))
    print(f"  {name}: {claims_count} claims")
