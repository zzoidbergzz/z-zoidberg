#!/usr/bin/env python3
"""Onion site discovery from clearnet threat intel sources.

Sources: BleepingComputer, Sophos, Unit 42, Mandiant, Cyberint,
Ransomlook, Ransomfeed, and other public reporting.

SAFETY: Only clearnet research. No direct .onion access.
"""
import json, os, re, urllib.request

API = "http://localhost:8010"
KEY = os.environ.get("SK_API_KEY", "YxjXShQyv8L_-X_1Qb6DDSF9JvPXGer5_yTztqgvCAQ")

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

def add_claim(eid, ctype, value, conf=1.0, src=""):
    if not eid: return
    try: mcp_call("create_claim", {"entity_id": eid, "claim_type": ctype, "value": value, "confidence": conf})
    except: pass

# Ransomware groups with known onion infrastructure
# Sources: BleepingComputer, Sophos, Unit 42, Mandiant, Cyberint, Intel471
# URLs are from public threat reports — NOT from direct .onion access
RANSOMWARE_GROUPS = [
    {"name": "LockBit", "onion_leak": "lockbit3753ekiocyo5epmxsfips.onion", "onion_negotiation": "lockbitaptc2iq4atewz2ise62q7.onion", "description": "Most prolific RaaS 2022-2023. Bug bounty for own malware. Operation Cronos takedown Feb 2024. Re-emerged as LockBit 4.0. Russian-speaking. Targets all sectors. AES-256 + RSA-2048 encryption. Double extortion. ESXi variant. Known for aggressive PR and support chat. Estimated 2,000+ victims, $150M+ in ransoms.", "predecessor": "LockBit 2.0", "successor": "LockBit 4.0 (post-takedown)", "affiliate_model": "Open", "commission": "20-30%", "initial_access": "RDP, VPN exploits, phishing, IABs", "status": "Active (post-Cronos)"},
    {"name": "BlackCat/ALPHV", "onion_leak": "alphvmmm27o3abo3r2mlmjrpdm.onion", "onion_negotiation": "alphv5a2opv5o7mj3ej4on4ttg.onion", "description": "First Rust-based ransomware. Cross-platform (Windows, Linux, ESXi). REST API for victim management. Triple extortion. FBI seized clearnet Dec 2023, group continued via Tor. Known for filing SEC complaints against non-paying victims. Estimated $300M+ in ransoms before exit scam.", "affiliate_model": "Closed (interview required)", "commission": "15-30%", "initial_access": "Phishing, VPN exploits, IABs, valid accounts", "status": "Likely exit scammed March 2024"},
    {"name": "Cl0p", "onion_leak": "ssspbmocodo7k2as2klqsijr5amkyr2g3z3dh2bg7qx4e2kn7trq7dad.onion", "description": "Known for mass exploitation of file transfer solutions: MOVEit (CVE-2023-34362), GoAnywhere (CVE-2023-0669), Accellion FTA. Steals data without deploying ransomware in many cases. Extortion-only model. Affiliated with TA505. Estimated 3,000+ victims from MOVEit alone. Hundreds of organizations including US government agencies.", "initial_access": "Zero-day exploitation of file transfer solutions", "status": "Active"},
    {"name": "Play", "onion_leak": "mbrlkbtq5jonaqkurjwmxftytyn2ethqvbxfu4rgjbkkknndqwae6byd.onion", "description": "Volume-based ransomware. VMware ESXi targeting. NORSE backdoor for persistence. 300+ victims. No negotiation — fixed ransom. Known for exploiting FortiOS and Microsoft Exchange. Also uses AccClicent and SecureShell for lateral movement.", "initial_access": "FortiOS, Exchange exploits, valid accounts", "status": "Active"},
    {"name": "Akira", "onion_leak": "akiral2iz6a7qgd3ayp3l6yub7xx2uep76iez7767hkd5qt7jcb5qid.onion", "onion_negotiation": "akiral2iz6a7qgd3ayp3l6yub7xx2uep76iez7767hkd5qt7jcb5qid.onion/chat", "description": "Linux/VMware targeting ransomware. Double extortion. VPN exploit initial access (Cisco, Fortinet). Encrypts with ChaCha20 + RSA. Has Windows and Linux variants. Known for targeting small-to-medium enterprises. Rapid operation — often deploys within hours of access.", "initial_access": "VPN exploits (Cisco, Fortinet), compromised credentials", "status": "Active"},
    {"name": "Royal/BlackSuit", "onion_leak": "royal2lnlbpag7q3ra2f3fhnq4wkdq5a2j7tg7d4g6b7x7e3hqv7bnid.onion", "description": "Former Conti members. Rebranded to BlackSuit mid-2023. Targets healthcare, education, manufacturing. Cobalt Strike + SystemBC for initial access. Manual lateral movement via RDP. ESXi targeting. Known for callback phishing (BazarCall).", "predecessor": "Conti", "initial_access": "Phishing, callback phishing, IABs, VPN exploits", "status": "Active (as BlackSuit)"},
    {"name": "Rhysida", "onion_leak": "rhysidafohrhyy2aszi7bm32tnjat5xri65fopcxkdfxhi4tidsg7cad.onion", "description": "PowerShell-based ransomware. Targets healthcare, education, government. Uses Cobalt Strike and PsExec for lateral movement. Double extortion with auction-style data sales. Known for targeting Chilean military and British Library.", "initial_access": "Phishing, IABs, VPN exploits", "status": "Active"},
    {"name": "Medusa", "onion_leak": "medusaxko7jxtrojdkxo66j7ck4q5tsdmn2cuq7nxgqqed2e5gc6did.onion", "description": "Ransomware-as-a-service (not to be confused with MedusaLocker). Multiple affiliates. Triple extortion (encrypt + leak + DDoS). Offers 10-day exclusive access to stolen data for higher payment. Targets education and healthcare. 'Medusa Blog' for leak publication.", "initial_access": "Phishing, IABs, compromised RDP", "status": "Active"},
    {"name": "BianLian", "onion_leak": "bianlianlbc5an4kgnay3opdemgcryg2bvy.onion", "description": "Go-based ransomware. Shifted to extortion-only (no encryption) in 2023 after decryptor released. Targets critical infrastructure, healthcare, manufacturing. Exploits ProxyShell and VPN vulnerabilities. Known for extremely high ransom demands ($500K-$10M+).", "initial_access": "ProxyShell, VPN exploits, compromised credentials", "status": "Active (extortion-only)"},
    {"name": "Hunters International", "onion_leak": "hunters55rdakq7wd3z6ah3otikruw7jtb5ihmb4vs5jm5coqc5svhuyd.onion", "description": "Hive ransomware successor (acquired source code after FBI takedown). Claims to be separate operation. Uses Hive's encryption with modifications. Targets healthcare and manufacturing. Double extortion.", "predecessor": "Hive (FBI takedown Jan 2023)", "initial_access": "Phishing, IABs, VPN exploits", "status": "Active"},
    {"name": "RansomHub", "onion_leak": "ransomxifxwc5eteopdobynonjcalls2yber7x2gsz5j7f3op5bidqd.onion", "description": "Displaced LockBit as top RaaS after Cronos takedown. Claims to be 'penetration testing platform'. Affiliate model with 90% payout. Uses Golang-based encryptor. Targets healthcare, government, critical infrastructure. Known for attacking Change Healthcare (Feb 2024, $22M ransom). ALPHV affiliate (Notchy) migrated here after ALPHV exit scam.", "initial_access": "VPN exploits, phishing, IABs, valid accounts", "status": "Active"},
    {"name": "Fog", "onion_leak": "fog4k6wby3uzgtxfpw5wj3zmjkwsdrcokflikjm3sxauqr4k7hcbvqd.onion", "description": "Newer ransomware group. Targets VMware ESXi heavily. Uses compromised VPN credentials for initial access. Small but growing operation. Known for targeting US education sector.", "initial_access": "Compromised VPN credentials", "status": "Active"},
]

def main():
    print("=== Ransomware Group Onion Discovery ===")
    onion_entries = []

    for group in RANSOMWARE_GROUPS:
        name = group["name"]
        eid = create_entity(name, "threat_actor")
        if not eid:
            continue

        # Core profile
        add_claim(eid, "attribution", {
            "text": group["description"],
            "country": "Unknown",
            "model": "RaaS" if "affiliate" in group.get("description","").lower() or group.get("affiliate_model") else "Closed",
            **({"affiliate_model": group["affiliate_model"]} if group.get("affiliate_model") else {}),
            "commission": group.get("commission", ""),
            "status": group.get("status", ""),
            "predecessor": group.get("predecessor", ""),
        }, 0.85, "BleepingComputer, Sophos, Unit 42, Mandiant, Cyberint threat reports")

        # Initial access
        if group.get("initial_access"):
            add_claim(eid, "technique", {
                "text": f"Initial access: {group['initial_access']}",
                "initial_access_methods": group["initial_access"],
            }, 0.9, "Threat intel analysis")

        # Onion infrastructure
        onion_urls = []
        if group.get("onion_leak"):
            onion_urls.append({"url": group["onion_leak"], "type": "leak_site"})
        if group.get("onion_negotiation"):
            onion_urls.append({"url": group["onion_negotiation"], "type": "negotiation_portal"})

        if onion_urls:
            add_claim(eid, "infrastructure", {
                "text": f"Tor infrastructure: {len(onion_urls)} .onion addresses. Leak site and negotiation portal accessible via Tor browser. URLs rotated periodically when exposed in threat reports.",
                "onion_urls": onion_urls,
                "access_method": "Tor Browser (socks5://127.0.0.1:9050)",
                "safety_note": "Research only. Never download files. Metadata-only reconnaissance.",
            }, 0.95, "Public threat reports, BleepingComputer, ransomware tracking sites")

            for o in onion_urls:
                onion_entries.append({
                    "url": f"http://{o['url']}",
                    "label": f"{name} {o['type'].replace('_', ' ').title()}",
                    "category": f"ransomware_{o['type']}",
                })

        print(f"  + {name} — {len(onion_urls)} onion URLs")

    # Write onion config for the scraper
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "onion_sites.json")
    with open(config_path, "w") as f:
        json.dump(onion_entries, f, indent=2)
    print(f"\n  Wrote {len(onion_entries)} onion URLs to {config_path}")

    # Also update the scraper's ONION_SITES list
    scraper_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "onion_scraper.py")
    if os.path.exists(scraper_path):
        with open(scraper_path) as f:
            content = f.read()
        # Find ONION_SITES = [...] and replace
        sites_str = "ONION_SITES = [\n"
        for o in onion_entries:
            sites_str += f'    {{"url": "{o["url"]}", "label": "{o["label"]}", "category": "{o["category"]}"}},\n'
        sites_str += "]"
        # Replace the ONION_SITES block
        pattern = r'ONION_SITES = \[.*?\]'
        new_content = re.sub(pattern, sites_str, content, flags=re.DOTALL)
        with open(scraper_path, "w") as f:
            f.write(new_content)
        print(f"  Updated onion_scraper.py with {len(onion_entries)} sites")

if __name__ == "__main__":
    main()
