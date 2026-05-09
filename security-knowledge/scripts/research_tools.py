#!/usr/bin/python3
"""Deep Research: NSA Equation Group leaked tools + exploit encyclopedia."""
import json, os, urllib.request

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

def main():
    print("=== NSA Tools & Exploit Encyclopedia ===")

    tools = [
        {"name": "EternalBlue", "cve": "CVE-2017-0144", "target": "Windows SMBv1 (MS17-010)", "desc": "NSA-developed SMB exploit. Buffer overflow in _NET_SESSION_SETUP_ANDX SMBv1 command. Reliable RCE on unpatched Windows 7/Server 2008. Sends crafted SMB packets triggering pool overflow in srv.sys. Port 445. Works without authentication. Used in WannaCry and NotPetya. CVSS 9.8. Patched March 2017.", "detection": "IDS signature on SMBv1 _NET_SESSION_SETUP_ANDX with oversized buffer. Network traffic with Transaction2 Secondary payload > 64KB. Double Pulsar implant beacon (4-byte XOR 0x37 response to SMB negotiate). Shadowserver scanning for exposed SMB.", "mitre": "T1210"},
        {"name": "EternalRomance", "cve": "CVE-2017-0147", "target": "Windows SMB (MS17-010)", "desc": "NSA SMB exploit targeting named pipe transaction. Similar to EternalBlue but uses different vulnerability path. Exploits race condition in SMB1 transaction handling. Requires named pipe access. Less reliable than EternalBlue but works on some systems where EternalBlue fails. Port 445.", "mitre": "T1210"},
        {"name": "EternalChampion", "cve": "CVE-2017-0146", "target": "Windows SMB (MS17-010)", "desc": "NSA SMB exploit via SMB1 negotiated protocol. Exploits vulnerability in SMB1 tree connect phase. Can achieve RCE on Windows Vista/7/8/Server 2008/2012. Part of FUZZBUNCH framework. Port 445.", "mitre": "T1210"},
        {"name": "EternalSynergy", "cve": "CVE-2017-0143", "target": "Windows SMB (MS17-010)", "desc": "NSA SMB exploit targeting Windows 8/Server 2012 via SMB1. Uses named pipe impersonation. Part of FUZZBUNCH framework. Port 445.", "mitre": "T1210"},
        {"name": "DoublePulsar", "cve": "N/A (implant, not exploit)", "target": "Windows kernel (x86/x64)", "desc": "NSA kernel-mode implant delivered after EternalBlue/EternalRomance exploitation. Installs as hook in srv2.sys SMB driver. Provides: 1) Backdoor via special SMB negotiate request (XOR 0x37 response), 2) DLL injection capability (stage0 payload loader). No disk persistence — memory-only. Detected by rapid port scanning (445) with crafted SMB negotiate. Found on 100K+ systems within weeks of Shadow Brokers leak.", "detection": "SMB negotiate request with specific parameters returns 4-byte response (XOR 0x37). Counter embedded in response indicates implant status. Scanning script: smb-double-pulsar-backdoor. Network anomaly: unusual SMB responses. Memory forensics: hooked srv2.sys dispatch table.", "mitre": "T1105,T1055"},
        {"name": "FUZZBUNCH", "cve": "N/A (framework)", "target": "Windows exploitation framework", "desc": "NSA Equation Group exploitation framework. Python-based with Tomcat integration. Automated target reconnaissance, exploit selection, and payload delivery. Includes plugins for each Eternal* exploit, DoublePulsar implant, and DANDERSPRITZ post-exploitation. Commands: redirect (set up proxy), target (define target), use (select exploit), set (configure parameters), exploit (execute). Leaked in full with Shadow Brokers April 2017 dump.", "mitre": "T1190"},
        {"name": "DANDERSPRITZ", "cve": "N/A (post-exploitation)", "target": "Windows post-exploitation suite", "desc": "NSA Equation Group post-exploitation framework. Modules: PASVOREGISTRY (registry read/write), PASSFREELY (credential harvesting), FUZZYBUNTING (keylogger), DARKSKYLINE (screen capture), YAKINKLES (process listing), PONDMAGIC (file system access). Communicates via encrypted channel with LP (Listening Post). Part of Equation Group toolchain after initial exploitation.", "mitre": "T1059,T1003,T1113,T1057"},
        {"name": "DARKPULSAR", "cve": "N/A (persistent implant)", "target": "Windows servers", "desc": "NSA Equation Group persistent backdoor for Windows servers. Installs as kernel driver. Survives reboots. Provides remote shell, file transfer, and command execution. Used for long-term persistent access to compromised servers. Extremely stealthy — minimal disk footprint.", "mitre": "T1543.003,T1059"},
        {"name": "ODDJOB", "cve": "N/A (implant)", "target": "Windows", "desc": "NSA Equation Group implant for Windows. Lightweight backdoor with file upload/download, command execution, and port forwarding capabilities. Often deployed alongside DoublePulsar for persistence.", "mitre": "T1059,T1021"},
        {"name": "EXTRABACON", "cve": "CVE-2016-6366", "target": "Cisco ASA (firewall)", "desc": "NSA Equation Group exploit targeting Cisco ASA SNMP vulnerability. Remote code execution on Cisco ASA 8.0-9.1.5. Delivered via crafted SNMP packet. Bypasses authentication to gain privileged EXEC mode. Patched by Cisco in 2016. Part of Shadow Brokers October 2016 dump (firewall tools).", "mitre": "T1190"},
        {"name": "BENIGNCERTAIN", "cve": "N/A", "target": "Fortigate firewalls", "desc": "NSA Equation Group exploit targeting Fortigate firewalls. Part of firewall toolset leaked October 2016. Exploits FortiOS vulnerability for remote access. Limited public technical details.", "mitre": "T1190"},
        {"name": "ESCUCHAR", "cve": "N/A", "target": "Juniper firewalls", "desc": "NSA Equation Group exploit targeting Juniper NetScreen firewalls. Part of firewall toolset leaked October 2016. Exploits ScreenOS vulnerability.", "mitre": "T1190"},
    ]

    for t in tools:
        eid = create_entity(t["name"], "tool")
        if eid:
            add_claim(eid, "capability", {
                "text": t["desc"],
                "source": "NSA Equation Group (leaked by Shadow Brokers)",
                "target": t["target"],
                **({"cve": t["cve"]} if t.get("cve") else {}),
                **({"mitre_attack_id": t["mitre"]} if t.get("mitre") else {}),
            }, 1.0, "Shadow Brokers dump analysis, Symantec, Kaspersky, Rapid7")
            if t.get("detection"):
                add_claim(eid, "detection", {"text": t["detection"]}, 0.95, "Security vendor analysis")
            add_claim(eid, "relationship", {
                "text": f"Leaked by Shadow Brokers in 2017. {t['name']} was part of NSA TAO (Tailored Access Operations) toolkit.",
                "related_entity": "Shadow Brokers",
                "relationship": "leaked_by",
            }, 1.0, "Shadow Brokers public releases")
            print(f"  + {t['name']}")

    # Ransomware families encyclopedia
    print("\n=== Ransomware Families ===")
    families = [
        ("WannaCry","malware","Self-propagating ransomware. EternalBlue + DoublePulsar for spread. AES-128-CBC + RSA-2048. Kill switch domain. 28-language ransom note. 2017. CVSS 9.8. Attributed to Lazarus/DPRK.", "CVE-2017-0144", "S0366"),
        ("NotPetya","malware","Destructive wiper disguised as ransomware. EternalBlue + EternalRomance + PsExec for spread. Overwrites MBR. No recovery possible. $10B+ damages. 2017. Attributed to Sandworm/GRU.", "CVE-2017-0144", "S0368"),
        ("Ryuk","malware","Targeted ransomware by Wizard Spider. Manual deployment. AES-256. $100K-$10M+ demands. 2018-2020. Evolved into Conti.", None, "S0446"),
        ("Conti","malware","RaaS by Wizard Spider. AES-256 + RSA-4096. Double extortion. ESXi variant. Source code leaked 2022. 1000+ victims.", None, "S0575"),
        ("LockBit3","malware","Rust-based RaaS. Bug bounty for own malware. Automated domain-wide deployment. ESXi variant. 2000+ victims. FBI most wanted. Takedown Feb 2024, re-emerged.", None, "S0492"),
        ("BlackCat/ALPHV","malware","First Rust ransomware. Cross-platform. REST API for victims. Triple extortion. FBI seizure Dec 2023. Exit scam Mar 2024.", None, "S1069"),
        ("Hive","malware","Go-based ransomware. FBI infiltrated and distributed decryptors for 1300+ victims. Takedown Jan 2023. Source code acquired by Hunters International.", None, "S0645"),
    ]
    for name, kind, desc, cve, mitre in families:
        eid = create_entity(name, kind)
        if eid:
            add_claim(eid, "capability", {"text": desc, **({"cve": cve} if cve else {}), **({"mitre_attack_id": mitre} if mitre else {})}, 1.0, "Threat intel analysis")
            print(f"  + {name}")

    print("\n=== Done ===")

if __name__ == "__main__":
    main()
