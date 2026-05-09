#!/usr/bin/env python3
"""Deep research ingestion — create interlinked threat intel entities.

Implements the deep-research-prompt.md plan: ingest threat actors,
TTPs, IOCs, tooling, and reports as searchable, interlinked entities.
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import AsyncSessionLocal
from app.models.entities import Entity
from app.models.claims import Claim
from app.models.evidence import Evidence
from app.models.auth import ApiKey

# ── Threat Intel Dataset ──────────────────────────────────────
# Core threat actors, incidents, and tooling from public reporting
THREAT_ACTORS = [
    {"name": "APT29", "kind": "threat_actor", "description": "Cozy Bear. Russian SVR-linked APT. Responsible for SolarWinds supply chain compromise, DNC hack. Known for living-off-the-land techniques, credential harvesting, and long-term espionage operations.", "aliases": ["Cozy Bear", "The Dukes", "YTTRIUM", "Iron Hemlock"], "mitre_id": "G0016", "country": "Russia", "motivation": "Espionage"},
    {"name": "APT28", "kind": "threat_actor", "description": "Fancy Bear. Russian GRU Unit 26165. Responsible for DNC hack, NotPetya contribution, Olympic Destroyer, and wide-ranging credential phishing campaigns. Uses zero-days and custom malware.", "aliases": ["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM", "Iron Twilight"], "mitre_id": "G0007", "country": "Russia", "motivation": "Espionage, Disruption"},
    {"name": "Lazarus Group", "kind": "threat_actor", "description": "North Korean state-sponsored group. Responsible for Bangladesh Bank SWIFT heist ($81M attempted), WannaCry ransomware, Sony Pictures hack, and numerous cryptocurrency exchange thefts. Divides into multiple sub-groups.", "aliases": ["HIDDEN COBRA", "Guardians of Peace", "Zinc", "Labyrinth Chollima", "APT38"], "mitre_id": "G0032", "country": "DPRK", "motivation": "Financial, Espionage"},
    {"name": "Shadow Brokers", "kind": "threat_actor", "description": "Mysterious group that leaked NSA Equation Group tools in 2016-2017. Released EternalBlue, EternalRomance, DoublePulsar and other Windows SMB exploits. Leaks led to WannaCry and NotPetya attacks. Auctioned additional tools for 10,000 BTC. Identity never confirmed — theories include Russian GRU insider threat or disgruntled NSA contractor.", "aliases": ["The Shadow Brokers"], "mitre_id": None, "country": "Unknown", "motivation": "Disruption, Financial"},
    {"name": "Carbanak", "kind": "threat_actor", "description": "Financially motivated APT targeting banks. Used Carbanak/Anunak malware to steal $1B+ from 100+ banks across 30 countries. Gained access via spear phishing, then used video surveillance of bank staff to mimic their activities. Known for persistence and understanding of internal banking SWIFT operations.", "aliases": ["FIN7", "Carbanak", "Cobalt Group", "Anunak"], "mitre_id": "G0017", "country": "Russia/Ukraine", "motivation": "Financial"},
    {"name": "DarkSide", "kind": "threat_actor", "description": "Ransomware-as-a-service operation. Responsible for Colonial Pipeline attack (May 2021) that caused US fuel shortage. Operated as affiliate model, taking 25% cut. Shut down after high-profile attention. Rebranded as BlackMatter. Used double extortion: encrypt + threaten data leak.", "aliases": ["BlackMatter"], "mitre_id": None, "country": "Eastern Europe", "motivation": "Financial"},
    {"name": "Conti", "kind": "threat_actor", "description": "Russian ransomware group. Leaked chat logs (500K+ messages) revealed organizational structure, HR processes, and operational security failures. Attacked Ireland's health service, Costa Rica government. Affiliated with Wizard Spider. Known for aggressive tactics and large-scale operations.", "aliases": ["Wizard Spider", "Ryuk", "TrickBot"], "mitre_id": None, "country": "Russia", "motivation": "Financial"},
    {"name": "APT41", "kind": "threat_actor", "description": "Chinese dual-mission APT conducting both espionage and financially motivated attacks. Unique in conducting state-directed espionage alongside personal financial crime. Uses supply chain compromises, mobile malware, and gaming-related targeting. Members indicted by US DOJ in 2020.", "aliases": ["Double Dragon", "Barium", "Wicked Panda", "Winnti"], "mitre_id": "G0096", "country": "China", "motivation": "Espionage, Financial"},
]

INCIDENTS = [
    {"name": "Bangladesh Bank SWIFT Heist", "kind": "incident", "description": "February 2016. Lazarus Group compromised Bangladesh Central Bank's SWIFT terminal. Submitted 35 fraudulent transfer requests totaling $951M. 5 transactions ($81M) processed before typo in 'foundation' flagged as suspicious. Funds laundered through Philippines casinos. Demonstrated critical SWIFT infrastructure vulnerability and DPRK financial motivation.", "year": 2016, "severity": "critical", "actors": ["Lazarus Group"], "ioCs": ["malware:Backdoor.Destover", "c2:lightning2010.org"]},
    {"name": "SolarWinds Supply Chain Attack", "kind": "incident", "description": "Discovered December 2020. APT29 compromised SolarWinds Orion build system, inserting SUNBURST backdoor into updates distributed to 18,000+ organizations. Affected US Treasury, Commerce Dept, DHS, FireEye, Microsoft. Supply chain trust exploited at unprecedented scale. Dormant for 9+ months before activation.", "year": 2020, "severity": "critical", "actors": ["APT29"], "ioCs": ["CVE-2020-10148", "malware:SUNBURST", "domain:avsvmcloud.com"]},
    {"name": "WannaCry Ransomware Attack", "kind": "incident", "description": "May 2017. Ransomware worm using EternalBlue (NSA SMB exploit leaked by Shadow Brokers) to self-propagate. Infected 230,000+ computers in 150 countries in 24 hours. UK NHS severely impacted. Kill switch domain registered by Marcus Hutchins halted spread. Attributed to Lazarus Group by US, UK governments.", "year": 2017, "severity": "critical", "actors": ["Lazarus Group", "Shadow Brokers"], "ioCs": ["CVE-2017-0144", "exploit:EternalBlue", "malware:WannaCry", "domain:iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"]},
    {"name": "NotPetya Attack", "kind": "incident", "description": "June 2017. Destructive wiper disguised as ransomware. Used EternalBlue and EternalRomance to spread. Maersk, Merck, Reckitt Benckiser, FedEx hit. $10B+ total damages. No recovery possible — MBR overwritten. Attributed to Russian GRU Sandworm unit. Most destructive cyberattack in history at the time.", "year": 2017, "severity": "critical", "actors": ["APT28", "Shadow Brokers"], "ioCs": ["CVE-2017-0144", "malware:NotPetya", "exploit:EternalBlue"]},
    {"name": "Colonial Pipeline Ransomware", "kind": "incident", "description": "May 2021. DarkSide ransomware encrypted Colonial Pipeline's billing system. Pipeline shut down for 6 days causing fuel shortages across US East Coast. $4.4M ransom paid (2.3 BTC). FBI recovered 63.7 BTC. Led to Executive Order on Improving Nation's Cybersecurity.", "year": 2021, "severity": "critical", "actors": ["DarkSide"], "ioCs": ["malware:DarkSide", "ransom_btc:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"]},
    {"name": "Stuxnet", "kind": "incident", "description": "2010. First known cyber weapon. Joint US-Israel operation targeting Iranian Natanz nuclear enrichment centrifuges. Used 4 Windows zero-days, Siemens PLC rootkit, and USB air-gap crossing. Destroyed ~1,000 centrifuges by manipulating rotor speeds while displaying normal readings to operators. Changed geopolitics of cyber warfare.", "year": 2010, "severity": "critical", "actors": [], "ioCs": ["malware:Stuxnet", "CVE-2010-2568", "CVE-2010-2729", "target:Siemens S7-300 PLC"]},
]

TOOLING = [
    {"name": "EternalBlue", "kind": "tool", "description": "NSA-developed SMB exploit (MS17-010) targeting Windows SMBv1. Leaked by Shadow Brokers in 2017. Exploits buffer overflow in SMBv1 transaction parsing. Reliable remote code execution on unpatched Windows 7/Server 2008. Used in WannaCry and NotPetya attacks. Patches available since March 2017.", "mitre_id": "T1210", "cve": "CVE-2017-0144", "source": "NSA Equation Group"},
    {"name": "Mimikatz", "kind": "tool", "description": "Windows credential dumper by Benjamin Delpy. Extracts plaintext passwords, hashes, PINs, Kerberos tickets from LSASS memory. Core tool in nearly every Windows post-exploitation chain. Features include pass-the-hash, pass-the-ticket, golden ticket, silver ticket attacks. Defenders detect via LSASS access monitoring.", "mitre_id": "T1003.001", "legitimate": True},
    {"name": "Cobalt Strike", "kind": "tool", "description": "Commercial adversary simulation framework by HelpSystems (now Fortra). Beacon implant provides C2, lateral movement, privilege escalation. Heavily cracked and used by actual threat actors (FIN7, APT29, Conti). Malleable C2 profiles allow traffic mimicry. Detection via beacon artifacts, JA3/JA3S fingerprinting.", "mitre_id": "S0154", "legitimate": True},
    {"name": "Metasploit", "kind": "tool", "description": "Open-source penetration testing framework. 2,000+ exploit modules, 1,000+ auxiliary modules. Meterpreter payload provides post-exploitation. Industry standard for vulnerability verification. Rapid7 maintained. Extensively documented, making it both defender's tool and attacker's entry point.", "legitimate": True},
]

async def main():
    async with AsyncSessionLocal() as db:
        # Get tenant
        from sqlalchemy import select
        from app.models.auth import Tenant
        res = await db.execute(select(Tenant).limit(1))
        tenant = res.scalar_one_or_none()
        if not tenant:
            print("ERROR: No tenant found. Bootstrap the service first.")
            return
        tid = tenant.id
        print(f"Tenant: {tid}")

        # Import threat actors
        created = 0
        for actor in THREAT_ACTORS:
            exists = await db.execute(select(Entity).where(Entity.canonical_name == actor["name"]))
            if exists.scalars().first():
                continue
            refs = {"aliases": actor.get("aliases", []), "country": actor.get("country", ""),
                    "motivation": actor.get("motivation", "")}
            if actor.get("mitre_id"):
                refs["mitre_attack_id"] = actor["mitre_id"]
            ent = Entity(
                canonical_name=actor["name"],
                kind=actor["kind"],
                tenant_id=tid,
                description=actor["description"],
                external_refs=refs,
            )
            db.add(ent)
            created += 1
        print(f"Actors: {created} created")

        # Import incidents
        created = 0
        for inc in INCIDENTS:
            exists = await db.execute(select(Entity).where(Entity.canonical_name == inc["name"]))
            if exists.scalars().first():
                continue
            refs = {"year": inc.get("year"), "severity": inc.get("severity", ""),
                    "actors": inc.get("actors", []), "ioCs": inc.get("ioCs", [])}
            ent = Entity(
                canonical_name=inc["name"],
                kind=inc["kind"],
                tenant_id=tid,
                description=inc["description"],
                external_refs=refs,
            )
            db.add(ent)
            created += 1
        print(f"Incidents: {created} created")

        # Import tooling
        created = 0
        for tool in TOOLING:
            exists = await db.execute(select(Entity).where(Entity.canonical_name == tool["name"]))
            if exists.scalars().first():
                continue
            refs = {}
            if tool.get("mitre_id"):
                refs["mitre_attack_id"] = tool["mitre_id"]
            if tool.get("cve"):
                refs["cve"] = tool["cve"]
            if tool.get("source"):
                refs["source"] = tool["source"]
            refs["legitimate"] = tool.get("legitimate", False)
            ent = Entity(
                canonical_name=tool["name"],
                kind=tool["kind"],
                tenant_id=tid,
                description=tool["description"],
                external_refs=refs,
            )
            db.add(ent)
            created += 1
        print(f"Tools: {created} created")

        await db.commit()
        print("Done! All threat intel entities created.")

if __name__ == "__main__":
    asyncio.run(main())
