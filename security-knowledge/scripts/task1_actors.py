#!/usr/bin/env python3
"""Task 1: Deep threat actor profiles — APT29, APT28, Lazarus, etc."""
import psycopg, uuid, json

TENANT = uuid.UUID('bcc8ab78-0982-4ea3-81d3-7e4bd166881a')
conn = psycopg.connect('postgresql://sk:sk@localhost:5433/sk', autocommit=True)
conn.execute('SET app.bypass = true')

def upsert(kind, name, refs=None, mitre_id=None):
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM entities WHERE canonical_name=%s AND tenant_id=%s", (name, TENANT))
        r = cur.fetchone()
        if r:
            if refs or mitre_id:
                cur.execute("UPDATE entities SET external_refs=COALESCE(external_refs,'{}')||%s, mitre_attack_id=COALESCE(%s,mitre_attack_id), updated_at=NOW() WHERE id=%s", (json.dumps(refs or {}), mitre_id, r[0]))
            return r[0]
        eid = uuid.uuid4()
        cur.execute("INSERT INTO entities (id,tenant_id,kind,canonical_name,mitre_attack_id,external_refs,created_at,updated_at) VALUES(%s,%s,%s,%s,%s,%s,NOW(),NOW())", (eid,TENANT,kind,name,mitre_id,json.dumps(refs or {})))
        return eid

def claim(eid, ctype, val, conf=0.9, src=""):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO claims (id,entity_id,tenant_id,claim_type,value,confidence,status,created_at,updated_at) VALUES(%s,%s,%s,%s,%s,%s,'approved',NOW(),NOW()) ON CONFLICT DO NOTHING", (uuid.uuid4(),eid,TENANT,ctype,json.dumps(val),conf))

def rel(f, t, k, c=1.0):
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM relationships WHERE from_entity_id=%s AND to_entity_id=%s AND kind=%s AND tenant_id=%s", (f,t,k,TENANT))
        if cur.fetchone(): return
        cur.execute("INSERT INTO relationships (id,tenant_id,from_entity_id,to_entity_id,kind,confidence) VALUES(%s,%s,%s,%s,%s,%s)", (uuid.uuid4(),TENANT,f,t,k,c))

ACTORS = [
    {"name":"APT29","mitre":"G0016","aliases":["Cozy Bear","The Dukes","Midnight Blizzard","Nobelium","YTTRIUM"],"country":"Russia","org":"SVR/FSB","desc":"Russian Foreign Intelligence Service cyber espionage group. Compromised SolarWinds Orion platform (2020), Democratic National Committee (2015), COVID-19 vaccine researchers (2020), Microsoft corporate email (2024). Known for sophisticated supply chain attacks and long-term persistence. Uses custom malware families including WellMess, SoreFang, Cobalt Strike, and NOBELIUM toolchain. Techniques: T1566.001 spearphishing, T1195.002 supply chain, T1059.001 PowerShell, T1071.001 web protocols, T1055 process injection, T1547 boot/key startup persistence, T1078 valid accounts, T1110 brute force.","techniques":["T1566.001","T1195.002","T1059.001","T1071.001","T1055","T1547","T1078","T1110"],"tools":["Cobalt Strike","WellMess","NativeZone","GoldMax","SolarWinds Orion implant"],"campaigns":["SolarWinds Supply Chain","DNC Hack","COVID Vaccine Targeting","Microsoft Corporate Email"],"confidence":0.95,"sources":["Mandiant UNC2452 report","Microsoft MSTIC Nobelium analysis","CISA AA20-352A","UK NCSC APT29 advisory"]},
    {"name":"APT28","mitre":"G0007","aliases":["Fancy Bear","Sofacy","Sednit","Strontium","Forest Blizzard"],"country":"Russia","org":"GRU Unit 26165","desc":"Russian Main Intelligence Directorate military intelligence unit. Notable operations: 2016 DNC hack, NotPetya (attributed), Olympic Destroyer (2018), Macron campaign hack, Bundestag breach. Targets government, military, media, and election infrastructure across NATO states. Uses X-Agent (Sofacy), X-Tunnel, Zebrocy, Seduploader, CHOPSTICK. Techniques: T1566.002 spearphishing with malicious attachments, T1059.001 PowerShell, T1059.003 Windows Command Shell, T1071.001, T1055.001 DLL injection, T1547.001 Run key persistence, T1110.003 password spraying.","techniques":["T1566.002","T1059.001","T1059.003","T1071.001","T1055.001","T1547.001","T1110.003"],"tools":["X-Agent","Zebrocy","Seduploader","CHOPSTICK","X-Tunnel"],"campaigns":["2016 DNC Hack","Olympic Destroyer","Macron Campaign","Bundestag Breach","NotPetya"],"confidence":0.95,"sources":["Mueller Indictment","Mandiant APT28 report","CISA AA20-249A","EU Council attribution"]},
    {"name":"Lazarus Group","mitre":"G0032","aliases":["HIDDEN COBRA","Guardians of Peace","Zinc","Diamond Sleet","Velvet Chollima","Labyrinth Chollima"],"country":"North Korea","org":"RGB (Reconnaissance General Bureau)","desc":"North Korean state-sponsored group conducting both espionage and financially motivated operations. Most prolific state-sponsored cybercriminal group. Bangladesh Bank heist ($81M attempted, $81M via SWIFT), WannaCry ransomware (2017), Sony Pictures hack (2014), numerous cryptocurrency exchange thefts ($2B+ total by 2023). Uses AppleJeus, FASTCash, Electric Fish, BadCall, RawDisk, Hermes ransomware, VHD ransomware, TradeTraitor. Operates through DPRK IT worker fraud scheme placing operatives in Western companies. Techniques: T1566 spearphishing, T1059 PowerShell/WMI, T1021 lateral movement, T1486 data encrypted for impact, T1490 inhibit system recovery, T1071 application layer protocol, T1001 data obfuscation, T1568 dynamic resolution.","techniques":["T1566","T1059","T1021","T1486","T1490","T1071","T1001","T1568"],"tools":["AppleJeus","FASTCash","Electric Fish","Hermes","VHD Ransomware","RawDisk","DreamJob"],"campaigns":["Bangladesh Bank Heist","WannaCry","Sony Pictures Hack","CRYPTO HEISTS","DPRK IT Worker Fraud"],"confidence":0.95,"sources":["FBI FLASH","CISA AA22-108A","UN Panel of Experts reports","Chainalysis DPRK tracking"]},
    {"name":"APT41","mitre":"G0096","aliases":["Double Dragon","Winnti","Barium","Wicked Panda","RedGolf"],"country":"China","org":"MSS-backed / Chengdu 404 Network","desc":"Unique Chinese APT conducting both state-directed espionage and financially motivated supply chain attacks. Supply chain compromises: ASUS Live Update, CCleaner, Overwatch game, HP and Lenovo driver signing. Targets gaming, healthcare, telecoms, and government. Uses Cobalt Strike, ShadowPad, PlugX, Winnti, Poison Ivy, CobKat. Dual mission: espionage for state, supply chain for profit. Indicted by US DOJ in 2020. Techniques: T1195.002 supply chain, T1059.001 PowerShell, T1547.001, T1566.001, T1071.001, T1055, T1573 encrypted channel, T1105 ingress tool transfer.","techniques":["T1195.002","T1059.001","T1547.001","T1566.001","T1071.001","T1055","T1573","T1105"],"tools":["ShadowPad","PlugX","Winnti","Cobalt Strike","CobKat","POISONIVY"],"campaigns":["ASUS Supply Chain","CCleaner Supply Chain","Overwatch Supply Chain","HP/Lenovo Driver Signing"],"confidence":0.9,"sources":["FireEye/Mandiant APT41 report","US DOJ Indictment","Bitdefender ShadowPad analysis","PRODAFT ShadowPad report"]},
    {"name":"FIN7","mitre":"G0045","aliases":["Carbanak","Carbanak Group","Navigator Group"],"country":"Russia/Ukraine","org":"Financial cybercrime group","desc":"Financially motivated threat group that stole $1B+ from 100+ financial institutions. Pioneered POS malware campaigns targeting US restaurant/retail chains (Chili's, Jason's Deli, Chipotle, Arby's, Sears). Evolved to ransomware: REvil, Darkside, BlackMatter. Uses Carbanak backdoor, PlugX, Cobalt Strike, POWERTRASH, Emotet distribution. Social engineering via fake DoorDash/Uber job offers with USB baiting. Three members indicted by US DOJ in 2018. Techniques: T1566.001 phishing, T1059.001 PowerShell, T1055, T1021.001 RDP, T1486 ransomware, T1490, T1071.001, T1110.","techniques":["T1566.001","T1059.001","T1055","T1021.001","T1486","T1490","T1071.001","T1110"],"tools":["Carbanak","POWERTRASH","Cobalt Strike","REvil","Darkside"],"campaigns":["POS Campaigns (Chili's, Chipotle, etc)","REvil Ransomware","Darkside/BlackMatter"],"confidence":0.9,"sources":["FireEye FIN7 report","US DOJ Indictment","CrowdStrike FIN7 analysis","IBM X-Force FIN7"]},
    {"name":"Sandworm","mitre":"G0034","aliases":["IRIDIUM","Voodoo Bear","ELECTRUM","Seashell Blizzard","Iron Viking"],"country":"Russia","org":"GRU Unit 74455 (Main Center for Special Technologies)","desc":"Russian military intelligence unit responsible for most destructive cyberattacks in history. NotPetya (2017, $10B+ damage), 2015 and 2016 Ukraine power grid attacks, Olympic Destroyer (2018), Georgia web defacement (2019), US critical infrastructure (2020+). Indicted by US DOJ in 2020. Uses Industroyer/CrashOverride, BlackEnergy, KillDisk, Olympic Destroyer, NotPetya/Petya, VPNFilter, Cyclops Blink. First known cyberattack causing power outage (Ukraine 2015). Techniques: T0857 engineering workstations, T0831 manipulation of control, T0862 supply chain, T1059, T1547, T1486, T1490, T1566, T1190.","techniques":["T0857","T0831","T0862","T1059","T1547","T1486","T1490","T1566","T1190"],"tools":["Industroyer","BlackEnergy","KillDisk","NotPetya","VPNFilter","Cyclops Blink"],"campaigns":["Ukraine Power Grid 2015","NotPetya 2017","Olympic Destroyer","Georgia 2019","US Critical Infrastructure"],"confidence":0.95,"sources":["US DOJ Indictment","Mandiant Sandworm report","ESET Industroyer analysis","Dragos CRASHOVERRIDE report"]},
    {"name":"Turla","mitre":"G0010","aliases":["Snake","KRYPTON","Venomous Bear","Waterbug","Secret Blizzard"],"country":"Russia","org":"FSB (Federal Security Service)","desc":"Russian intelligence-linked APT active since 2004. One of the longest-running APTs. Known for sophisticated C2 using satellite internet hijacking (DVB-S2), compromised satellite links for C2, and hijacked Pakistani APT (Patchwork) infrastructure. Agent.BTZ (2008) infected US military CENTCOM networks via USB. Epic Turla (2014) and Venomous Bear campaigns. Uses Snake malware (rootkit, 20+ year evolution), Agent.BTZ, Carbon, Kazuar, ComRAT, Crutch. Techniques: T1071.002 bit-to-bit via satellite, T1573 encrypted channel, T1105, T1059, T1547, T1205 traffic signaling, T1021.","techniques":["T1071.002","T1573","T1105","T1059","T1547","T1205","T1021"],"tools":["Snake rootkit","Agent.BTZ","Carbon","Kazuar","ComRAT","Crutch"],"campaigns":["Agent.BTZ/CENTCOM","Epic Turla","Venomous Bear","Satellite C2 Campaigns"],"confidence":0.9,"sources":["ESET Turla research","Kaspersky Snake analysis","NASA OIG Agent.BTZ report","PwC Turla satellite C2"]},
    {"name":"Evil Corp","mitre":"G0115","aliases":["INDRIK SPIDER","Wizard Spider","UNC1878"],"country":"Russia","org":"Cybercrime group (Maksim Yakubets)","desc":"Russia-based cybercrime group responsible for Dridex banking trojan and BitPaymer/DoppelPaymer ransomware. Maksim Yakubets and Igor Turashev indicted by US DOJ in 2019. $100M+ stolen via Dridex. Uses Dridex (banking trojan), BitPaymer ransomware, DoppelPaymer (rebranded), WastedLoader, Hancitor loader. Transitioned to ransomware-as-a-service. Techniques: T1566.001, T1059.001, T1021.001, T1486, T1490, T1055, T1071, T1547.","techniques":["T1566.001","T1059.001","T1021.001","T1486","T1490","T1055","T1071","T1547"],"tools":["Dridex","BitPaymer","DoppelPaymer","WastedLoader","Hancitor"],"campaigns":["Dridex Banking","BitPaymer Ransomware","DoppelPaymer Ransomware"],"confidence":0.95,"sources":["US DOJ Indictment","NCA Evil Corp advisory","CrowdStrike INDRIK SPIDER","Microsoft MSTIC"]},
    {"name":"Equation Group","mitre":"G0020","aliases":["Tilded Team","Strawfit"],"country":"United States","org":"NSA TAO (Tailored Access Operations)","desc":"Highly sophisticated APT attributed to NSA TAO. Active since at least 2001. Shadow Brokers leak (2016) released EternalBlue (exploited in WannaCry/NotPetya), EternalRomance, DoublePulsar, and 20+ Windows SMB/RPC exploits. Stuxnet link — shared code with Equation Group tools. Uses GRAYFISH firmware implant, EQGRP tools, DOUBLEARCS, MANYACSEX, DARKPULLEY. Fanny worm (2008) used USB air-gap bridging. Techniques: T1190, T1210, T1055, T1547, T1569, T1105, T1071, T1573.","techniques":["T1190","T1210","T1055","T1547","T1569","T1105","T1071","T1573"],"tools":["EternalBlue","EternalRomance","DoublePulsar","GRAYFISH","Fanny Worm"],"campaigns":["Shadow Brokers Leak","Stuxnet (linked)","Fanny Worm","GRIZZLY STEPPE"],"confidence":0.8,"sources":["Kaspersky Equation Group report","Shadow Brokers releases","The Intercept NSA documents","Symantec Equation Group analysis"]},
    {"name":"Equation Group — Tooling & Exploit Leaks","mitre":None,"aliases":[],"country":"United States","org":"NSA TAO","desc":"Shadow Brokers leaked Equation Group tools in 2016-2017. EternalBlue (MS17-010, CVE-2017-0144) exploited SMBv1, used in WannaCry and NotPetya — caused billions in damage. EternalRomance (CVE-2017-0143) targeted SMB. DoublePulsar backdoor. EDUCATEDSCHOLAR exploited Windows Print Spooler. ODDJOB ICMP tunnel. DARKPULLEY keylogger. The leak fundamentally changed threat landscape — nation-state exploits became commodity. At least 20+ unique Windows SMB/RPC exploitation frameworks released.","techniques":["T1190","T1210"],"tools":["EternalBlue","EternalRomance","EternalSynergy","DoublePulsar","EDUCATEDSCHOLAR","EMERALDTHREAD"],"campaigns":["Shadow Brokers Month 1-6 dumps"],"confidence":0.8,"sources":["Shadow Brokers GitHub","Microsoft MS17-010","RiskSense EternalBlue analysis"]},
]

count = 0
for a in ACTORS:
    eid = upsert("threat_actor", a["name"], refs={
        "mitre_attack_id": a.get("mitre",""), "aliases": a["aliases"],
        "country": a["country"], "organization": a["org"],
        "sources": a.get("sources",[]), "trust_tier": 1,
    }, mitre_id=a.get("mitre"))

    claim(eid, "attribution", {
        "assertion": f"{a['name']} ({', '.join(a['aliases'])}) is attributed to {a['org']}, {a['country']}. {a['desc'][:200]}",
        "country": a["country"], "organization": a["org"], "aliases": a["aliases"],
        "tags": ["threat-actor","attribution",a["country"].lower()] + [a["name"].lower()],
    }, conf=a.get("confidence",0.9))

    claim(eid, "technique", {
        "assertion": f"{a['name']} uses techniques: {', '.join(a['techniques'])}. {a['desc'][:300]}",
        "techniques": a["techniques"], "tags": ["techniques","mitre-attack"] + a["techniques"][:5],
    }, conf=a.get("confidence",0.9))

    claim(eid, "tooling", {
        "assertion": f"{a['name']} uses tooling: {', '.join(a['tools'])}.",
        "tools": a["tools"], "tags": ["tools","malware"] + a["tools"][:5],
    }, conf=a.get("confidence",0.85))

    claim(eid, "campaign", {
        "assertion": f"{a['name']} campaigns: {', '.join(a['campaigns'])}.",
        "campaigns": a["campaigns"], "tags": ["campaigns","operations"],
    }, conf=a.get("confidence",0.85))

    # Link to tools/malware
    for tool_name in a["tools"]:
        tool_eid = upsert("tool" if "Cobalt Strike" in tool_name or "PowerShell" in tool_name else "malware", tool_name, refs={"source": a["name"], "trust_tier": 2})
        rel(eid, tool_eid, "uses", 0.85)

    count += 1
    print(f"  {a['name']}: entity + 4 claims + {len(a['tools'])} tool links")

conn.close()
print(f"\n✅ {count} threat actors profiled")
