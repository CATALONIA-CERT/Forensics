# Revsocks

## Index

- [Revsocks](#revsocks)
  - [Index](#index)
  - [1. Technical overview](#1-technical-overview)
  - [2. Summary table of artifacts](#2-summary-table-of-artifacts)
    - [2.a. Disk artifacts](#2a-disk-artifacts)
    - [2.b. Runtime artifacts](#2b-runtime-artifacts)
  - [3. Installation artifacts](#3-installation-artifacts)
  - [4. Disk artifacts](#4-disk-artifacts)
    - [4.a. Execution traces created by the operating system](#4a-execution-traces-created-by-the-operating-system)
      - [Prefetch](#prefetch)
      - [Amcache / ShimCache](#amcache--shimcache)
    - [4.b. Process‑related artifacts](#4b-processrelated-artifacts)
      - [Process Creation Events (Security Logs)](#process-creation-events-security-logs)
    - [4.c. PowerShell Telemetry](#4c-powershell-telemetry)
      - [Script Block Logging](#script-block-logging)
    - [4.d. Windows Error Reporting (WER)](#4d-windows-error-reporting-wer)
    - [4.e. Attacker‑created persistence (not part of the tool)](#4e-attackercreated-persistence-not-part-of-the-tool)
    - [4.f. File System Evidence](#4f-file-system-evidence)
      - [Recent Files (LNK artifacts)](#recent-files-lnk-artifacts)
      - [Shadow Copies / Residual Copies](#shadow-copies--residual-copies)
  - [5. Runtime artifacts](#5-runtime-artifacts)
    - [5.a  OS Interaction artifacts](#5a--os-interaction-artifacts)
      - [WinSock provider enumeration](#winsock-provider-enumeration)
      - [WinSock provider enumeration](#winsock-provider-enumeration-1)
      - [Networking DLLs loaded in memory](#networking-dlls-loaded-in-memory)
    - [5.b  Network artifacts](#5b--network-artifacts)
      - [Long‑lived TCP connection](#longlived-tcp-connection)
      - [Long‑lived TCP connection](#longlived-tcp-connection-1)
      - [TLS traffic characteristics (if TLS enabled)](#tls-traffic-characteristics-if-tls-enabled)
      - [Non‑TLS traffic characteristics (if TLS disabled)](#nontls-traffic-characteristics-if-tls-disabled)
  - [6. Detection rules and collection targets](#6-detection-rules-and-collection-targets)


## 1. Technical overview

High‑level description of the tool’s purpose, functionality, and operating behavior.

| Section | Content |
|---------|---------|
| Description | GitHub – kost/revsocks: Reverse SOCKS5 implementation in Go  <br><br>Reverse SOCKS5 tunneler with SSL/TLS and proxy support (without proxy authentication and with basic/NTLM proxy authentication) that can also reverse itself over a firewall. |
| Tactics & Techniques | TA0005 – Defense Evasion  <br>• T1572 – Protocol Tunneling  <br>• T1090 – Proxy  <br>• T1071.001 – Web Protocols (WebSocket/HTTPS)  <br>• T1071.004 – DNS (SOCKS over DNS)  <br>• T1573 – Encrypted Channel (TLS by default)  <br><br>TA0007 – Discovery  <br>• T1012 – Query Registry (WinSock registry keys)  <br>• T1016 – System Network Configuration Discovery (inspection of network stack/capabilities)  <br>• API context: WSAEnumProtocols* to enumerate installed protocols  <br><br>TA0011 – Command and Control  <br>• T1090 – Proxy |
| Privileges | No (Portable Mode) |
| OS | Windows, Linux, macOS (written in Go) |
| Network | Typically:  <br>• TCP/8443 (C2C)  <br>• TCP/1080 (victim side)  <br>• TCP/53 or UDP/53 (DNS) |


## 2. Summary table of artifacts

Overview table summarizing the main artifacts, where they reside and what information they contain.

### 2.a. Disk artifacts

| Source | Artifact | Indicator |
|------------|----------|-----------|
| Binary execution | %SystemRoot%\Prefetch  <br>%SystemRoot%\System32\config\SYSTEM  <br>%SystemRoot%\AppCompat\Programs\Amcache.hve | • Prefetch: executable name, path, and execution count  <br>• Amcache/ShimCache: historical execution metadata for binaries, SHA1 hash |
| Process events | %SystemRoot%\System32\winevt\Logs | Event ID 4688 (process creation) |
| PowerShell logs | %SystemRoot%\System32\winevt\Logs | • Script Block Logging (4104), transcripts  <br>• Commands and parameters captured if ScriptBlockLogging or Transcription were enabled |
| Binary errors | %ProgramData%\Microsoft\Windows\WER\ReportArchive\  <br>%LOCALAPPDATA%\Microsoft\Windows\WER\ReportArchive\ | Windows Error Reporting (WER) logs |
| Attacker-created persistence (not built into the tool) | Multiple | • Rare or unknown services  <br>• Run keys  <br>• Unrecognized scheduled tasks |
| File system | Bit‑by‑bit disk copy  <br>%APPDATA%\Roaming\Microsoft\Windows\Recent | • Does not write files to the file system  <br>• Does not generate .conf, .json, .ini  <br>• No installers or paths created by the tool  <br>• Copies of the binary may be found in shadow copies or auxiliary scripts  <br>• LNK files may appear in Recent Items referencing the binary |

### 2.b. Runtime artifacts

| Source | Artifact | Indicator |
|------------|----------|-----------|
| Enumeration of WinSock providers | %SystemRoot%\System32\Config\SYSTEM | HKLM\SYSTEM\ControlSet001\Services\WinSock2\Parameters <br> (This is quite characteristic of reverse proxies.) |
| API calls | Memory dump, procdump or EDR | • WSAStartup  <br>• WSAEnumProtocolsW  <br>• WSAGetOverlappedResult |
| DLLs in memory | Memory dump, procdump or EDR | • WS2_32.dll  <br>• wship6.dll  <br>• wshtcpip.dll  <br>• wshqos.dll <br> (Common in tunneling tools.) |
| Generic network detection | Memory dump, procdump, EDR, FW, IDS/IPS | Long‑lived TCP connection with:  <br>• Low throughput  <br>• Multiplexed traffic  <br>• Repetitive bytes (Go framing)  <br>• Unusual DNS traffic |
| Detection of TLS network traffic | Memory dump, procdump, EDR, FW, IDS/IPS | • Recently issued Let's Encrypt certificates  <br>• Customized SNI  <br>• ALPN not typical (h2, http/1.1) |
| Detection of non‑TLS network traffic | Memory dump, procdump, EDR, FW, IDS/IPS | • First bytes do not match standard SOCKS5 handshake  <br>• protobuf sequences observed  <br>• Multiplexed channels with channel ID |


## 3. Installation artifacts
Not applicable.


## 4. Disk artifacts

Persistent data the tool writes to disk, including configuration files, logs, system files, and other persistent data created.

> The tool does not leave characteristic artifacts on disk after shutdown (cold acquisition). It does not write configuration files, does not drop auxiliary components, does not persist itself, and does not patch or modify system files.
>
> Therefore, all artifacts below correspond only to execution traces that Windows naturally produces, not to intentional persistence or file creation by the tool.

### 4.a. Execution traces created by the operating system

#### Prefetch

Windows Prefetch records execution metadata of binaries launched from disk. Although the tool does not persist, launching the binary normally generates a .pf file unless Prefetching is disabled.

```
C:\Windows\Prefetch\
```

**What to look for?**

- Executable name
- Execution path (useful to determine where the binary was run from)
- Execution count
- Last execution timestamp

#### Amcache / ShimCache

Amcache and ShimCache record historical execution information for PE files, including program path and cryptographic hashes.

```
C:\Windows\AppCompat\Programs\Amcache.hve
SYSTEM hive → ...\AppCompatCache
```

**What to look for?**

- File path used at execution time
- SHA‑1 hash
- Last modification timestamps
- Evidence of execution even if file no longer exists

### 4.b. Process‑related artifacts

#### Process Creation Events (Security Logs)

Windows logs new process creation when auditing is enabled. The tool’s execution will appear as a standard process creation event: Event ID 4688

```
C:\Windows\System32\winevt\Logs\Security.evtx
```

**What to look for?**

- Parent process (e.g., explorer.exe, cmd.exe, powershell.exe)
- Full command line
- Process ID mapping
- Execution path

### 4.c. PowerShell Telemetry

(Only if launched through PowerShell or if PowerShell was used around the time of execution)

#### Script Block Logging

If ScriptBlockLogging (4104) or Transcription is enabled, commands and parameters used to invoke the binary may appear in the PowerShell Operational Log.

```
C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell/Operational.evtx
```

**What to look for?**

- PowerShell invocation of the binary
- Command‑line arguments
- Operator activity before/after execution

### 4.d. Windows Error Reporting (WER)

If the binary crashes or is forcibly terminated, Windows Error Reporting generates diagnostic bundles.

```
C:\ProgramData\Microsoft\Windows\WER\ReportArchive\
C:\Users\<USER>\AppData\Local\Microsoft\Windows\WER\ReportArchive\
```

**What to look for?**

- Crash dumps (if generated)
- Faulting module name
- Execution timestamp
- System metadata tied to the execution event

### 4.e. Attacker‑created persistence (not part of the tool)

The tool itself does not create persistence, but an attacker may create manual persistence around it.

Potential locations include:
```
HKCU/HKLM Run keys
Scheduled Tasks (C:\Windows\System32\Tasks\)
New services created using sc.exe or PowerShell
```

**What to look for?**

Recently created services with unusual names
Run keys pointing to non‑signed or temporary binaries
Suspicious scheduled tasks with unexpected triggers

### 4.f. File System Evidence

(No persistent artifacts, but OS traces may remain)

#### Recent Files (LNK artifacts)

If ScriptBlockLogging (4104) or Transcription is enabled, commands and parameters used to invoke the binary may appear in the PowerShell Operational Log.

```
C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell/Operational.evtx
```

**What to look for?**

- PowerShell invocation of the binary
- Command‑line arguments
- Operator activity before/after execution

#### Shadow Copies / Residual Copies

Copies of the binary may remain in restore points or shadow copies even if deleted afterward.

(No fixed path — browse via vssadmin / forensic mounts)

**What to look for?**

- Copies of the binary in user directories
- Operator tool staging areas

## 5. Runtime artifacts
Evidence produced during the tool’s execution, such as processes, network connections, session activity, temporary files, and other live data.

> Runtime analysis reveals clear, distinctive behavioral indicators produced by this tool.

### 5.a  OS Interaction artifacts

#### WinSock provider enumeration

The tool performs read‑only enumeration of WinSock provider catalogs to understand the available transport protocols — a behavior strongly associated with tunneling and reverse SOCKS agents.

```
C:\Windows\System32\Config\SYSTEM
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WinSock2\Parameters
```

**What to look for?**

- Repeated reads of AppId_Catalog, Protocol_Catalog9, NameSpace_Catalog5
- Queries occurring immediately after process startup
- No modifications — enumeration only

#### WinSock provider enumeration

A distinctive sequence of WinSock API calls is observed during initialization. This pattern clearly differs from standard applications and is typical of custom tunneling frameworks.

```
WSAStartup
WSAEnumProtocolsW
WSAGetOverlappedResult
```

**What to look for?**
- Telemetry showing enumeration of WSAPROTOCOL_INFO structures
- No involvement of persistence‑related APIs
- High density of networking API calls during early runtime

#### Networking DLLs loaded in memory

The tool dynamically loads standard Windows DLLs required for socket operations. The combination is consistent with custom network tunneling.

```
WS2_32.dll
wship6.dll
wshtcpip.dll
wshqos.dll
```

**What to look for?**
- DLL load order characteristic of custom sockets initialization
- Absence of dropped or injected DLLs
- Presence of memory structures tied to stream‑multiplexing logic

### 5.b  Network artifacts

#### Long‑lived TCP connection

The tool establishes a persistent TCP session acting as a multiplexed reverse tunnel.

```
Artifact location/path
```

**What to look for?**
- One long‑duration TCP connection to a remote operator
- Low but steady throughput
- Evidence of multiple logical channels over a single TCP socket
- Repetitive Go framing bytes

#### Long‑lived TCP connection

The tool establishes a persistent TCP session acting as a multiplexed reverse tunnel.

**What to look for?**
- One long‑duration TCP connection to a remote operator
- Low but steady throughput
- Evidence of multiple logical channels over a single TCP socket
- Repetitive Go framing bytes

#### TLS traffic characteristics (if TLS enabled)

TLS handshakes reveal a non‑standard client fingerprint.

**What to look for?**
- Recently issued Let's Encrypt certificates
- Custom or unexpected SNI
- ALPN missing common values (no h2, no http/1.1)

#### Non‑TLS traffic characteristics (if TLS disabled)

Without encryption, the tool's internal multiplexing protocol becomes visible.

**What to look for?**
- First packet does not match SOCKS5 handshake
- protobuf‑based serialization (varints, field tags)
- Channel IDs indicating multiple streams on a single TCP session


## 6. Detection rules and collection targets

This section documents the **files and rules** generated to enhance forensic analysis of AnyDesk activity. These detection artifacts are designed to identify suspicious behaviors, unauthorized remote access attempts, and persistence mechanisms associated with AnyDesk.

https://github.com/ditekshen/detection/blob/master/yara/indicator_tools.yar

```yaml
rule INDICATOR_TOOL_PROX_revsocks {
    meta:
        author = "ditekSHen"
        description = "Detects revsocks Reverse socks5 tunneler with SSL/TLS and proxy support"
    strings:
        $s1 = "main.agentpassword" fullword ascii 
        $s2 = "main.connectForSocks" fullword ascii 
        $s3 = "main.connectviaproxy" fullword ascii 
        $s4 = "main.DnsConnectSocks" fullword ascii 
        $s5 = "main.listenForAgents" fullword ascii 
        $s6 = "main.listenForClients" fullword ascii
        $s7 = "main.getPEMs" fullword ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x457f) and 4 of them
}
```

https://github.com/SEKOIA-IO/Community/blob/main/yara_rules/tool_revsocks_strings.yar

```yaml
rule tool_revsocks_strings {
    meta:
        id = "f5f34e74-0795-4c81-a385-218a8197a0b7"
        version = "1.0"
        description = "Detects revsocks client"
        author = "Sekoia.io"
        creation_date = "2024-03-07"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "reverse socks5 server/client by kost" ascii fullword
        $ = "github.com/kost/"
        $ = "revsocks -listen"
        $ = "Start on the DNS server: revsocks -dns"
        $ = "crypto/aes."
        
    condition:
        ( uint32be(0) == 0x7f454c46 or 
          uint16be(0) == 0x4d5a or 
          uint32be(0) == 0xfeedface or 
          uint32be(0) == 0xfeedfacf or 
          uint32be(0) ==  0xcafebabe or
          uint32be(0) ==  0xCFFAEDFE) and
        3 of them
}
```

```yaml
title: Suspicious WinSock Provider Enumeration by Non-System Processes
status: experimental
description: Detecta procesos que no forman parte del sistema operativo enumerando catálogos de WinSock (AppId_Catalog, Protocol_Catalog9, NameSpace_Catalog5). Actividad típica de proxys inversos, túneles y herramientas como revsocks, ligolo-ng, gost o frp.
author: Copilot
date: 2026-03-03
logsource:
  product: windows
  category: registry

detection:
  winsock_keys:
    TargetObject|contains:
      - "\\Services\\WinSock2\\Parameters\\AppId_Catalog"
      - "\\Services\\WinSock2\\Parameters\\Protocol_Catalog9"
      - "\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5"

  exclude_system:
    Image|startswith:
      - "C:\\Windows\\System32\\"
      - "C:\\Windows\\SysWOW64\\"
      - "C:\\Windows\\winsxs\\"
      - "C:\\Program Files\\WindowsApps\\"
      - "C:\\Windows\\explorer.exe"

  condition: winsock_keys and not exclude_system

fields:
  - Image
  - TargetObject
  - ProcessId
  - User
  - ComputerName

falsepositives:
  - Software de red legítimo que consulta proveedores WinSock (muy poco habitual).
  - Herramientas de diagnóstico avanzadas de red.
level: high
```