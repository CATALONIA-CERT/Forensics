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
| Binary execution | %SystemRoot%\Prefetch  <br>%SystemRoot%\System32\config\SYSTEM  <br>%SystemRoot%\AppCompat\Programs\Amcache.hve | • Prefetch (if enabled): executable name, path, and execution count  <br>• Amcache/ShimCache: historical execution metadata for binaries, SHA1 hash |
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
> Therefore, you can find [here](../README.md) a guide of traces that Windows naturally produces, not to intentional persistence or file creation by the tool.

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

This section documents the **files and rules** generated to enhance forensic analysis of AnyDesk activity. These detection artifacts are designed to identify suspicious behaviors, unauthorized remote access attempts, and persistence mechanisms associated with revsocks.

- [revsocks.yml (CATALONIA-CERT)](../../Outputs/sigmas/revsocks.yml)
- [indicator_tools.yar (ditekshen)](https://github.com/ditekshen/detection/blob/master/yara/indicator_tools.yar)
- [tool_revsocks_strings.yar (SEKOIA-IO)](https://github.com/SEKOIA-IO/Community/blob/main/yara_rules/tool_revsocks_strings.yar)