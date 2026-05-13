# Zoho Assist

- [Zoho Assist](#zoho-assist)
  - [1. Technical overview](#1-technical-overview)
  - [2. Summary table of artifacts](#2-summary-table-of-artifacts)
    - [Non-volatile artifacts](#non-volatile-artifacts)
  - [3. Non-volatile artifacts](#3-non-volatile-artifacts)
    - [3.1 Browser Extension IDs (Chrome, Edge, Firefox)](#31-browser-extension-ids-chrome-edge-firefox)
      - [Chromium-based browsers (Chrome and Edge)](#chromium-based-browsers-chrome-and-edge)
        - [Example extension ID (case provided)](#example-extension-id-case-provided)
        - [Typical installation path](#typical-installation-path)
      - [Mozilla Firefox](#mozilla-firefox)
    - [3.2 Log Artifacts](#32-log-artifacts)
      - [Service and GUI logs](#service-and-gui-logs)
      - [What to look for?](#what-to-look-for)
      - [3.2.1 SessionAuditReport\_`<SessionID>`.log](#321-sessionauditreport_sessionidlog)
      - [3.2.1.1 Audit components metadata](#3211-audit-components-metadata)
      - [3.2.1.2 Process execution and termination events](#3212-process-execution-and-termination-events)
      - [3.2.1.3 Remote script execution activity](#3213-remote-script-execution-activity)
      - [3.2.1.4 File transfer activity](#3214-file-transfer-activity)
      - [3.2.2 FileTransferWindowAppLog.log](#322-filetransferwindowapploglog)
      - [3.2.2.1 File transfer session initialization](#3221-file-transfer-session-initialization)
      - [3.2.3 LogFile.log](#323-logfilelog)
      - [3.2.3.1 User consent and approval workflow](#3231-user-consent-and-approval-workflow)
      - [3.2.3.2 Network connectivity and communication](#3232-network-connectivity-and-communication)
      - [3.2.3.3 Client email](#3233-client-email)
  - [4. Volatile artifacts](#4-volatile-artifacts)
    - [4.1 Extension-based execution (browser)](#41-extension-based-execution-browser)
      - [What to look for?](#what-to-look-for-1)
    - [4.2 Agent-based execution (installed service)](#42-agent-based-execution-installed-service)
      - [What to look for?](#what-to-look-for-2)
    - [4.3 Behavioral pattern comparison](#43-behavioral-pattern-comparison)
  - [5. Detection rules and collection targets](#5-detection-rules-and-collection-targets)

---

## 1. Technical overview

High-level description of the tool’s purpose, functionality, and operating behavior.

| Section | Content |
|---------|---------|
| Description | Zoho Assist – Browser Extension is a browser-based remote support component that enables Zoho Assist remote desktop sessions directly from a web browser. It is designed to facilitate on-demand remote support by bridging the browser environment with a local Zoho Assist agent installed on the endpoint. |
| Execution Model | The **Zoho Assist browser extension** does not operate as a full remote access tool on its own; therefore, the installation or execution of **native Zoho Assist agents** is required to enable full functionality.<br>The tool can be executed or abused in **three different operational modes**, depending on how the attacker leverages the extension and associated agents:<br><br>**1. Browser extension – Victim-initiated outbound connection** (Data exfiltration scenario)<br>• The attacker abuses the browser extension–initiated functionality to establish an outbound connection from the compromised machine to Zoho Assist cloud infrastructure.<br>• This connection can be leveraged to abuse built-in capabilities such as **file transfer**, enabling data exfiltration directly from the victim system.<br><br>**2. Quick installation (on-demand agent)**<br>• Enables **temporary remote control** of the compromised system.<br>• Does not expose the full feature set of Zoho Assist.<br>• Still allows: **Remote desktop control and File transfer capabilities**.<br><br>**3. Agent installation – Attacker-initiated remote control** (Unattended access scenario)<br>• The attacker installs a **persistent Zoho Assist unattended agent** on the victim machine.<br>• The attacker connects from their own system to Zoho Assist cloud infrastructure.<br>• The cloud service brokers the session, allowing the attacker to **remotely control the victim system at any time** without further user interaction.|
| Tactics & Techniques | TA0001 - Initial Access  <br>• T1133 - External Remote Services  <br><br>TA0003 - Persistence  <br>• T1547.001 - Registry Run Keys / Startup Folder  <br>• T1053 - Scheduled Task/Job  <br>• T1543 - Create or Modify System Process (service)  <br><br>TA0011 - Command and Control  <br>• T1071.001 - Web Protocols (HTTPS)  <br>• T1219 - Remote Access Software  <br>• T1573 - Encrypted Channel (TLS/WebRTC) |
| Privileges | User-level (can escalate to SYSTEM if installed as service) |
| OS | Windows, Linux, macOS (agent + browser extension) |
| Network | Typically:<br>• TCP/443 (HTTPS / WebSocket signaling)<br>• UDP dynamic ports (screen/audio streaming when enabled)<br>• Domains: `*.zohoassist.com`, `assist.zoho.eu`, `ft*.zohoassist.com`|

---

## 2. Summary table of artifacts


### Non-volatile artifacts

Mode A - Quick installation (on-demand agent)

| OS | Source | Artifact | Indicator |
|----|--------|----------|-----------|
| Windows | Browser profile | `C:\Users\<USER>\AppData\Local\Google\Chrome\User Data\Default\Extensions\<EXTENSION_ID>\`<br>`C:\Users\<USER>\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\<EXTENSION_ID>\`<br>`C:\Users\<USER>\AppData\Roaming\Mozilla\Firefox\Profiles\<PROFILE>\extensions\` | Installed Zoho Assist extension directory containing manifest and JS payloads |
| Windows | Browser config | `C:\Users\<USER>\AppData\Local\Google\Chrome\User Data\Default\Preferences`<br>`C:\Users\<USER>\AppData\Local\Microsoft\Edge\User Data\Default\Preferences`<br>`C:\Users\<USER>\AppData\Roaming\Mozilla\Firefox\Profiles\<PROFILE>\prefs.js` | Extension install state, timestamps, enable/disable status |
| Windows | Browser storage | `C:\Users\<USER>\AppData\Local\Google\Chrome\User Data\Default\IndexedDB\`<br>`C:\Users\<USER>\AppData\Local\Microsoft\Edge\User Data\Default\IndexedDB\`<br>`C:\Users\<USER>\AppData\Roaming\Mozilla\Firefox\Profiles\<PROFILE>\storage\default\` | WebRTC session data, temporary connection state |
Windows| Quick installation |`C:\Users\<USER>\AppData\Local\ZohoMeeting`<br>`C:\Program Files (x86)\ZohoMeeting`| Main folder |
Windows| Logs |`C:\Users\<USER>\AppData\Local\ZohoMeeting\log`| Session logs and execution traces
 | 

Mode B - Agent installation (attacker-initiated / persistent access)

| OS | Source | Artifact | Indicator |
|----|--------|----------|-----------|
| Windows | File system | `C:\Program Files (x86)\ZohoMeeting\UnAttended\ZohoMeeting\ZMAgent.exe` | Main agent binary |
| Windows | File system | `C:\Program Files (x86)\ZohoMeeting\UnAttended\ZohoMeeting\Version.txt` | Version |
| Windows | Registry | `HKLM\SYSTEM\ROOT\<ControlSet>\Services\Zoho Assist-Unattended Support`<br>`HKLM\SOFTWARE\ROOT\Classes\CLSID\{A1D8C690-705E-40BA-9A89-F76A36B2E9CA}\InprocServer32`|
Windows| Agent installation |`C:\Users\<USER>\AppData\Local\ZohoMeeting` <br> `C:\Program Files (x86)\ZohoMeeting\UnAttended` <br> `C:\ProgramData\ZohoMeeting`
Windows| Logs |`C:\Users\<USER>\AppData\Local\ZohoMeeting\log`<br> `C:\ProgramData\ZohoMeeting\log`| Session logs and execution 
Windows| Scripts |`C:\ProgramData\ZohoMeeting\scripts`| Scripts deployed and executed via Zoho Assist remote scripting functionality
Windows| Settings |`C:\ProgramData\ZohoMeeting\Settings.conf`| Configuration file 
Windows| Proxy |`C:\ProgramData\ZohoMeeting\Proxy.Conf`| Proxy configuration

## 3. Non-volatile artifacts

Persistent data the tool writes to disk, including configuration files, logs, system files, and other persistent data created.

### 3.1 Browser Extension IDs (Chrome, Edge, Firefox)

Within forensic analysis of non-volatile artifacts, **browser extension IDs** are a critical element. They define the directory structure used to store extensions inside user profiles and are essential for identifying and correlating installed extensions across different environments.

---

#### Chromium-based browsers (Chrome and Edge)

In Chromium-based browsers such as Google Chrome and Microsoft Edge, extension IDs:

- Are deterministic and derived from the extension’s public key
- Remain stable for the same extension installed from the same source
- The same ID allows direct correlation between Chrome and Edge profiles  
- Even after partial deletion, remnants may still exist in file system artifacts or backups  
- The extension name and metadata can be identified using the Chrome Web Store by querying the extension ID directly:

  https://chromewebstore.google.com/detail/\<ExtensionID>


##### Example extension ID (case provided)

```
ieinjhnflpkoheailbgaickpoaehjoal
```

##### Typical installation path
```
C:\Users\<USER>\AppData\Local\Google\Chrome\User Data\Default\Extensions
C:\Users\<USER>\AppData\Local\Microsoft\Edge\User Data\Default\Extensions
``` 

#### Mozilla Firefox
In Mozilla Firefox, the extension system is fundamentally different:

- Does not use Chromium-style deterministic IDs
- Extension IDs cannot be directly correlated with Chromium-based browsers  
- Extension identifiers are usually:
  - UUIDs (`{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`)
  - Or custom string-based identifiers defined by the developer

> The application is not available for **:contentReference[oaicite:0]{index=0}**, and therefore it does not generate or interact with Firefox-specific extension artifacts, identifiers, or profile-based storage structures.  
> As a result, no Firefox extension ID, installation directory, or browser integration artifacts can be observed or analyzed in relation to this tool within Firefox environments.  

### 3.2 Log Artifacts

#### Service and GUI logs

The directories below contain **persistent log files generated by Zoho Assist native components**, covering agent lifecycle events, GUI activity, remote session handling, file transfer operations, and session auditing.

```
C:\Users\<USER>\AppData\Local\ZohoMeeting\log
C:\ProgramData\ZohoMeeting\log
```

These locations store detailed forensic artifacts that allow reconstruction of remote access sessions, user consent, enabled capabilities, and actions performed during the session.

#### What to look for?

#### 3.2.1 SessionAuditReport_`<SessionID>`.log
The file provides a **chronological log of actions performed** during a single session.
<br><br>

Use the numeric value as a Zoho Assist Session ID.

> SessionAuditReport_4261321824.log

The file provides a high‑fidelity, chronological log of actions performed during a single session.

#### 3.2.1.1 Audit components metadata
- Identifies the exact auditing binary
- Confirms product version and build
- Distinguishes unattended agent sessions from attended/browser‑based sessions
  
```
Application Name : Session Audit
Version          : 2026.4.20.0
ProcessPath      : C:\Program Files (x86)\ZohoMeeting\UnAttended\ZohoMeeting\SessionAudit.exe
BuildTimeStamp   : Apr 20 2026
```
#### 3.2.1.2 Process execution and termination events
- Evidence of remote command execution
  
**Search for:**
-  `Process Launch`
-  `Process Terminate`

```
Process Launch    : cmd.exe
Process Launch    : wevtutil.exe
Process Launch    : auditpol.exe
Process Launch    : ScriptLauncher.exe
Process Terminate : cmd.exe
```

> [!IMPORTANT]: 
> The presence of ScriptLauncher.exe indicates Remote Script Execution functionality.
> This directly correlates with script artifacts located at: `C:\ProgramData\ZohoMeeting\scripts`


#### 3.2.1.3 Remote script execution activity
- Evidence of remote command execution
  
**Search for:**
-  `Process Launch`

#### 3.2.1.4 File transfer activity
- Evidence of the file transfer module
  
**Search for:**
-  `ZAFileTransfer`

```
Process Launch           : ZAFileTransfer.exe
Foreground Active Window : The ZAFileTransfer window was opened
```

#### 3.2.2 FileTransferWindowAppLog.log
The file provides a file transfer–related activity occurring during a Zoho Assist session.

<br><br>

#### 3.2.2.1 File transfer session initialization
- Evidence of the file transfer workflow is initiated.
  
**Search for:**
-  `AssistAgentDialog`

```
AssistAgentDialog::Starting file transfer dialog
Zb Permit protocol Received
```

#### 3.2.3 LogFile.log
The file provides a session lifecycle events.
<br>

#### 3.2.3.1 User consent and approval workflow
- The log records user‑visible consent dialogs and responses.

```
Permission Dialog shown. User clicked: 0
Customer declined the remote control request
```

#### 3.2.3.2 Network connectivity and communication
- The log records network initialization and communication with Zoho Assist infrastructure.

**Search for:**
-  `Connection`

```
Creating WebSocket Connection
Direct SSL Connection
assist.zoho.eu
```

#### 3.2.3.3 Client email
- The log records client identity attributes associated with a Zoho Assist session.

**Search for:**
-  `displayName`
-  `emailId`
-  `client_details`
```
"client_details":{"zsoid":20114154884,"clientId":424028000000063008,"clientRole":0,"isCustomer":false,"displayName":"mail%40gmail.com","emailId":"mail@gmail.com","zuid":20081347388},"is_unauth_session":false,"client_properties":{"CLIENT_ID":424028000000063008,"VIEW_ONLY_ACCESS":true,"PRESENTER":false,"APPROVAL_STATUS":0}
```

## 4. Volatile artifacts

Evidence produced during the tool’s execution, such as processes, network connections, session activity, temporary files, and other live data.

**Volatile data is the primary source of truth**. Unlike other tools, Zoho Assist may leave limited or no strong persistence artifacts depending on deployment mode (extension vs agent).  

Therefore, **network telemetry correlated with process execution is the most critical evidence** to identify:
- Active remote control sessions  
- Command and Control (C2) communication  
- Data exfiltration channels  
The following PowerShell command provides the **highest-value triage output**,correlating network connections with executing processes:

```
powershell Get-NetTCPConnection | ForEach-Object {
 $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
 [PSCustomObject]@{
 LocalAddress = $_.LocalAddress
 LocalPort = $_.LocalPort
 RemoteAddress = $_.RemoteAddress
 RemotePort = $_.RemotePort
 State = $_.State
 ProcessName = $proc.Name
 PID = $_.OwningProcess
 }
} | Format-Table -AutoSize
```

### 4.1 Extension-based execution (browser)

Identifies the compromised device and the account used to manage it.
- Connections originate from browser processes (e.g., msedge.exe, chrome.exe)
- Multiple simultaneous TLS connections
- Use of distributed infrastructure (CDNs, relays, cloud IPs)

```
10.66.0.10   57341   185.230.212.219  443   Established   ZMAgent   
10.66.0.10   57340   185.20.209.127   443   Established   ZohoURSService 
10.66.0.10   57339   138.2.130.153    443   Established   ZMAgent 
```

#### What to look for?

- Browser process maintaining multiple outbound TLS connections
- Connections to non-standard or low-reputation IPs
- Persistent ESTABLISHED sessions without user browsing activity

### 4.2 Agent-based execution (installed service)
- Dedicated process (e.g., ZMAgent.exe)
- Single or limited persistent connection
- Direct communication with relay/middleman server

```
10.66.0.10   57341   185.230.212.219  443   Established   ZMAgent  
```

#### What to look for?

- A single long-lived TLS connection
- Process name clearly linked to ZMAgent or ZohoURSService
- Stable remote IP (relay server)

### 4.3 Behavioral pattern comparison

| Feature | Extension Mode | Agent Mode |
|--------|--------------|-----------|
| Process | Browser (`msedge`, `chrome`, `firefox`) | Dedicated binary (`ZMAgent.exe` or `ZohoURSService`) |
| Connection pattern | Multiple simultaneous outbound connections | Single or few persistent connections |
| Network behavior | Distributed endpoints (CDN, cloud, relay mix) | Direct connection to relay/middleman server |
| Traffic type | WebRTC / WebSocket over HTTPS (blended traffic) | Persistent TLS tunnel |
| Visibility | Low (masquerades as normal browser traffic) | High (distinct process and connection) |
| Stability of remote IP | Variable (multiple IPs) | Stable (same relay IP) |
| Detection difficulty | High (requires behavioral analysis) | Moderate (signature + network correlation) |

## 5. Detection rules and collection targets

This section documents the files and rules generated to enhance forensic analysis of Zoho Assist activity. These detection artifacts are designed to identify suspicious behaviors, unauthorized remote access attempts, and persistence mechanisms associated with revsocks.

- [win_system_service_install_remote_access_software.yml](https://github.com/SigmaHQ/sigma/blob/34c5d66c22bbe41fe701cb6341d78ce324e6b24a/rules/windows/builtin/system/service_control_manager/win_system_service_install_remote_access_software.yml#L50)
- [dns_query_win_remote_access_software_domains_non_browsers.yml](https://github.com/SigmaHQ/sigma/blob/34c5d66c22bbe41fe701cb6341d78ce324e6b24a/rules/windows/dns_query/dns_query_win_remote_access_software_domains_non_browsers.yml#L12)