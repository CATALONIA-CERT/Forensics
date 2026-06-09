# getscreen.me

- [getscreen.me](#getscreenme)
  - [1. Technical overview](#1-technical-overview)
  - [2. Summary table of artifacts](#2-summary-table-of-artifacts)
    - [Non-volatile artifacts](#non-volatile-artifacts)
  - [3. Non-volatile artifacts](#3-non-volatile-artifacts)
    - [3.1 Browser Extension IDs (Chrome, Edge, Firefox)](#31-browser-extension-ids-chrome-edge-firefox)
      - [Chromium-based browsers (Chrome and Edge)](#chromium-based-browsers-chrome-and-edge)
        - [Example extension ID (case provided)](#example-extension-id-case-provided)
        - [Typical installation path](#typical-installation-path)
      - [Mozilla Firefox](#mozilla-firefox)
    - [3.2 Log Artifacts – ProgramData](#32-log-artifacts--programdata)
      - [Service and GUI logs](#service-and-gui-logs)
      - [What to look for?](#what-to-look-for)
      - [3.2.1 Device identification (link host to attacker account)](#321-device-identification-link-host-to-attacker-account)
      - [3.2.2 Remote session details (attacker infrastructure \& activity)](#322-remote-session-details-attacker-infrastructure--activity)
      - [3.2.3 File transfer / exfiltration](#323-file-transfer--exfiltration)
      - [3.2.4 Connection status and behavior](#324-connection-status-and-behavior)
  - [4. Volatile artifacts](#4-volatile-artifacts)
    - [4.1 Extension-based execution (browser)](#41-extension-based-execution-browser)
      - [What to look for?](#what-to-look-for-1)
    - [4.2 Agent-based execution (installed service)](#42-agent-based-execution-installed-service)
      - [What to look for?](#what-to-look-for-2)
    - [4.3 Behavioral pattern comparison](#43-behavioral-pattern-comparison)
  - [5. Detection rules and collection targets](#5-detection-rules-and-collection-targets)
  - [6. References](#6-references)

---

## 1. Technical overview

High-level description of the tool’s purpose, functionality, and operating behavior.

| Section | Content |
|---------|---------|
| Description | Getscreen.me - Cloud-based remote desktop and remote access tool that enables browser-controlled sessions without complex network configuration. Provides screen sharing, remote control, file transfer, and unattended access via persistent agent. |
| Execution Model | The tool can be abused in **two distinct operational modes**, depending on how the attacker deploys it:<br><br>**1. Browser extension - Victim-initiated outbound connection (data exfiltration scenario)**<br>• The attacker installs or tricks the user into installing a **browser extension** or lightweight agent on the compromised machine.<br>• On the attacker side, a **Getscreen binary or web console** is used to manage sessions.<br>• The victim machine establishes an **outbound connection to Getscreen infrastructure**, which is then bridged to the attacker.<br>• This allows:<br>  - Remote screen access<br>  - File transfer / data exfiltration<br>  - Command execution via UI interaction<br><br>**2. Agent installation - Attacker-initiated remote control (unattended access scenario)**<br>• The attacker installs a **persistent Getscreen agent** on the victim machine (service/daemon).<br>• The attacker connects from their own machine (browser or binary client) to the Getscreen cloud.<br>• The cloud service brokers the session, allowing the attacker to **remotely control the victim system at any time**.<br><br>In both cases, communication is mediated via Getscreen infrastructure, making direct attribution harder and bypassing NAT/firewall restrictions.<br> |
| Tactics & Techniques | TA0001 - Initial Access  <br>• T1133 - External Remote Services  <br><br>TA0003 - Persistence  <br>• T1547.001 - Registry Run Keys / Startup Folder  <br>• T1053 - Scheduled Task/Job  <br>• T1543 - Create or Modify System Process (service)  <br><br>TA0011 - Command and Control  <br>• T1071.001 - Web Protocols (HTTPS)  <br>• T1219 - Remote Access Software  <br>• T1573 - Encrypted Channel (TLS/WebRTC) |
| Privileges | User-level (can escalate to SYSTEM if installed as service) |
| OS | Windows, Linux, macOS (agent + browser extension) |
| Network | Typically:  <br>• TCP/443 (primary HTTPS/WebRTC signaling)  <br>• UDP dynamic ports (WebRTC media)  <br>• Domains: `*.getscreen.me` |

---

## 2. Summary table of artifacts


### Non-volatile artifacts

Mode A - Browser-based execution (victim-initiated)

| Source | Artifact | Indicator |
|--------|----------|-----------|
| Browser profile | `C:\Users\<USER>\AppData\Local\Google\Chrome\User Data\Default\Extensions\<EXTENSION_ID>\`<br>`C:\Users\<USER>\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\<EXTENSION_ID>\`<br>`C:\Users\<USER>\AppData\Roaming\Mozilla\Firefox\Profiles\<PROFILE>\extensions\` | Installed Getscreen extension directory containing manifest and JS payloads |
| Browser config | `C:\Users\<USER>\AppData\Local\Google\Chrome\User Data\Default\Preferences`<br>`C:\Users\<USER>\AppData\Local\Microsoft\Edge\User Data\Default\Preferences`<br>`C:\Users\<USER>\AppData\Roaming\Mozilla\Firefox\Profiles\<PROFILE>\prefs.js` | Extension install state, timestamps, enable/disable status |
| Browser storage | `C:\Users\<USER>\AppData\Local\Google\Chrome\User Data\Default\IndexedDB\`<br>`C:\Users\<USER>\AppData\Local\Microsoft\Edge\User Data\Default\IndexedDB\`<br>`C:\Users\<USER>\AppData\Roaming\Mozilla\Firefox\Profiles\<PROFILE>\storage\default\` | WebRTC session data, temporary connection state |

Mode B - Agent-based execution (attacker-initiated / persistent access)

| Source | Artifact | Indicator |
|--------|----------|-----------|
| File system | `C:\Program Files\Getscreen\getscreend.exe` | Main agent binary |
| File system | `C:\Users\<USER>\AppData\Local\Getscreen\settings.txt` | Device ID, session configuration |
| File system | `C:\ProgramData\Getscreen.me\logs` | Session logs and execution traces |
| Registry | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Getscreen.me`<br>`HKLM\SYSTEM\<ControlSet>\Control\SafeBoot\Network\Getscreen.me`<br>`HKLM\SYSTEM\<ControlSet>\Services\Getscreen.me`<br>`HKLM\SYSTEM\<ControlSet>\Services\Getscreen.me\Security`<br>`HKU\<SID>\Software\GetScreen\Getscreen.me` | User configuration and identifiers |

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


##### Example extension ID (case provided)

```
iaohfhfkcdddhmpmonkhhblodjfolfmf
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

> The application is not available for Mozilla Firefox, and therefore it does not generate or interact with Firefox-specific extension artifacts, identifiers, or profile-based storage structures.  
>
> As a result, no Firefox extension ID, installation directory, or browser integration artifacts can be observed or analyzed in relation to this tool within Firefox environments.  
>

### 3.2 Log Artifacts – ProgramData

#### Service and GUI logs

The directory below contains **persistent log files generated by the Getscreen agent**, including GUI activity, service lifecycle events, and remote session metadata.

```
C:\ProgramData\Getscreen.me\logs
```

This file acts similarly to a **user interface activity log**, capturing:

- Session lifecycle
- Remote connection details
- User/account identifiers
- Configuration and capability flags
- File transfer events
- Remote access mode (control vs connect)

#### What to look for?

#### 3.2.1 Device identification (link host to attacker account)
Identifies the compromised device and the account used to manage it.

**Search for:**
- Attacker device id: `event-permanent-device-id`
- Attacker account associated: `event-permanent-login-success`
- Attacker machine hostname: `event-settings (name)`

```
06:30:06.457 INFO Gui send event event-permanent-login-success: '{"value":"someone@somemail.com"}'
06:30:06.457 INFO Gui send event event-permanent-device-id: '{"value":"<numerical_id>"}'
06:30:06.457 INFO Gui send event event-settings: '{"value":{"name":"HOSTNAME"}}'
```

#### 3.2.2 Remote session details (attacker infrastructure & activity)
Contains critical information about remote sessions, including attacker IP, location, browser, and session timing.

**Search for:**
- Attacker public IP: `event-session-info`
```
06:30:06.457 INFO Gui send event event-session-info: '{"active":false,"ip":"x.x.x.x","country":"Germany","region":"Saxony","city":"Falkenstein","browser":"Chrome","link":"https://go.getscreen.me/zdk-2sz-rai","login":"srvdrgv dvdrvrds","start":1776853455.0,"stop":1776853485.0,"mode":"control"}'
```

#### 3.2.3 File transfer / exfiltration
Indicates files being transferred from the victim system (potential data exfiltration).

**Search for:**
- Destination path for trasnferred files: `event-notify-upload`

```
06:46:39.911 INFO Gui send event event-notify-upload: '{"value":"C:\\Path\\to\\final\\folder\\name_exfiltrated_file"}'
```

#### 3.2.4 Connection status and behavior
Tracks connection attempts, successful connections, and failures.

**Search for:**
- Destination path for trasnferred files: `event-application-status`

```
06:30:06.440 INFO Gui send event event-application-status: '{"value":"connecting"}'
06:30:06.457 INFO Gui send event event-application-status: '{"value":"connect"}'
06:45:27.657 INFO Gui send event event-application-status: '{"value":"active"}'
06:48:38.261 INFO Gui send event event-application-status: '{"value":"error"}'
```

## 4. Volatile artifacts

Evidence produced during the tool’s execution, such as processes, network connections, session activity, temporary files, and other live data.

**Volatile data is the primary source of truth**. Unlike other tools, Getscreen may leave limited or no strong persistence artifacts depending on deployment mode (extension vs agent).  

Therefore, **network telemetry correlated with process execution is the most critical evidence** to identify:
- Active remote control sessions  
- Command and Control (C2) communication  
- Data exfiltration channels  
The following PowerShell command provides the **highest-value triage output**,correlating network connections with executing processes:

```powershell
Get-NetTCPConnection | ForEach-Object {
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
10.66.0.27   57341   148.251.219.3   443   Established   msedge   7632
10.66.0.27   57340   49.13.208.86    443   Established   msedge   7632
10.66.0.27   57339   51.89.95.37     443   Established   msedge   7632
```

#### What to look for?

- Browser process maintaining multiple outbound TLS connections
- Connections to non-standard or low-reputation IPs
- Persistent ESTABLISHED sessions without user browsing activity

### 4.2 Agent-based execution (installed service)
- Dedicated process (e.g., getscreen.exe)
- Single or limited persistent connection
- Direct communication with relay/middleman server

```
10.66.0.200   49609   162.55.165.163   443   Established   getscreen   7956
```

#### What to look for?

- A single long-lived TLS connection
- Process name clearly linked to Getscreen
- Stable remote IP (relay server)

### 4.3 Behavioral pattern comparison

| Feature | Extension Mode | Agent Mode |
|--------|--------------|-----------|
| Process | Browser (`msedge`, `chrome`, `firefox`) | Dedicated binary (`getscreen.exe`) |
| Connection pattern | Multiple simultaneous outbound connections | Single or few persistent connections |
| Network behavior | Distributed endpoints (CDN, cloud, relay mix) | Direct connection to relay/middleman server |
| Traffic type | WebRTC / WebSocket over HTTPS (blended traffic) | Persistent TLS tunnel |
| Visibility | Low (masquerades as normal browser traffic) | High (distinct process and connection) |
| Stability of remote IP | Variable (multiple IPs) | Stable (same relay IP) |
| Detection difficulty | High (requires behavioral analysis) | Moderate (signature + network correlation) |

## 5. Detection rules and collection targets

This section documents the files and rules generated to enhance forensic analysis of Getscreen activity. These detection artifacts are designed to identify suspicious behaviors, unauthorized remote access attempts, and persistence mechanisms associated with revsocks.

- [getscreen_processes_sigma.yml (magicsword-io)](https://github.com/magicsword-io/LOLRMM/blob/main/detections/sigma/getscreen_processes_sigma.yml)
- [getscreen_network_sigma.yml (magicsword-io)](https://github.com/magicsword-io/LOLRMM/blob/main/detections/sigma/getscreen_network_sigma.yml)
- [Getscreen.tkape (CATALONIA-CERT)](https://github.com/CATALONIA-CERT/Forensics/blob/main/Outputs/tkapes/Getscreen.tkape)
- [ChromiumExtensionsMetadata.tkape (CATALONIA-CERT)](https://github.com/CATALONIA-CERT/Forensics/blob/main/Outputs/tkapes/ChromiumExtensionsMetadata.tkape)

## 6. References

N/A
