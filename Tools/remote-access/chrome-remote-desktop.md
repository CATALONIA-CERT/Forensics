# chrome remote desktop

- [chrome remote desktop](#chrome-remote-desktop)
  - [1. Technical overview](#1-technical-overview)
  - [2. Summary table of artifacts](#2-summary-table-of-artifacts)
    - [Non-volatile artifacts](#non-volatile-artifacts)
  - [3. Non-volatile artifacts](#3-non-volatile-artifacts)
    - [3.1 Extension ID (Chrome)](#31-extension-id-chrome)
    - [3.2 Installation Artifacts](#32-installation-artifacts)
    - [3.3 Log Artifacts](#33-log-artifacts)
      - [3.3.1 Windows Event Log (Application.evtx)](#331-windows-event-log-applicationevtx)
      - [3.3.2 Windows Event Log (System.evtx)](#332-windows-event-log-systemevtx)
  - [4. Volatile artifacts](#4-volatile-artifacts)
    - [4.1 Remote Support mode (attended session)](#41-remote-support-mode-attended-session)
      - [What to look for?](#what-to-look-for)
    - [4.2 Remote Access mode (unattended / persistent service)](#42-remote-access-mode-unattended--persistent-service)
      - [What to look for?](#what-to-look-for-1)
    - [4.3 Behavioral pattern comparison](#43-behavioral-pattern-comparison)
  - [5. Detection rules and collection targets](#5-detection-rules-and-collection-targets)
  - [6. References](#6-references)

---

## 1. Technical overview

High-level description of the tool's purpose, functionality, and operating behavior.

| Section | Content |
|---------|---------|
| Description | Chrome Remote Desktop is a remote access tool developed by Google, distributed as a Chrome browser extension (`inomeogfingihgjfjlpeplalcfajhgai`) paired with a native host component. It enables both on-demand attended remote support sessions and persistent unattended access to managed machines, communicating exclusively over HTTPS to Google-controlled relay infrastructure. |
| Execution Model | Chrome Remote Desktop can be leveraged in **two distinct operational modes** depending on adversary intent:<br><br>**1. Remote Support – Attended session (victim-initiated)**<br>• The victim (or attacker with local access) initiates a support session from the Chrome extension.<br>• A temporary native host component is invoked and an outbound connection is established to Google relay infrastructure.<br>• The session is active only while the browser extension is running; no persistent service is installed.<br><br>**2. Remote Access – Unattended access (persistent service)**<br>• A persistent native host service (`chromoting`) is installed on the target machine and registered as a Windows service.<br>• The attacker authenticates via their Google account from any device and initiates sessions at any time without victim interaction.<br>• The service survives reboots and provides full remote desktop control. |
| Tactics & Techniques | TA0003 - Persistence<br>• T1543.003 - Create or Modify System Process: Windows Service<br>• T1547.001 - Registry Run Keys / Startup Folder<br><br>TA0008 - Lateral Movement<br>• T1021 - Remote Services<br><br>TA0010 - Exfiltration<br>• T1041 - Exfiltration Over C2 Channel<br><br>TA0011 - Command and Control<br>• T1071.001 - Web Protocols (HTTPS)<br>• T1219 - Remote Access Software |
| Privileges | User-level for attended sessions; SYSTEM-level service for unattended access |
| OS | Windows, Linux, macOS |
| Network | • TCP/443 (HTTPS / WebRTC signaling)<br>• Domains: `remotedesktop.google.com`, `*.remotedesktop.google.com`, Google relay IP ranges |

---

## 2. Summary table of artifacts

### Non-volatile artifacts

Mode A – Remote Support (attended session)

| OS | Source | Artifact | Indicator |
|----|--------|----------|-----------|
| Windows | Browser profile | `C:\Users\<USER>\AppData\Local\Google\Chrome\User Data\Default\Extensions\inomeogfingihgjfjlpeplalcfajhgai\` | Installed Chrome Remote Desktop extension directory |
| Windows | Event log | `C:\Windows\System32\winevt\Logs\Application.evtx` | Source: `chromoting` — EventID 5 (access code generated), EventID 1/4 (connection established), EventID 2 (connection ended) |
| macOS | Browser profile | `~/Library/Application Support/Google/Chrome/Default/Extensions/inomeogfingihgjfjlpeplalcfajhgai/` | Extension installation directory |
| Linux | Browser profile | `~/.config/google-chrome/Default/Extensions/inomeogfingihgjfjlpeplalcfajhgai/` | Extension installation directory |

Mode B – Remote Access (unattended / persistent service)

| OS | Source | Artifact | Indicator |
|----|--------|----------|-----------|
| Windows | File system | `C:\Program Files (x86)\Google\Chrome Remote Desktop\` | Main installation directory |
| Windows | File system | `C:\ProgramData\Google\Chrome Remote Desktop\host.json` | Host configuration: host_id, host name, authorized Google account |
| Windows | Registry | `HKLM\SYSTEM\CurrentControlSet\Services\chromoting` | Persistent service registration |
| Windows | Registry | `HKCU\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.google.chrome.remotedesktop` | Native messaging host manifest pointer |
| Windows | Registry | `HKLM\SOFTWARE\Google\Chrome Remote Desktop\paired-clients\` | Paired client identifiers and secrets |
| Windows | Event log | `C:\Windows\System32\winevt\Logs\Application.evtx` | Source: `chromoting` — EventID 1/4 (connection established), EventID 2 (connection ended) |
| Windows | Event log | `C:\Windows\System32\winevt\Logs\System.evtx` | EventID 7045 (service creation), EventID 7040 (service start type changed to auto) |
| Linux | Service dir | `/opt/google/chrome-remote-desktop/` | Main installation directory |
| Linux | Browser profile | `~/.config/google-chrome/Default/Extensions/inomeogfingihgjfjlpeplalcfajhgai/` | Extension installation directory |

---

## 3. Non-volatile artifacts

Persistent data the tool writes to disk, including configuration files, logs, system files, and other persistent data created.

### 3.1 Extension ID (Chrome)

Within forensic analysis of non-volatile artifacts, the **browser extension ID** is a critical element. Chrome Remote Desktop's extension ID is deterministic, derived from its public key, and remains stable across all Chromium-based browsers and installations.

```
inomeogfingihgjfjlpeplalcfajhgai
```

**Typical installation paths:**

```
C:\Users\<USER>\AppData\Local\Google\Chrome\User Data\Default\Extensions\inomeogfingihgjfjlpeplalcfajhgai\
C:\Users\<USER>\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\inomeogfingihgjfjlpeplalcfajhgai\
~/Library/Application Support/Google/Chrome/Default/Extensions/inomeogfingihgjfjlpeplalcfajhgai/    # macOS
~/.config/google-chrome/Default/Extensions/inomeogfingihgjfjlpeplalcfajhgai/                         # Linux
```

File creation and modification timestamps within these directories can be used to determine the installation time and the last period of activity. Even after partial deletion, remnants may persist in file system artifacts or browser backups.

> The Chrome Remote Desktop extension is only available for Chromium-based browsers (Chrome and Edge). No Firefox extension exists, and therefore no Firefox-specific extension artifacts will be present.

### 3.2 Installation Artifacts

**Windows – Remote Access service installation:**

```
C:\Program Files (x86)\Google\Chrome Remote Desktop\
```

Key binaries within this directory:

| Binary | Description |
|--------|-------------|
| `remoting_host.exe` | Main native host process managing session lifecycle |
| `remoting_native_messaging.exe` | Communication bridge between the browser extension and the native host |
| `remote_assistance_host.exe` | Host component invoked during attended Remote Support sessions |
| `remoting_desktop.exe` | Desktop capture and management during active sessions |
| `remote_security_key.exe` | Security key forwarding component |

**Host configuration file (Remote Access mode only):**

```
C:\ProgramData\Google\Chrome Remote Desktop\host.json
```

This file is created when Remote Access (unattended access) is configured. It contains the authoritative identity of the host and the Google account authorized to connect.

| Field | Description |
|-------|-------------|
| `host_id` | Unique identifier for this host registration |
| `host_name` | Name assigned to the host during setup |
| `host_secret_hash` | HMAC-SHA256 derived from the PIN and host_id |
| Authorized Google account | The Gmail account permitted to initiate unattended sessions |

> [!IMPORTANT]
> `host.json` is the primary artifact for identifying **who set up Remote Access** and **which Google account** controls unattended access to the machine. Its creation timestamp establishes when persistent access was configured.

**Registry keys:**

```
HKLM\SYSTEM\CurrentControlSet\Services\chromoting
HKCU\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.google.chrome.remotedesktop
HKLM\SOFTWARE\Google\Chrome Remote Desktop\paired-clients\
```

**Linux:**

```
/opt/google/chrome-remote-desktop/
~/.config/google-chrome/Default/Extensions/inomeogfingihgjfjlpeplalcfajhgai/
```

### 3.3 Log Artifacts

#### 3.3.1 Windows Event Log – Application.evtx

```
C:\Windows\System32\winevt\Logs\Application.evtx
```

The `chromoting` event source logs session lifecycle events within the Windows Application event log. These are the most direct forensic indicators for remote session activity.

**EventID 5 – Access Code Generated**

Logged when a user generates a temporary one-time access code to initiate a Remote Support session. Marks the moment the attended session workflow was started.

**Search for:**
- Source: `chromoting`
- EventID: `5`

**EventID 1 / 4 – Connection Established**

Logged when a remote session is successfully initiated. Includes the remote user's Google account email address, enabling attribution.

**Search for:**
- Source: `chromoting`
- EventID: `1` or `4`

**EventID 2 – Connection Ended**

Logged when a remote session is terminated. Includes a unique session ID and the remote user's email.

**Search for:**
- Source: `chromoting`
- EventID: `2`

> [!IMPORTANT]
> Correlate EventID 1/4 and EventID 2 timestamps to reconstruct session duration and frequency. EventID 1/4 entries contain the **remote user's Google account email**, which is the primary identity indicator for attributing who initiated the session.

#### 3.3.2 Windows Event Log – System.evtx

```
C:\Windows\System32\winevt\Logs\System.evtx
```

The Windows System event log records service installation and configuration changes performed when Remote Access is set up on the machine.

| EventID | Source | Description | DFIR Value |
|---------|--------|-------------|------------|
| 7045 | Service Control Manager | A new service was installed in the system | Confirms installation of `Chrome Remote Desktop Service`; timestamp establishes when persistent access was first enabled |
| 7040 | Service Control Manager | The start type of a service was changed | Confirms the service was set to auto-start, indicating intentional persistence configuration |

**What to look for?**

- EventID 7045 with service name `Chrome Remote Desktop Service` or binary path referencing `remoting_host.exe`
- Temporal correlation of EventID 7045 with the known incident timeline
- EventID 7040 confirming the service was configured for automatic startup

---

## 4. Volatile artifacts

Evidence produced during the tool's execution, such as processes, network connections, session activity, temporary files, and other live data.

**Volatile data is the primary source of truth for active session detection.** Chrome Remote Desktop communicates exclusively over TCP/443 to Google-managed relay infrastructure. Traffic is distinguishable only through destination IP range analysis or DNS resolution — not by port or protocol anomaly — making behavioral correlation essential.

The following PowerShell command provides the **highest-value triage output**, correlating active network connections with executing processes:

```powershell
Get-NetTCPConnection | ForEach-Object {
  $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
  [PSCustomObject]@{
    LocalAddress  = $_.LocalAddress
    LocalPort     = $_.LocalPort
    RemoteAddress = $_.RemoteAddress
    RemotePort    = $_.RemotePort
    State         = $_.State
    ProcessName   = $proc.Name
    PID           = $_.OwningProcess
  }
} | Format-Table -AutoSize
```

### 4.1 Remote Support mode (attended session)

- Connection originates from the browser process (`chrome.exe`)
- Session is temporary; no persistent service is installed
- Traffic is indistinguishable from normal HTTPS browsing at the network layer
- `remote_assistance_host.exe` spawned as a child process of `chrome.exe`

```
10.66.0.10   54321   142.250.x.x   443   Established   chrome                  <PID>
10.66.0.10   54322   142.250.x.x   443   Established   remote_assistance_host  <PID>
```

#### What to look for?

- `chrome.exe` maintaining long-lived ESTABLISHED connections to Google IP ranges
- DNS queries to `remotedesktop.google.com` or `*.remotedesktop.google.com`
- `remote_assistance_host.exe` spawned as a child of `chrome.exe` rather than `services.exe`
- Persistent ESTABLISHED connections without corresponding user browsing activity

### 4.2 Remote Access mode (unattended / persistent service)

- Dedicated host process (`remoting_host.exe`) running as a Windows service (`chromoting`)
- Long-lived persistent outbound connection to Google relay infrastructure
- Process is active at all times, including before any attacker-initiated session
- Parent process is `services.exe`

```
10.66.0.10   55210   142.250.x.x   443   Established   remoting_host  <PID>
```

#### What to look for?

- `remoting_host.exe` running as a child of `services.exe`
- `chromoting` service present in the Windows service list (`Get-Service chromoting`)
- Persistent ESTABLISHED connection to Google IP ranges maintained by `remoting_host.exe`
- Presence of `C:\ProgramData\Google\Chrome Remote Desktop\host.json`
- Service creation timestamp relative to the known incident timeline

### 4.3 Behavioral pattern comparison

| Feature | Remote Support Mode | Remote Access Mode |
|---------|--------------------|-----------------------|
| Process | Browser (`chrome.exe`) + child `remote_assistance_host.exe` | Dedicated service binary (`remoting_host.exe`) |
| Parent process | `chrome.exe` | `services.exe` |
| Connection pattern | Session-scoped; terminates when browser closes | Persistent; active at all times |
| Service installation | None | `chromoting` Windows service; survives reboot |
| Configuration file | None | `C:\ProgramData\Google\Chrome Remote Desktop\host.json` |
| Session initiation | Requires victim presence in browser | Attacker-initiated at any time without victim interaction |
| Persistence | None | Registry service key (`HKLM\...\Services\chromoting`) |
| Detection difficulty | High (blends with normal browser traffic) | Moderate (dedicated process with identifiable parent and service entry) |

---

## 5. Detection rules and collection targets

This section documents the files and rules to enhance forensic analysis of Chrome Remote Desktop activity. These detection artifacts are designed to identify unauthorized remote access attempts, session activity, and persistence mechanisms.

- [win_system_service_install_remote_access_software.yml](https://github.com/SigmaHQ/sigma/blob/34c5d66c22bbe41fe701cb6341d78ce324e6b24a/rules/windows/builtin/system/service_control_manager/win_system_service_install_remote_access_software.yml)
- [dns_query_win_remote_access_software_domains_non_browsers.yml](https://github.com/SigmaHQ/sigma/blob/34c5d66c22bbe41fe701cb6341d78ce324e6b24a/rules/windows/dns_query/dns_query_win_remote_access_software_domains_non_browsers.yml)

**Collection targets:**

```
C:\ProgramData\Google\Chrome Remote Desktop\host.json
C:\Windows\System32\winevt\Logs\Application.evtx
C:\Windows\System32\winevt\Logs\System.evtx
HKLM\SYSTEM\CurrentControlSet\Services\chromoting
HKCU\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.google.chrome.remotedesktop
HKLM\SOFTWARE\Google\Chrome Remote Desktop\paired-clients\
C:\Users\<USER>\AppData\Local\Google\Chrome\User Data\Default\Extensions\inomeogfingihgjfjlpeplalcfajhgai\
```

---

## 6. References

- https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide
- https://medium.com/@chaoskist/chrome-remote-desktop-rmm-investigation-c61f8545da26
- https://warroom.rsmus.com/chromoting-acccess/
