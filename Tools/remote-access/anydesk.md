# anydesk

- [anydesk](#anydesk)
  - [1. Technical overview](#1-technical-overview)
  - [2. Summary table of artifacts](#2-summary-table-of-artifacts)
    - [Non-volatile artifacts](#non-volatile-artifacts)
    - [Volatile artifacts](#volatile-artifacts)
  - [3. Non-volatile artifacts](#3-non-volatile-artifacts)
    - [3.1 Configuration files (AppData)](#31-configuration-files-appdata)
      - [system.conf and user.conf](#systemconf-and-userconf)
      - [service.conf](#serviceconf)
    - [3.2 Log artifacts – AppData (ad.trace)](#32-log-artifacts--appdata-adtrace)
      - [What to look for?](#what-to-look-for)
      - [3.2.1 Session login and remote participant identification](#321-session-login-and-remote-participant-identification)
      - [3.2.2 External IP address and local Client ID](#322-external-ip-address-and-local-client-id)
      - [3.2.3 File transfer events](#323-file-transfer-events)
    - [3.3 Log artifacts – ProgramData (installed version only)](#33-log-artifacts--programdata-installed-version-only)
      - [3.3.1 Incoming connections (connection\_trace.txt)](#331-incoming-connections-connection_tracetxt)
      - [3.3.2 Service log file (ad\_svc.trace)](#332-service-log-file-ad_svctrace)
    - [3.4 Printer driver artifacts (installed version only)](#34-printer-driver-artifacts-installed-version-only)
    - [3.5 Registry artifacts (installed version only)](#35-registry-artifacts-installed-version-only)
  - [4. Volatile artifacts](#4-volatile-artifacts)
    - [4.1 Portable execution (user process)](#41-portable-execution-user-process)
      - [What to look for?](#what-to-look-for-1)
    - [4.2 Installed service execution](#42-installed-service-execution)
      - [What to look for?](#what-to-look-for-2)
    - [4.3 Behavioral pattern comparison](#43-behavioral-pattern-comparison)
  - [5. Detection rules and collection targets](#5-detection-rules-and-collection-targets)
  - [6. References](#6-references)

---

## 1. Technical overview

High-level description of the tool's purpose, functionality, and operating behavior.

| Section | Content |
|---------|---------|
| Description | AnyDesk is a remote desktop and remote access tool that enables interactive or unattended control of systems, including screen sharing, file transfer, clipboard synchronization, and session recording. It can operate as a **portable executable** (no installation required) or as a **persistent installed service**, making it a frequent choice for legitimate remote administration and a common Living-off-the-Land tool abused for unauthorized access and data exfiltration. |
| Execution Model | The tool can be deployed in **two distinct operational modes**, each leaving a different artifact footprint:<br><br>**1. Portable mode – No installation (user-level execution)**<br>• The attacker drops or executes `AnyDesk.exe` directly without installation.<br>• Artifacts are limited to the **AppData** user profile (`ad.trace`, `*.conf`).<br>• No service is created; no ProgramData logs; no registry service key.<br>• The process runs under the user context, not SYSTEM.<br>• This mode leaves a **minimal persistent footprint** and is harder to detect post-execution.<br><br>**2. Installed mode – Persistent service (attacker-initiated unattended access)**<br>• AnyDesk is installed on the victim system, creating a **Windows service** (`AnyDesk`).<br>• A **printer driver** (`AnyDesk Printer`) is installed during setup.<br>• Session logs are written to **ProgramData** in addition to AppData.<br>• Registry keys are created for the service and installation metadata.<br>• The attacker can reconnect at any time without user interaction via the **password-protected unattended access** configured in `service.conf`.<br><br>In both modes, communication is relayed through AnyDesk infrastructure, masking direct attacker attribution behind relay nodes. Direct peer-to-peer connections are also possible when firewall rules permit. |
| Tactics & Techniques | **TA0010 – Exfiltration**<br>• T1567.002 – Exfiltration Over Web Services<br><br>**TA0011 – Command and Control**<br>• T1219 – Remote Access Software<br><br>**TA0003 – Persistence** *(installed mode)*<br>• T1543.003 – Create or Modify System Process: Windows Service<br><br>**TA0005 – Defense Evasion**<br>• T1036 – Masquerading (portable binary may be renamed) |
| Privileges | Not required for portable mode. Administrator privileges needed for installation (service creation and printer driver). Unattended access is protected by a configurable password stored in `service.conf`. |
| OS | Windows, Linux, macOS (agent available for all platforms) |
| Network | • **TCP/6568** – Direct peer-to-peer connection (AnyDesk proprietary protocol)<br>• **TCP/443** – HTTPS relay communication (fallback / default)<br>• **TCP/80** – HTTP relay communication (fallback)<br>• **UDP/50001–50003** – Discovery and relay negotiation<br>• Domains: `*.anydesk.com`, relay nodes (e.g., `relay-*.anydesk.com`) |

---

## 2. Summary table of artifacts

Overview table summarizing the main artifacts, where they reside, and what information they contain.

### Non-volatile artifacts

Mode A – Portable execution (user-level, no installation)

| Source | Artifact | Indicator |
|--------|----------|-----------|
| AppData – configuration | `C:\Users\<USER>\AppData\Roaming\AnyDesk\system.conf`<br>`C:\Users\<USER>\AppData\Roaming\AnyDesk\user.conf` | Session file transfer paths revealing local username; connection preferences and default directories |
| AppData – configuration | `C:\Users\<USER>\AppData\Roaming\AnyDesk\service.conf` | Password hash (`ad.anynet.pwd_hash`) and salt (`ad.anynet.pwd_salt`) for unattended access; TLS certificate and private key |
| AppData – UI log | `C:\Users\<USER>\AppData\Roaming\AnyDesk\ad.trace` | Remote participant IP address, AnyDesk Client ID, relay node ID, session timestamps, file transfer events |

Mode B – Installed service (persistent, attacker-initiated)

| Source | Artifact | Indicator |
|--------|----------|-----------|
| AppData – configuration | `C:\Users\<USER>\AppData\Roaming\AnyDesk\*.conf` | Same as Mode A; also present under the service account profile |
| AppData – UI log | `C:\Users\<USER>\AppData\Roaming\AnyDesk\ad.trace` | Same as Mode A |
| ProgramData – connection log | `C:\ProgramData\AnyDesk\connection_trace.txt` | Incoming connection log: remote Client ID, authorization method (user approval or password), timestamps |
| ProgramData – service log | `C:\ProgramData\AnyDesk\ad_svc.trace` | Service-level session log: local external IP, local Client ID, remote Client ID, remote IP, relay node, connection timestamps |
| Registry | `HKLM\SOFTWARE\Clients\Media\AnyDesk`<br>`HKLM\SYSTEM\CurrentControlSet\Services\AnyDesk` | Installation date (key last write time); service configuration (binary path, start type, account) |
| File system – printer driver | `C:\Users\<USER>\AppData\Roaming\AnyDesk\printer_driver\` | Printer driver installation directory; reveals the user account that triggered the installation |
| Windows Event Log | `C:\Windows\System32\winevt\Logs\Microsoft-Windows-DeviceSetupManager\Admin.evtx` | EID 112 – AnyDesk Printer device setup; confirms installed version was run under a specific user |

### Volatile artifacts

| Source | Artifact | Indicator |
|--------|----------|-----------|
| Process | `AnyDesk.exe` running in Task Manager / process list | User-level or SYSTEM process depending on deployment mode |
| Network connections | `Get-NetTCPConnection` / `netstat` | Outbound TCP/6568 (direct) or TCP/443 (relay) to AnyDesk infrastructure; persistent `ESTABLISHED` connection during active session |
| Active service | `sc query AnyDesk` / `Get-Service AnyDesk` | `AnyDesk` service in `RUNNING` state (installed mode only) |
| Memory | Process memory of `AnyDesk.exe` | Active session state, Client ID, relay connection handles, clipboard buffer content |

---

## 3. Non-volatile artifacts

Persistent data written to disk by AnyDesk, including configuration files, session logs, registry entries, and printer driver artifacts.

### 3.1 Configuration files (AppData)

AnyDesk stores its configuration in the user's AppData profile, regardless of whether it is running in portable or installed mode.

**Configuration directory:**
```
C:\Users\<USER>\AppData\Roaming\AnyDesk\
```

---

#### system.conf and user.conf

These files store AnyDesk operational settings and, critically, **default file transfer paths** that reveal the local username and working directories used during remote sessions.

**Key variables of forensic interest:**

| Variable | Content | Key value |
|----------|---------|------------|
| `ad.session.remote_browser_start_path` | Default path on the **target** system for file upload/download via AnyDesk | Reveals the username and home directory of the victim system |
| `ad.session.local_browser_start_path` | Default path on the **connecting** (attacker) system | Reveals the username and working directory of the attacker system |

> **Key value:** These path variables allow analysts to reconstruct the direction of file transfers (attacker → victim or victim → attacker) and identify the usernames involved on both sides of the session, even when no dedicated file transfer log exists.

---

#### service.conf

This file is the most sensitive configuration artifact. It stores the **unattended access password** (as a SHA-256 hash with salt), as well as the AnyDesk **TLS certificate** and **private key** used to authenticate the installation.

```
C:\Users\<USER>\AppData\Roaming\AnyDesk\service.conf
```

**Example content:**
```
ad.anynet.cert=-----BEGIN CERTIFICATE-----\nMIICqDCCA...mOi\n-----END CERTIFICATE-----\n
ad.anynet.pkey=-----BEGIN PRIVATE KEY-----\nMIIEvgIBA...aum\n-----END PRIVATE KEY-----\n
ad.anynet.pwd_hash=5344a7a23b2abb6314c0fa0ae9e20339a62814b7c2fa494b49c897ad63c0d7c9
ad.anynet.pwd_salt=81279b158b9f3e2e697baef91f35b35b
```

| Field | Description | Key value |
|-------|-------------|------------|
| `ad.anynet.pwd_hash` | SHA-256 hash of the unattended access password | Confirms unattended access was configured; hash may be crackable offline |
| `ad.anynet.pwd_salt` | Salt used in password hashing | Required for offline password cracking attempts |
| `ad.anynet.cert` | TLS certificate unique to this AnyDesk installation | Can be used to fingerprint and correlate this specific installation across multiple systems |
| `ad.anynet.pkey` | Private key corresponding to the certificate | Confirms the identity of this specific AnyDesk instance |

> **Key value:** The presence of `pwd_hash` and `pwd_salt` is a definitive indicator that **unattended access was deliberately configured**, enabling the attacker to reconnect without any user interaction. This is the primary persistence mechanism of AnyDesk in attack scenarios.

---

### 3.2 Log artifacts – AppData (ad.trace)

The file `ad.trace` acts as the **user interface activity log** for AnyDesk. It records critical session details including the IP address of the remote participant, their AnyDesk Client ID, relay node information, and file transfer events.

```
C:\Users\<USER>\AppData\Roaming\AnyDesk\ad.trace
```

This log captures:
- Session lifecycle (connect, disconnect)
- Remote participant network identity (IP and Client ID)
- Local external IP address and relay assignment
- File transfer operations (source and destination paths)
- Connection authorization method

#### What to look for?

#### 3.2.1 Session login and remote participant identification

Identifies who connected to this machine and from which IP address.

**Search for:** `Logged in`

```
info 2022-09-28 12:39:26.845  lsvc  9952  9944  21  anynet.any_socket  - Client-ID: 442226597 (FPR: 8e28a2a25b30).
info 2022-09-28 12:39:26.845  lsvc  9952  9944  21  anynet.any_socket  - Logged in from 12.xx.xx.21:59562 on relay 80e496c0.
```

| Field | Content |
|-------|---------|
| `Client-ID` | AnyDesk ID of the **remote connecting participant** |
| `FPR` | Fingerprint of the remote client's TLS certificate |
| `Logged in from` | **Public IP address and port** of the remote participant |
| `on relay` | Relay node ID used for this session |

---

#### 3.2.2 External IP address and local Client ID

Identifies the local machine's public IP and its AnyDesk Client ID as seen from the outside.

**Search for:** `External address` and `Client-ID`

```
info 2022-09-28 12:38:44.222  lsvc  9952  9944  3  anynet.relay_conn        - External address: 34.xx.xx.123:50831.
info 2022-09-28 12:38:44.222  lsvc  9952  9944  3  anynet.main_relay_conn   - Main relay ID: 80e496c0y.
info 2022-09-28 12:38:44.225  lsvc  9952  9944  3  anynet.main_relay_conn   - Detected 2 new networks.
info 2022-09-28 12:38:44.228  lsvc  9952  9944  2  anynet.connection_mgr    - Main relay connection established.
info 2022-09-28 12:38:44.228  lsvc  9952  9944  2  anynet.connection_mgr    - New user data. Client-ID: 294433414.
```

| Field | Content |
|-------|---------|
| `External address` | **Public IP and port** of the local (victim) machine |
| `Main relay ID` | Relay node assigned to this session |
| `Client-ID` (connection_mgr) | AnyDesk ID of the **local machine** |

> **Correlation tip:** The `Client-ID` values in `ad.trace` (local) and `connection_trace.txt` / `ad_svc.trace` (remote) can be cross-correlated to reconstruct the full session topology: which AnyDesk ID connected from which IP, through which relay, at what time.

---

#### 3.2.3 File transfer events

Records files transferred during the remote session, including source paths on the local system.

**Search for:** `file_transfer` and `prepare_task`

```
info 2022-09-28 12:41:20.001  front  6252  496  app.prepare_task         - Preparing files in 'C:\Users\lab\Downloads'.
info 2022-09-28 12:41:20.001  front  6252  496  app.local_file_transfer  - Preparation of 1 files completed (io_ok)
```

> **Key value:** The path `C:\Users\lab\Downloads` reveals both the **username** (`lab`) and the directory from which files were staged for transfer. This is a direct indicator of data exfiltration activity and can be correlated with filesystem artifacts (USN Journal, Prefetch) to identify specific files transferred.

---

### 3.3 Log artifacts – ProgramData (installed version only)

The ProgramData directory is only populated when AnyDesk is installed as a service. These logs capture **service-level** session information with higher fidelity than the AppData logs.

```
C:\ProgramData\AnyDesk\
```

---

#### 3.3.1 Incoming connections (connection_trace.txt)

`connection_trace.txt` records details of every **incoming connection** accepted by the local system. It also records **how the connection was authorized**: whether a local user manually approved it, or whether it was accepted automatically via the unattended access password.

```
C:\ProgramData\AnyDesk\connection_trace.txt
```

**Search for:** `Incoming`

```
Incoming 2022-09-28, Passwd    547911884  547911884
Incoming 2022-09-28, 12:39  User  442226597  442226597
```

| Field | Content | Key value |
|-------|---------|------------|
| `Passwd` | Connection authorized via unattended access password | Confirms the attacker used the pre-configured password — no user interaction occurred |
| `User` | Connection manually approved by a local user | Indicates a user was present and accepted the connection |
| Numeric IDs | Remote participant's AnyDesk Client ID (repeated twice) | Can be correlated with `ad_svc.trace` and `ad.trace` entries |

> **Key value:** The `Passwd` authorization method is the most significant indicator: it confirms the attacker had **pre-configured unattended access** and could connect silently without victim interaction. This directly supports the persistence hypothesis.

---

#### 3.3.2 Service log file (ad_svc.trace)

`ad_svc.trace` is the **AnyDesk service log**. It records the same session information as `ad.trace` but from the service context (running as SYSTEM), providing an independent and higher-integrity record of session activity.

```
C:\ProgramData\AnyDesk\ad_svc.trace
```

**Search for:** Local host external IP and Client ID → `External address` and `Client-ID`

```
info 2022-08-23 10:20:11.969  gsvc  4628  3528  3  anynet.relay_conn      - External address: 34.xx.xx.123:46798.
info 2022-08-23 10:20:11.969  gsvc  4628  3528  3  anynet.main_relay_conn - Main relay ID: 8d9e4ddf
info 2022-08-23 10:20:11.984  gsvc  4628  3528  1  fiber.scheduler        - Spawning root fiber 18.
info 2022-08-23 10:20:11.984  gsvc  4628  3528  2  anynet.connection_mgr  - Main relay connection established.
info 2022-08-23 10:20:11.984  gsvc  4628  3528  2  anynet.connection_mgr  - New user data. Client-ID: 609579424.
```

**Search for:** Remote host external IP and Client ID → `Logged in` and `Client-ID`

```
info 2022-08-23 10:20:17.125  gsvc  4628  3528  23  anynet.any_socket - Client-ID: 547911884 (FPR: 67a8dcc336a1).
info 2022-08-23 10:20:17.125  gsvc  4628  3528  23  anynet.any_socket - Logged in from 12.xx.xx.21:41314 on relay ad3345a7.
```

| Log Entry | Content |
|-----------|---------|
| Local `External address` | Public IP of the **victim** (local) machine |
| Local `Client-ID` (connection_mgr) | AnyDesk ID of the **victim** machine |
| Remote `Client-ID` (any_socket) | AnyDesk ID of the **attacker** (remote) machine |
| Remote `Logged in from` | **Public IP and port** of the **attacker** |
| `FPR` | Fingerprint of the attacker's AnyDesk TLS certificate — consistent across sessions from the same installation |

---

### 3.4 Printer driver artifacts (installed version only)

By default, AnyDesk installs a **virtual printer driver** (`AnyDesk Printer`) during setup. This provides an additional installation artifact and reveals the user account under which the installation was performed.

**Printer driver directory:**
```
C:\Users\<USER>\AppData\Roaming\AnyDesk\printer_driver\
```

The user-specific path of this directory identifies the **account that triggered the AnyDesk installation**, which may differ from the account used for remote sessions.

**Associated event log:**
```
C:\Windows\System32\winevt\Logs\Microsoft-Windows-DeviceSetupManager\Admin.evtx
```

**Search for:** `AnyDesk Printer` device installation — **Event ID 112**

```
"Prop_ContainerId":"4AB05252-BFD6-C6E9-7D0E-58FBD6159485",
"Prop_DeviceName":"AnyDesk Printer",
"Prop_PropertyCount":42,
"Prop_TaskCount":4,
"Prop_WorkTime_MilliSeconds":46
```

> **Key value:** EID 112 in the DeviceSetupManager log provides a timestamped record of the printer driver installation, which closely correlates with the **AnyDesk installation time**. In the absence of a dedicated installer log, this is a reliable secondary timestamp source.

---

### 3.5 Registry artifacts (installed version only)

When AnyDesk is installed as a service, two registry keys are created that can help establish **installation date** and confirm the presence of the application.

**Registry hive location (offline):**
```
C:\Windows\System32\Config\SOFTWARE
C:\Windows\System32\Config\SYSTEM
```

**Keys of interest:**

| Registry Key | Content | Key value |
|---|---|---|
| `HKLM\SOFTWARE\Clients\Media\AnyDesk` | Application registration | **Last write time** approximates the installation date |
| `HKLM\SYSTEM\CurrentControlSet\Services\AnyDesk` | Service definition: binary path, start type (`Auto`/`Manual`), account (`LocalSystem`) | Confirms AnyDesk was installed as a persistent service; start type `Auto` indicates it survives reboots |

> **Key value:** The **last write timestamp** of `HKLM\SOFTWARE\Clients\Media\AnyDesk` is one of the most reliable indicators of installation date when installer logs or Prefetch files are unavailable. A service start type of `2` (Automatic) confirms the intent for persistent, long-term access.

---

## 4. Volatile artifacts

Evidence produced during AnyDesk execution, such as running processes, network connections, active sessions, and live memory content.

**Volatile data is critical for active session detection.** Unlike other tools, AnyDesk may leave minimal strong persistence artifacts in portable mode. Network telemetry correlated with process execution is the most reliable real-time evidence to identify active remote control sessions.

The following PowerShell command provides the **highest-value triage output**, correlating network connections with executing processes:

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

---

### 4.1 Portable execution (user process)

When AnyDesk runs as a portable binary, the process executes under the **user context** and establishes one or more outbound connections to AnyDesk relay infrastructure.

- Connection originates from `AnyDesk.exe` running under a user account (not SYSTEM)
- Typically a single persistent outbound TLS connection on TCP/443 (relay) or TCP/6568 (direct)
- No associated Windows service entry

```
10.66.0.27   52341   relay-us-east.anydesk.com   443   Established   AnyDesk   5284
```

#### What to look for?

- `AnyDesk.exe` process running under a user account with a persistent outbound connection
- Connection to TCP/443 or TCP/6568 toward AnyDesk relay infrastructure
- Binary located in an unusual path (e.g., `%TEMP%`, `%APPDATA%`, `C:\Users\<USER>\Downloads\`) rather than `C:\Program Files (x86)\AnyDesk\`
- No corresponding `AnyDesk` service in `sc query` output

---

### 4.2 Installed service execution

When AnyDesk is installed, a dedicated service (`AnyDesk`) runs as **SYSTEM** and maintains a persistent background connection to the relay infrastructure, even when no active remote session is in progress.

```
10.66.0.200   49781   relay-eu.anydesk.com   443   Established   AnyDesk   1108
```

#### What to look for?

- `AnyDesk.exe` process running as **SYSTEM** (PID owned by `services.exe`)
- A single long-lived TLS connection on TCP/443 or TCP/6568, stable even between remote sessions
- `AnyDesk` service present and in `RUNNING` state:

```powershell
Get-Service AnyDesk | Select-Object Name, Status, StartType
```

```
Name      Status  StartType
AnyDesk   Running Automatic
```

- Correlate the service start time with the `ad_svc.trace` first entry timestamp

---

### 4.3 Behavioral pattern comparison

| Feature | Portable Mode | Installed Service Mode |
|---------|--------------|----------------------|
| Process | `AnyDesk.exe` (user context) | `AnyDesk.exe` (SYSTEM, child of `services.exe`) |
| Connection persistence | Active only while process is running | Always-on, survives reboots |
| Network behavior | Outbound TCP/443 or TCP/6568 to relay | Persistent TCP/443 or TCP/6568, stable relay IP |
| ProgramData logs | Not present | `connection_trace.txt`, `ad_svc.trace` |
| Registry service key | Not present | `HKLM\SYSTEM\...\Services\AnyDesk` |
| Printer driver | Not installed | `AnyDesk Printer` installed (EID 112) |
| Unattended access | Possible via `service.conf` in AppData | Default mechanism via `service.conf` |
| Binary location | Arbitrary / user-writable path | `C:\Program Files (x86)\AnyDesk\AnyDesk.exe` |
| Detection difficulty | High (portable, no service, minimal registry) | Moderate (service + registry + ProgramData logs) |

---

## 5. Detection rules and collection targets

This section documents the files and rules generated to enhance forensic analysis of AnyDesk activity. These detection artifacts are designed to identify suspicious behaviors, unauthorized remote access attempts, and persistence mechanisms associated with AnyDesk.

- [anydesk_processes_sigma.yml (magicsword-io)](https://github.com/magicsword-io/LOLRMM/blob/main/detections/sigma/anydesk_processes_sigma.yml)
- [anydesk_network_sigma.yml (magicsword-io)](https://github.com/magicsword-io/LOLRMM/blob/main/detections/sigma/anydesk_network_sigma.yml)
- [AnyDesk.tkape (EricZimmerman/KapeFiles)](https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/AnyDesk.tkape)

**Key Windows Event IDs for detection:**

| Event ID | Log | Description |
|----------|-----|-------------|
| EID 112 | Microsoft-Windows-DeviceSetupManager/Admin | AnyDesk Printer driver installation — confirms installed version |
| EID 7045 | System | AnyDesk service creation (`ServiceName: AnyDesk`) |
| EID 7036 | System | AnyDesk service state change (running/stopped) |
| EID 4688 / Sysmon EID 1 | Security / Sysmon | `AnyDesk.exe` process creation; command-line may reveal connection parameters |

**Threat hunting recommendations:**

- Alert on `AnyDesk.exe` executing from non-standard paths (`%TEMP%`, `%APPDATA%`, `Downloads`) — indicates portable/unauthorized deployment
- Hunt for outbound TCP/6568 connections from workstations — this port is exclusively used by AnyDesk direct connections and is not expected in most enterprise environments
- Monitor `C:\ProgramData\AnyDesk\connection_trace.txt` for entries with `Passwd` authorization — confirms silent unattended access without user interaction
- Search `service.conf` for the presence of `ad.anynet.pwd_hash` across all endpoints — any system with this value configured has unattended access enabled
- Correlate `ad.trace` / `ad_svc.trace` `Client-ID` values against known AnyDesk IDs from threat intelligence feeds
- Alert on `HKLM\SYSTEM\CurrentControlSet\Services\AnyDesk` creation events where AnyDesk is not part of the approved software inventory

---

## 6. References

- [AnyDesk – Official documentation](https://support.anydesk.com/knowledge/log-files)
- [LOLRMM – AnyDesk detection rules (magicsword-io)](https://github.com/magicsword-io/LOLRMM)
- [KAPE Target – AnyDesk.tkape (EricZimmerman)](https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/AnyDesk.tkape)
- [MITRE ATT&CK – T1219: Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [MITRE ATT&CK – T1567.002: Exfiltration Over Web Services](https://attack.mitre.org/techniques/T1567/002/)
- [MITRE ATT&CK – T1543.003: Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/)
- [DFIR.it – AnyDesk forensic artifacts analysis](https://dfir.it/blog/2021/09/anydesk-forensics/)
- [CATALONIA-CERT Forensics – Detection outputs and collection targets](https://github.com/CATALONIA-CERT/Forensics)
