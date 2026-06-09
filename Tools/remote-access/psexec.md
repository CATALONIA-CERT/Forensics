# psexec (Sysinternals)

- [psexec (Sysinternals)](#psexec-sysinternals)
  - [1. Technical overview](#1-technical-overview)
  - [2. Summary table of artifacts](#2-summary-table-of-artifacts)
    - [Non-volatile artifacts](#non-volatile-artifacts)
    - [Volatile artifacts](#volatile-artifacts)
  - [3. Non-volatile artifacts](#3-non-volatile-artifacts)
    - [3.1 Service artifacts](#31-service-artifacts)
    - [3.2 Event log artifacts](#32-event-log-artifacts)
      - [3.2.1 Source host – process execution traces](#321-source-host--process-execution-traces)
      - [3.2.2 Destination host – service installation and network access](#322-destination-host--service-installation-and-network-access)
      - [3.2.3 Authentication and logon traces](#323-authentication-and-logon-traces)
      - [3.2.4 SMB share access and lateral movement indicators](#324-smb-share-access-and-lateral-movement-indicators)
    - [3.3 Registry artifacts](#33-registry-artifacts)
      - [Source host – EULA acceptance key](#source-host--eula-acceptance-key)
      - [Destination host – PSEXESVC service key](#destination-host--psexesvc-service-key)
    - [3.4 File system artifacts](#34-file-system-artifacts)
      - [Destination host – service binary](#destination-host--service-binary)
      - [Source host – temporary key file](#source-host--temporary-key-file)
    - [3.5 Prefetch artifacts](#35-prefetch-artifacts)
    - [3.6 Amcache and Shimcache artifacts](#36-amcache-and-shimcache-artifacts)
    - [3.7 USN Journal artifacts](#37-usn-journal-artifacts)
    - [3.8 Scheduled task artifacts](#38-scheduled-task-artifacts)
    - [3.9 Lateral movement traces](#39-lateral-movement-traces)
  - [4. Volatile artifacts](#4-volatile-artifacts)
    - [4.1 Process execution and process tree](#41-process-execution-and-process-tree)
      - [What to look for?](#what-to-look-for)
    - [4.2 Active network connections](#42-active-network-connections)
      - [What to look for?](#what-to-look-for-1)
    - [4.3 Named pipes and IPC artifacts](#43-named-pipes-and-ipc-artifacts)
    - [4.4 Active sessions and SMB state](#44-active-sessions-and-smb-state)
    - [4.5 Memory indicators](#45-memory-indicators)
    - [4.6 Behavioral pattern comparison – source vs. destination host](#46-behavioral-pattern-comparison--source-vs-destination-host)
  - [5. Detection rules and collection targets](#5-detection-rules-and-collection-targets)
  - [6. References](#6-references)

---

## 1. Technical overview

High-level description of the tool's purpose, functionality, and operating behavior.

| Section | Content |
|---------|---------|
| Description | PsExec is a command-line utility from Microsoft Sysinternals designed for legitimate remote administration of Windows systems. It enables the execution of processes on remote machines without requiring manual installation of client software. Adversaries abuse PsExec to perform lateral movement, execute payloads on remote systems, escalate privileges, and transfer tools across the network — all using built-in Windows authentication and administrative shares. |
| Execution Model | PsExec operates across **two hosts** with distinct roles and artifact sets:<br><br>**Source host (attacker-controlled machine running psexec.exe)**<br>• The operator executes `psexec.exe` with target host, credentials, and command arguments.<br>• PsExec authenticates to the remote host via SMB (TCP/445).<br>• It uploads the `PSEXESVC.exe` service binary to the target's `ADMIN$` share (`C:\Windows\`).<br>• It connects to the Service Control Manager (SCM) over RPC (TCP/135) to create and start the `PSEXESVC` service.<br>• A named pipe is established for I/O redirection between source and remote process.<br><br>**Destination host (victim / target machine)**<br>• Receives `PSEXESVC.exe` via the `ADMIN$` administrative share.<br>• The `PSEXESVC` service is created, started, executes the requested command, then stops and self-deletes.<br>• The remotely executed process runs as a child of `PSEXESVC.exe`.<br>• Authentication, SMB access, service creation, and process execution events are all recorded on this host.<br><br>The binary is transient by design — `PSEXESVC.exe` is deleted from disk once execution completes, but the event log and registry trail persists. |
| Tactics & Techniques | **TA0002 – Execution**<br>• T1569.002 – System Services: Service Execution<br><br>**TA0003 – Persistence**<br>• T1136.002 – Create Account: Domain Account<br><br>**TA0004 – Privilege Escalation**<br>• T1543.003 – Create or Modify System Process: Windows Service<br><br>**TA0008 – Lateral Movement**<br>• T1021.002 – Remote Services: SMB/Windows Admin Shares<br>• T1570 – Lateral Tool Transfer |
| Privileges | **Source host:** Standard user (EULA registry key written); Administrator or Domain Admin credentials required to authenticate to the destination.<br>**Destination host:** Administrator-level access required; PSEXESVC runs as SYSTEM. |
| OS | Windows (all versions supporting SMB and the Windows Service Control Manager) |
| Network | • **TCP/445** – SMB (service binary transfer via ADMIN$, share access)<br>• **TCP/135** – RPC endpoint mapper (Service Control Manager communication)<br>• **TCP/High random port (≥1024)** – Dynamic RPC channel for service creation and named pipe I/O<br>• *In domain environments, additional Kerberos traffic occurs toward the Domain Controller (TCP/UDP 88).* |

---

## 2. Summary table of artifacts

Overview table summarizing the main artifacts, where they reside, and what information they contain.

### Non-volatile artifacts

| Source | Artifact | Indicator |
|--------|----------|-----------|
| Prefetch | `%SystemRoot%\Prefetch\PSEXEC.EXE-XXXXXXXX.pf`<br>`%SystemRoot%\Prefetch\PSEXESVC.EXE-XXXXXXXX.pf` | Execution count, last execution timestamp, referenced file paths for both the initiating binary and the remote service binary |
| Amcache | `%SystemRoot%\AppCompat\Programs\Amcache.hve` | Executable name, full path, SHA-1 hash, and first execution timestamp for `psexec.exe` and `PSEXESVC.exe` |
| Shimcache | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` | Execution presence and last modification timestamp of `psexec.exe`; `PSEXESVC.exe` may appear on destination host |
| Security Event Log (source) | `%SystemRoot%\System32\winevt\Logs\Security.evtx` | EID 4688 / 4689 – `psexec.exe` process creation and exit; EID 5156 – outbound connections on TCP/445 and TCP/135 |
| Security Event Log (destination) | `%SystemRoot%\System32\winevt\Logs\Security.evtx` | EID 4624 – network logon (Type 3); EID 4672 – special privilege assignment; EID 5140 – ADMIN$ and IPC$ share access; EID 5145 – share object access check (paths contain `PSEXESVC` and `C:\Windows`); EID 4656 / 4663 – handle to `PSEXESVC.exe`; EID 4660 / 4658 – deletion of `PSEXESVC.exe` |
| System Event Log (destination) | `%SystemRoot%\System32\winevt\Logs\System.evtx` | EID 7045 – `PSEXESVC` service installed; EID 7036 – service state changed (Running → Stopped) |
| Sysmon Event Log (source) | `%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx` | EID 1 – process creation for `psexec.exe` (includes full command line with remote host and executed command); EID 5 – process termination |
| Sysmon Event Log (destination) | `%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx` | EID 1 / 5 – `PSEXESVC.exe` process creation/termination and child process; EID 11 – file creation event for `PSEXESVC.exe` dropped in `C:\Windows\` |
| Registry – Services (destination) | `HKLM\SYSTEM\CurrentControlSet\Services\PSEXESVC` | Service key created at runtime; confirms service name, binary path (`%SystemRoot%\PSEXESVC.exe`), and service type |
| Registry – EULA (source) | `HKEY_USERS\<SID>\Software\Sysinternals\PsExec\EulaAccepted` | Value `1` indicates the EULA was accepted — confirms `psexec.exe` was run interactively on this host |
| File system (destination) | `C:\Windows\PSEXESVC.exe` | Service binary dropped on target; deleted post-execution but recoverable via Volume Shadow Copy, USN Journal, or memory acquisition |
| USN Journal | `$Extend\$UsnJrnl` (on destination host volume) | FileCreate and FileDelete records for `PSEXESVC.exe`; `PsExec-<SOURCE_HOSTNAME>-<RANDOM>.key` temporary key file |
| SMB network trace | PCAP / NDR telemetry | SMB2 `TREE_CONNECT` to `ADMIN$`; SMB2 `CREATE` / `WRITE` for `PSEXESVC.exe`; DCE/RPC `OpenSCManagerW`, `CreateServiceW`, `StartServiceW` calls visible in clear on unencrypted SMB |

### Volatile artifacts

| Source | Artifact | Indicator |
|--------|----------|-----------|
| Memory – process tree | Live memory / EDR telemetry | `wininit.exe → services.exe → PSEXESVC.exe → <remotely executed command>` |
| Memory – process | Live memory | `psexec.exe` in memory on source host with command-line arguments containing remote hostname, username, and executed payload |
| Network connections | `netstat` / `Get-NetTCPConnection` | Outbound connections from source to destination on TCP/445 and TCP/135; high-port dynamic RPC channel (TCP/≥1024) from source to destination |
| Active SMB sessions | `net session` / `Get-SmbSession` | Session from source host IP to destination over port 445 |
| Named pipes | `pipelist` / `Get-ChildItem \\.\pipe\` | `\PSEXESVC`, `\PSEXESVC-<hostname>-<pid>-stdin`, `\PSEXESVC-<hostname>-<pid>-stdout`, `\PSEXESVC-<hostname>-<pid>-stderr` |
| Active services | `sc query PSEXESVC` / `Get-Service PSEXESVC` | `PSEXESVC` in `RUNNING` state while remote command executes |
| USN Journal (volatile window) | `$Extend\$UsnJrnl` | `PsExec-<SOURCE_HOSTNAME>-XXXXXXXX.key` FileCreate entry |

---

## 3. Non-volatile artifacts

Persistent data written to disk by PsExec activity, including event logs, registry entries, file system remnants, and execution history artifacts.

### 3.1 Service artifacts

PsExec's most reliable and distinctive forensic trace on the **destination host** is the transient creation of the `PSEXESVC` Windows service. Even though the binary is deleted after execution, the **System Event Log entry always persists**.

**Service binary path:**
```
C:\Windows\PSEXESVC.exe
```

**Service key location (destination host):**
```
HKLM\SYSTEM\CurrentControlSet\Services\PSEXESVC
```

The service lifecycle produces the following **System Event Log sequence** on the destination host:

| Event ID | Source | Description |
|----------|--------|-------------|
| 7045 | Service Control Manager | A new service was installed: `PSEXESVC`, ImagePath: `%SystemRoot%\PSEXESVC.exe` |
| 7036 | Service Control Manager | The PSEXESVC service entered the **running** state |
| 7036 | Service Control Manager | The PSEXESVC service entered the **stopped** state |


**What to look for:**

- `ServiceName` field containing `PSEXESVC` (default) or a suspicious custom name when `-r` is used
- `ImagePath` resolving to `%SystemRoot%\<name>.exe` (always `C:\Windows\`)
- Tight temporal correlation between EID 7045 (install), 7036 (running), 7036 (stopped) — often within seconds

```
EID 7045  14:23:01  PSEXESVC  %SystemRoot%\PSEXESVC.exe  Type: Own Process
EID 7036  14:23:01  The PSEXESVC service entered the running state.
EID 7036  14:23:04  The PSEXESVC service entered the stopped state.
```

---

### 3.2 Event log artifacts

#### 3.2.1 Source host – process execution traces

On the host where `psexec.exe` is run, the following events are recorded when process auditing is enabled.

**Log location:**
```
%SystemRoot%\System32\winevt\Logs\Security.evtx
%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx
```

**Search for:**

- Process creation and termination of `psexec.exe`: `EID 4688 / 4689` (Security) or `EID 1 / 5` (Sysmon)

```
EID 4688  Subject: DOMAIN\attacker  Process Name: C:\Tools\PsExec.exe
EID 4689  Process Name: C:\Tools\PsExec.exe  Exit Status: 0x0
```

The **Sysmon EID 1** entry is the highest-value source-host artifact because it captures the **full command line**, including the remote host, account, and the command dispatched to the target:

```
EID 1 (Sysmon)
  Image:       C:\Tools\PsExec.exe
  CommandLine: psexec.exe \\192.168.1.50 -u DOMAIN\Administrator -p Password1 cmd.exe
  User:        DOMAIN\attacker
  ProcessId:   4812
  UtcTime:     2024-11-15 14:23:00.412
```

**Network filtering platform (source):**
- `EID 5156` – outbound connection to destination on TCP/445 and TCP/135

```
EID 5156  Application: psexec.exe  Direction: Outbound
          Destination: 192.168.1.50  Port: 445  Protocol: 6 (TCP)
EID 5156  Application: psexec.exe  Direction: Outbound
          Destination: 192.168.1.50  Port: 135  Protocol: 6 (TCP)
```

---

#### 3.2.2 Destination host – service installation and network access

On the **destination host**, PsExec activity is logged across the Security and System event logs.

**Log location:**
```
%SystemRoot%\System32\winevt\Logs\System.evtx
%SystemRoot%\System32\winevt\Logs\Security.evtx
%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx
```

**Sysmon EID 1 / 5 – PSEXESVC.exe process lifecycle:**

```
EID 1 (Sysmon)
  Image:    C:\Windows\PSEXESVC.exe
  User:     NT AUTHORITY\SYSTEM
  UtcTime:  2024-11-15 14:23:01.889

EID 5 (Sysmon)
  Image:    C:\Windows\PSEXESVC.exe
  UtcTime:  2024-11-15 14:23:04.002
```

**Sysmon EID 11 – PSEXESVC.exe file drop:**

```
EID 11 (Sysmon)
  TargetFilename: C:\Windows\PSEXESVC.exe
  CreationUtcTime: 2024-11-15 14:23:01.102
```

**Object access (Security log) – file handle and deletion:**

| Event ID | Description | Key Fields |
|----------|-------------|------------|
| EID 4656 | Handle to `C:\Windows\PSEXESVC.exe` requested | Process ID: `0x4` (SYSTEM); Access: `DELETE`, `ReadAttributes` |
| EID 4663 | Attempt to access `C:\Windows\PSEXESVC.exe` | Object Name: `C:\Windows\PSEXESVC.exe` |
| EID 4660 | Object deleted (PSEXESVC.exe removed) | Handle ID correlated with EID 4656 |
| EID 4658 | Handle closed | Handle ID correlated with EID 4656 |

> **Key value:** The EID 4656 → 4663 → 4660 → 4658 sequence with `Object Name: C:\Windows\PSEXESVC.exe` and `Process ID: 0x4 (SYSTEM)` constitutes a definitive trace of the service binary's creation and self-deletion.

---

#### 3.2.3 Authentication and logon traces

PsExec authenticates to the destination host using Windows credentials. The following logon events are generated on the **destination host**.

**Log location:**
```
%SystemRoot%\System32\winevt\Logs\Security.evtx
```

**Search for:**

- `EID 4624` – Successful network logon (Type 3) immediately before service installation
- `EID 4672` – Special privileges assigned to the authenticated account

```
EID 4624
  Logon Type:       3 (Network)
  Account Name:     Administrator
  Source Address:   192.168.1.10   (source host IP)
  Source Port:      49210
  Logon Process:    NtLmSsp / Kerberos

EID 4672
  Account Name:     Administrator
  Privileges:       SeBackupPrivilege, SeRestorePrivilege, SeDebugPrivilege...
```

> **Correlation tip:** The timestamp of EID 4624 will appear immediately before EID 7045 (service install). Correlating these two events across the same second window is strong evidence of PsExec-initiated lateral movement rather than an ordinary interactive logon.

---

#### 3.2.4 SMB share access and lateral movement indicators

PsExec uses the `ADMIN$` administrative share to transfer the `PSEXESVC.exe` binary and the `IPC$` share for named pipe communication.

**Log location:**
```
%SystemRoot%\System32\winevt\Logs\Security.evtx
```

**Search for:**

- `EID 5140` – Network share object accessed

```
EID 5140  (ADMIN$ access – binary transfer)
  Account Name:  Administrator
  Source Address: 192.168.1.10
  Share Name:    \\*\ADMIN$
  Share Path:    \??\C:\Windows

EID 5140  (IPC$ access – named pipe)
  Account Name:  Administrator
  Source Address: 192.168.1.10
  Share Name:    \\*\IPC$
```

- `EID 5145` – Network share object checked for client access (logged multiple times)

```
EID 5145
  Account Name:  Administrator
  Source Address: 192.168.1.10
  Share Path:    \??\C:\Windows        (contains "PSEXESVC")
  Share Path:    \\*\IPC$
```

> **Key value:** `EID 5140` with `Share Path: \??\C:\Windows` (rather than a user home directory or standard share) is an anomalous indicator. Combined with EID 7045 in the System log, this provides high-confidence confirmation of PsExec use for lateral movement.

---

### 3.3 Registry artifacts

PsExec leaves registry evidence on **both** the source and destination host.

#### Source host – EULA acceptance key

```
HKEY_USERS\<SID>\Software\Sysinternals\PsExec
  Value: EulaAccepted  REG_DWORD  0x1
```

- Written the **first time** `psexec.exe` is executed interactively on a host
- Persists indefinitely after execution
- If the key is absent, PsExec may have been run with the `-accepteula` command-line flag (non-interactive automation) or never run on this account before

| Artifact | Location | Key value |
|----------|----------|------------|
| EulaAccepted key | `HKEY_USERS\<SID>\Software\Sysinternals\PsExec` | Confirms `psexec.exe` was executed under this user account on this machine |
| Key last write time | Registry metadata | Approximates the earliest known use date of PsExec on this system under this user |

#### Destination host – PSEXESVC service key

```
HKLM\SYSTEM\CurrentControlSet\Services\PSEXESVC
  ImagePath:  %SystemRoot%\PSEXESVC.exe
  Type:       0x10 (Own Process)
  Start:      0x3  (Manual / demand start)
  ObjectName: LocalSystem
```

- Created at runtime by the SCM when PsExec registers the service
- May persist in the registry after execution if cleanup is incomplete, or may be deleted along with the binary
- Can survive in `HKLM\SYSTEM\ControlSet001\Services\PSEXESVC` within offline registry hives

> **Key value:** The presence of this key in a registry hive from a host that has no other administrative justification for the `PSEXESVC` service is a strong indicator of unauthorized lateral movement.

---

### 3.4 File system artifacts

#### Destination host – service binary

```
C:\Windows\PSEXESVC.exe
```

- Dropped via `ADMIN$` share during PsExec execution
- **Deleted automatically** after the remote command exits
- Recoverable via:
  - Volume Shadow Copies (`vssadmin list shadows`)
  - USN Journal FileCreate entry (name and timestamp remain even after deletion)
  - Memory acquisition (if process was still running)
  - Forensic file carving from unallocated space

#### Source host – temporary key file

```
C:\Windows\Temp\PsExec-<SOURCE_HOSTNAME>-XXXXXXXX.key
```

- Temporary mutual authentication key file created by PsExec on the **source** host
- Short-lived; may be deleted before acquisition
- USN Journal FileCreate entry persists and reveals the source hostname embedded in the filename

| File | Host | Persistence | Recovery Path |
|------|------|-------------|---------------|
| `PSEXESVC.exe` | Destination | Deleted post-execution | USN Journal, VSS, file carving |
| `PsExec-<HOST>-<RAND>.key` | Source | Short-lived temp file | USN Journal FileCreate record |
| `psexec.exe` | Source | Persistent (attacker-placed) | Standard file system, Prefetch, Amcache |

---

### 3.5 Prefetch artifacts

Prefetch files provide **execution timestamps and reference file lists** for both `psexec.exe` (source) and `PSEXESVC.exe` (destination).

**Prefetch location:**
```
%SystemRoot%\Prefetch\
```

| Prefetch File | Host | Key Information |
|---------------|------|-----------------|
| `PSEXEC.EXE-XXXXXXXX.pf` | Source | Last execution timestamp, execution count, referenced files (target systems may appear in volume path references) |
| `PSEXESVC.EXE-XXXXXXXX.pf` | Destination | Execution timestamp matching service install time; referenced child process paths |

**What to look for:**

- Execution count `> 1` on the source host suggests repeated lateral movement operations
- On the destination host, `PSEXESVC.EXE-*.pf` appearing in a Prefetch directory with a single or low execution count, correlated with EID 7045, confirms the service was executed
- Timestamps in Prefetch files should be correlated with Security EID 4688 and System EID 7045 to establish a unified timeline

> **Note:** Prefetch is **disabled by default on Windows Server** editions. If Prefetch files are absent on server targets, this is expected behavior and does not indicate artifact deletion.

---

### 3.6 Amcache and Shimcache artifacts

Both execution compatibility databases record evidence of `psexec.exe` and `PSEXESVC.exe` presence.

**Amcache location:**
```
%SystemRoot%\AppCompat\Programs\Amcache.hve
```

| Artifact | Key Information | Key value |
|----------|-----------------|------------|
| Amcache – `psexec.exe` entry (source) | Full path, SHA-1 hash, product name (`Sysinternals PsExec`), original file name, company (`Sysinternals`) | Confirms execution; hash enables reputation lookup and cross-host correlation |
| Amcache – `PSEXESVC.exe` entry (destination) | Full path (`C:\Windows\PSEXESVC.exe`), SHA-1 hash, first execution time | Links execution time with System EID 7045 |

**Shimcache location:**
```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```

| Artifact | Key Information | Key value |
|----------|-----------------|------------|
| Shimcache – `psexec.exe` (source) | Binary path, last modification time | Presence confirms `psexec.exe` was present on the system; does **not** confirm execution alone |
| Shimcache – `PSEXESVC.exe` (destination) | Binary path `C:\Windows\PSEXESVC.exe`, modification timestamp | Confirms the binary was placed in `C:\Windows\` — anomalous for any legitimate process |

> **Key value:** The SHA-1 hash from Amcache allows analysts to verify whether the binary matches the known-good Sysinternals PsExec hash or a renamed/modified variant. Deviation from the expected hash is a significant escalation indicator.

---

### 3.7 USN Journal artifacts

The NTFS USN Journal (`$Extend\$UsnJrnl`) records file system operations and persists **after file deletion**, providing evidence of transient files that no longer exist on disk.

**Journal location:**
```
<Volume Root>\$Extend\$UsnJrnl:$J
```

**Key records to search for:**

| Record Type | Filename Pattern | Host | Significance |
|-------------|-----------------|------|--------------|
| FileCreate | `PSEXESVC.exe` | Destination | Confirms binary was written to `C:\Windows\` at execution time |
| FileDelete | `PSEXESVC.exe` | Destination | Confirms self-deletion of the service binary |
| FileCreate | `PsExec-<HOSTNAME>-XXXXXXXX.key` | Source | Temporary mutual authentication key; hostname embedded in filename reveals source identity |

> **Key value:** The USN Journal is one of the most reliable sources for recovering evidence of `PSEXESVC.exe` when the file itself has been deleted and no VSS copies are available. The embedded hostname in the `.key` file can corroborate source-host attribution.

---

### 3.8 Scheduled task artifacts

No evidence identified for scheduled task artifacts created directly by default PsExec execution. PsExec does not create scheduled tasks as part of its standard operation.

> **Note:** Adversaries may combine PsExec with `schtasks.exe` to establish persistence on a remote host after gaining initial execution via PsExec. In such cases, task XML files would appear in `C:\Windows\System32\Tasks\` and `C:\Windows\Tasks\` on the destination host, and Sysmon EID 1 would capture the `schtasks.exe` command line including the `/s <REMOTE_HOST>` flag.

---

### 3.9 Lateral movement traces

The combination of artifacts across **source** and **destination** hosts establishes the lateral movement chain. The following table summarizes the cross-host evidence correlation.

| Timeline Point | Source Host Artifact | Destination Host Artifact |
|----------------|---------------------|--------------------------|
| PsExec launch | EID 4688 / Sysmon EID 1 (`psexec.exe`, full cmdline) | — |
| SMB connection | EID 5156 (TCP/445 outbound) | EID 5156 (TCP/445 inbound) |
| ADMIN$ access | — | EID 5140 (Share: `ADMIN$`, Path: `\??\C:\Windows`) |
| Binary drop | USN FileCreate (`PsExec-*.key`) | USN FileCreate (`PSEXESVC.exe`); Sysmon EID 11 |
| Authentication | — | EID 4624 (Type 3), EID 4672 (special privileges) |
| Service install | — | EID 7045 (`PSEXESVC`, `%SystemRoot%\PSEXESVC.exe`) |
| Service start | — | EID 7036 (running); Sysmon EID 1 (`PSEXESVC.exe`, SYSTEM) |
| Remote execution | Sysmon EID 5 (`psexec.exe` exits) | Sysmon EID 1 (child process under `PSEXESVC.exe`) |
| Cleanup | — | EID 4656/4660 (`PSEXESVC.exe` deleted); EID 7036 (stopped) |

---

## 4. Volatile artifacts

Evidence produced during active PsExec execution, captured from live system memory, network state, and real-time process monitoring.

**Volatile artifacts are time-critical.** The `PSEXESVC` service and its child processes exist only for the duration of the remote command. Named pipes, active sessions, and network connections disappear once execution completes. Live response or EDR telemetry must be collected during or immediately after execution.

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
        CommandLine   = (Get-WmiObject Win32_Process -Filter "ProcessId=$($_.OwningProcess)").CommandLine
    }
} | Format-Table -AutoSize
```

---

### 4.1 Process execution and process tree

The canonical PsExec process tree on the **destination host** is one of the most reliable volatile indicators available.

**Expected process tree (destination host):**

```
wininit.exe
  └─ services.exe
       └─ PSEXESVC.exe   (SYSTEM)
            └─ cmd.exe   (or any remotely executed command)
                 └─ [child processes of the remote command]
```

**Expected process tree (source host):**

```
<parent shell or dropper>
  └─ psexec.exe   (DOMAIN\attacker or local admin)
```

#### What to look for?

- `PSEXESVC.exe` running as a **direct child of `services.exe`** — this parent-child relationship is unambiguous
- `PSEXESVC.exe` user context is always `NT AUTHORITY\SYSTEM`
- The remotely executed process (e.g., `cmd.exe`, `powershell.exe`, a payload binary) will appear as a child of `PSEXESVC.exe`
- On the source host, `psexec.exe` remains active in the process list until the remote command exits (it blocks awaiting I/O from the named pipe)

**PowerShell — enumerate PSEXESVC children:**

```powershell
Get-WmiObject Win32_Process | Where-Object { $_.Name -eq "PSEXESVC.exe" } |
    ForEach-Object {
        $parent = $_
        $children = Get-WmiObject Win32_Process | Where-Object { $_.ParentProcessId -eq $parent.ProcessId }
        [PSCustomObject]@{
            PSEXESVC_PID    = $parent.ProcessId
            PSEXESVC_User   = ($parent.GetOwner()).User
            Children        = ($children | Select-Object -ExpandProperty Name) -join ", "
            ChildCmdLines   = ($children | Select-Object -ExpandProperty CommandLine) -join " | "
        }
    }
```

---

### 4.2 Active network connections

During PsExec execution, **multiple simultaneous TCP connections** exist between source and destination.

**Expected connections (as seen from the destination host):**

```
LocalAddress      LocalPort  RemoteAddress   RemotePort  State        Process
192.168.1.50      445        192.168.1.10    49210       ESTABLISHED  System
192.168.1.50      49671      192.168.1.10    49215       ESTABLISHED  PSEXESVC
```

**Expected connections (as seen from the source host):**

```
LocalAddress      LocalPort  RemoteAddress   RemotePort  State        Process
192.168.1.10      49210      192.168.1.50    445         ESTABLISHED  psexec
192.168.1.10      49215      192.168.1.50    49671       ESTABLISHED  psexec
```

#### What to look for?

- A connection from `psexec.exe` to TCP/445 of an internal host — unexpected in environments that do not use PsExec for administration
- A second, high-port connection (`≥1024`) from the same source IP as the SMB connection — this is the RPC/named pipe channel
- On the destination, `System` (PID 4) owning the TCP/445 listener is normal; a second connection owned by `PSEXESVC.exe` on a high port is the discriminating indicator
- `netstat -ano` on the destination will show the high-port connection while the service is running:

```
netstat -ano | findstr PSEXESVC_PID
```

---

### 4.3 Named pipes and IPC artifacts

PsExec uses **named pipes** over the `IPC$` share for I/O redirection (stdin, stdout, stderr) between the source and the remote process.

**Expected pipes (visible on destination host during execution):**

```
\\.\pipe\PSEXESVC
\\.\pipe\PSEXESVC-<source_hostname>-<pid>-stdin
\\.\pipe\PSEXESVC-<source_hostname>-<pid>-stdout
\\.\pipe\PSEXESVC-<source_hostname>-<pid>-stderr
```

**Enumerate named pipes (PowerShell):**

```powershell
Get-ChildItem \\.\pipe\ | Where-Object { $_.Name -like "*PSEXESVC*" }
```

**Enumerate named pipes (Sysinternals PipeList):**

```
pipelist.exe | findstr PSEXESVC
```

> **Key value:** The presence of `PSEXESVC`-prefixed named pipes is a **live execution indicator**. The embedded hostname in the pipe name (`PSEXESVC-<hostname>-<pid>-stdin`) directly identifies the **source machine** initiating the PsExec connection, providing real-time attribution.

---

### 4.4 Active sessions and SMB state

While PsExec is executing, an active SMB session exists between the source and destination hosts.

**Enumerate active SMB sessions (destination host):**

```powershell
Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens, SecondsExists
```

```
ClientComputerName  ClientUserName         NumOpens  SecondsExists
192.168.1.10        DOMAIN\Administrator   3         12
```

**Legacy command:**

```cmd
net session
```

```
\\192.168.1.10  DOMAIN\Administrator  0  00:00:12
```

> **What to look for:** An active SMB session from an unexpected source IP (`ClientComputerName`) authenticating as a privileged account (`DOMAIN\Administrator`, `DOMAIN\Domain Admins` member) to a workstation or server that would not normally receive administrative SMB connections during working hours.

---

### 4.5 Memory indicators

When PsExec is executed, both `psexec.exe` (source) and `PSEXESVC.exe` (destination) are loaded into memory along with their full execution context.

**Key memory artifacts:**

| Artifact | Host | Content |
|----------|------|---------|
| `psexec.exe` process memory | Source | Command-line arguments including remote hostname, credentials (if `-p` flag used), and remote command — credentials may appear in cleartext in process memory |
| `PSEXESVC.exe` process memory | Destination | Service control structures, pipe handles, references to the remotely executed command |
| Named pipe buffers | Destination | Buffered stdin/stdout/stderr content from the remote command session |
| Network socket buffers | Both | SMB2 packet fragments, DCE/RPC CreateService request bodies |

> **Key value:** A memory acquisition of the destination host during active PsExec execution may recover the **original command line** dispatched remotely, even if Sysmon is not running. This is particularly relevant in environments where audit logging is limited.

---

### 4.6 Behavioral pattern comparison – source vs. destination host

| Feature | Source Host | Destination Host |
|---------|-------------|-----------------|
| Primary process | `psexec.exe` (attacker-initiated) | `PSEXESVC.exe` (service, SYSTEM) |
| Process parent | Attacker shell / dropper | `services.exe` |
| Registry artifact | `EulaAccepted` key under user SID | `HKLM\...\Services\PSEXESVC` key |
| Network role | Initiates SMB/RPC connections outbound | Receives SMB connection on TCP/445 |
| Event log focus | Security EID 4688/4689, 5156 | Security EID 4624, 4672, 5140, 5145, 4656, 4663, 4660; System EID 7045, 7036 |
| Named pipes | Client end (attaches to remote pipe) | Server end (creates and serves pipes) |
| File system trace | `PsExec-<HOST>-*.key` temp file | `PSEXESVC.exe` created and deleted |
| Prefetch | `PSEXEC.EXE-*.pf` | `PSEXESVC.EXE-*.pf` (if Prefetch enabled) |
| Detection difficulty | Moderate (process cmdline reveals intent) | Low (service name and event IDs are distinctive) |

---

## 5. Detection rules and collection targets

This section documents the files and rules generated to enhance forensic analysis of PsExec activity. These detection artifacts are designed to identify suspicious behaviors, unauthorized remote executions, and persistence mechanisms associated with PsExec.

**Sigma rules:**

- [file_event_win_sysinternals_psexec_service_key.yml](../../Outputs/sigmas/file_event_win_sysinternals_psexec_service_key.yml)
- [win_system_service_install_sysinternals_psexec.yml](../../Outputs/sigmas/win_system_service_install_sysinternals_psexec.yml)
- [proc_creation_win_sysinternals_psexec_paexec_escalate_system.yml](../../Outputs/sigmas/proc_creation_win_sysinternals_psexec_paexec_escalate_system.yml)


**KAPE collection targets:**

- [PsExec.tkape (CATALONIA-CERT)](https://github.com/CATALONIA-CERT/Forensics/blob/main/Outputs/tkapes/PsExec.tkape)

---

## 6. References

- [Microsoft Sysinternals – PsExec documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)
- [JPCERT/CC – Detecting Lateral Movement through Tracking Event Logs (2017)](https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf)
- [Red Canary – Threat Hunting PsExec Lateral Movement](https://redcanary.com/blog/threat-detection/threat-hunting-psexec-lateral-movement/)
- [DFIRDominican – The Key to Identify PsExec](https://dfirdominican.com/the-key-to-identify-psexec/)
- [Windows Lateral Movement Through EDR – PsExec (AMikel)](https://github.com/AMikel/Windows-Lateral-Movement-Through-EDR/blob/main/docs/PsExec.md)
- [MITRE ATT&CK – T1021.002: Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK – T1569.002: System Services: Service Execution](https://attack.mitre.org/techniques/T1569/002/)
- [MITRE ATT&CK – T1543.003: Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/)
- [MITRE ATT&CK – T1570: Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)
- [Sigma Rules – SigmaHQ PsExec detection rules](https://github.com/SigmaHQ/sigma/search?q=psexec)
- [CATALONIA-CERT Forensics – Detection outputs and KAPE targets](https://github.com/CATALONIA-CERT/Forensics)
