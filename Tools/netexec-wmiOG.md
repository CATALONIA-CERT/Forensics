# netexec-wmi

- [1. Technical overview](#1-technical-overview)
- [2. Summary table of artifacts](#2-summary-table-of-artifacts)
- [3. Non-volatile artifacts](#3-non-volatile-artifacts)
- [4. Volatile artifacts](#4-volatile-artifacts)
  - [4.a OS Interaction artifacts](#4a-os-interaction-artifacts)
  - [4.b Network artifacts](#4b-network-artifacts)
- [5. Detection rules and collection targets](#5-detection-rules-and-collection-targets)
  - [SIGMA rules](#sigma-rules)

---

## 1. Technical overview

High‑level description of the tool’s purpose, functionality, and operating behavior.

| Section | Content |
|--------|---------|
| **Description** | **NetExec** (formerly known as CrackMapExec) is a tool commonly used for red teaming and pentesting. It is an internal network auditing framework capable of executing commands remotely through native Windows protocols.<br><br>This publication focuses on the forensic analysis of **Windows Management Instrumentation (WMI)** traffic, a protocol that due to its inherent characteristics may go unnoticed by forensic analysts, especially in environments lacking deep telemetry and when used for remote execution. |
| **Relevance** | During 2025, **WMI (T1047)** was one of the most frequently abused techniques by threat actors for remote execution, discovery and lateral movement. |
| **Living-off-the-Land** | WMI operates through legitimate Windows processes (notably `WmiPrvSE.exe`) and enables execution and persistence without introducing external files, increasing its evasive capability. Technical analyses consistently identify WMI as one of the most exploited LOLBins for stealthy remote execution in Windows environments. |
| **Architecture** | WMI remote communication does not rely on a proprietary protocol but operates over **DCOM (Distributed Component Object Model)**, which itself depends on **RPC**. Communication begins on TCP port **135**, after which the main session is established using **dynamic RPC ports (49152–65535)**. This design complicates network monitoring and hampers detection where relevant logs are not enabled by default. |
| **Methodological note** | In real intrusions, attackers typically do not deploy NetExec itself. However, in controlled environments NetExec serves as a reliable instrument to study attacker‑like WMI behavior and develop effective detection and DFIR capabilities. |
| **Objectives** | • Detect WMI remote execution through forensic artifacts<br>• Identify fileless lateral movement via RPC/DCOM<br>• Delimit potential WMI persistence vectors |
| **Tool reference** | <https://github.com/Pennyw0rth/NetExec> |

### Tactics & Techniques (MITRE ATT&CK)

- **TA0002 – Execution**
  - **T1047 – Windows Management Instrumentation**

---

## 2. Summary table of artifacts

Overview table summarizing the main artifacts, where they reside and what information they contain.

### Non‑volatile artifacts

| Source | Artifact | Indicator |
|------|----------|-----------|
| Security logs | `Security.evtx` | 4624 (Logon Type 3)<br>4625 (Authentication failure)<br>4672 (Special privileges assigned) |
| WMI logs | `Microsoft-Windows-WMI-Activity/Operational.evtx` | 5857 / 5858 / 5859 *(execution phase only)* |
| Process creation | `Security.evtx` / Sysmon | 4688 (Parent: `WmiPrvSE.exe`) |

### Volatile artifacts

| Source | Artifact | Indicator |
|------|----------|-----------|
| Active processes | Memory / EDR | `WmiPrvSE.exe`<br>Child processes (`cmd.exe`, `powershell.exe`) |
| Network traffic | NDR / PCAP | TCP/135 + dynamic RPC ports |

---

## 3. Non-volatile artifacts

When NetExec is used via WMI, **no binaries or files are written to disk** on the target system.

As a result:

- No Prefetch entries associated with NetExec
- No Amcache or ShimCache artifacts
- No configuration files, installers or persistence files created

All relevant forensic evidence is derived from **native Windows telemetry**, primarily security auditing and WMI operational logs.

---

## 4. Volatile artifacts

Evidence produced during remote WMI interaction, including authentication, process creation and runtime behavior.

### 4.a OS Interaction artifacts

- Remote authentication via DCOM/RPC
- No interactive user session
- Optional process creation via `Win32_Process.Create`
- Execution brokered by `WmiPrvSE.exe`
- Security Event ID **4624** (Logon Type 3)

---

### 4.b Network artifacts

- Initial connection to TCP/135
- Subsequent connections to RPC dynamic ports
- Traffic visually indistinguishable from legitimate administrative WMI usage
- Absence of identifiable application‑layer indicators

---

## 4.1 Differentiation between WMI authentication and WMI execution

The absence of WMI‑Activity events **does not imply absence of WMI abuse**; it may indicate a pre‑execution access or reconnaissance phase.

During the **authentication phase**, NetExec establishes a remote session via DCOM over RPC to validate credentials and confirm access to the WMI environment (typically `root\cimv2`). No WMI queries, method invocations or process creation occur at this stage.

Consequently, **authentication alone does not generate entries** in `Microsoft-Windows-WMI-Activity/Operational`. Observable artifacts are limited to security authentication events, primarily:

- **4624** (Logon Type 3 – Network)
- **4672** when administrative privileges are granted

In contrast, **effective WMI execution**—through query execution, method invocation (e.g. `Win32_Process.Create`) or event‑based persistence—triggers full WMI telemetry. This includes:

- Events **5857, 5858 and 5859** in `WMI-Activity`
- Process creation events (**4688**) with `WmiPrvSE.exe` as the parent process

From a DFIR perspective, differentiating these phases is critical. WMI‑Activity logs are execution‑centric and their absence must not be interpreted as the absence of malicious WMI usage, but potentially as **lateral movement preparation or credential validation**.

---

## 4.2 Windows detection – Authentication

**Host:** Target system  
**Log source:** `Security.evtx`

**Relevant Event IDs:**

- **4624** – Logon Type 3
- **4625** – Authentication failure
- **4672** – Special privileges assigned

**Expected behavior:**

- Network logon without interactive session
- No corresponding WMI‑Activity events during this phase

---

## 4.3 Windows detection – Execution

**Log sources:**

- `Security.evtx`
- `Microsoft-Windows-WMI-Activity/Operational.evtx`

**Relevant Event IDs:**

- **4688** – New process created  
  - Parent process: `WmiPrvSE.exe`  
  - Child process: `cmd.exe`, `powershell.exe`, etc.
- **4689** – Process termination
- **5857 / 5858 / 5859** – WMI operational activity

`WmiPrvSE.exe` acts as an execution intermediary, enabling remote, non‑interactive and fileless process creation, a behavior frequently abused for stealthy lateral movement.

---

## 5. Detection rules and collection targets

### SIGMA rules

- <https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_netexec.yml>

```yaml
title: HackTool - NetExec Execution
id: 7638e5fe-600c-4289-a968-f49dd537ec7d
status: experimental
description: Detects execution of the hacktool NetExec.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\nxc.exe'
    CommandLine|contains:
      - ' ftp '
      - ' ldap '
      - ' mssql '
      - ' nfs '
      - ' rdp '
      - ' smb '
      - ' ssh '
      - ' vnc '
      - ' winrm '
      - ' wmi '
  condition: selection
falsepositives:
  - Authorized red team or administrative usage
level: high
``
