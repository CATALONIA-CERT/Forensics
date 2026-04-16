# PsExec - sysinternals

- [PsExec - sysinternals](#PsExec-sysinternals)
  - [1. Technical overview](#1-technical-overview)
  - [2. Summary table of artifacts](#2-summary-table-of-artifacts)
  - [3. Detection rules and collection targets](#3-detection-rules-and-collection-targets)
  - [4. Reference](#4-Reference)

## 1. Technical overview

High‑level description of the tool’s purpose, functionality, and operating behavior.

| Section | Content |
|---------|---------|
| Description | PsExec is a command-line utility from Microsoft Sysinternals that allows to execute processes remotely on Windows systems. It works by creating a temporary service on the target machine, enabling the execution of commands or applications as if they were run locally.|
| Tactics & Techniques |TA0003 – Persistence <br>• T1136.002 – Create Account: Domain Account <br><br>TA0004 – Privilege Escalation <br>• T1543.003 – Create or Modify System Process: Windows Service <br><br>TA0008 – Lateral Movement <br>• T1570 – Lateral Tool Transfer <br>• T1021.002 – Remote Services: SMB/Windows Admin Shares <br><br>TA0002 – Execution <br> • T1569.002 – System Services: Service Execution |
| Privileges | Yes |
| OS | Windows |
| Network | • TCP/445 (SMB) <br> •  TCP/135 (RPC)|


## 2. Summary table of artifacts

Overview table summarizing the main artifacts, where they reside and what information they contain.

Non-volatile artifacts:

| Source | Artifact | Indicator |
|------------|----------|-----------|
| Binary execution | %SystemRoot%\Prefetch <br>%SystemRoot%\AppCompat\Programs\Amcache.hve | • Prefetch (if enabled): executable name, path, and execution count  <br>• Amcache/ShimCache:executable name, product version,  path, SHA1 hash |
| Process events | %SystemRoot%\System32\winevt\Logs\Security<br> %SystemRoot%\System32\winevt\Logs\SYSMON | Event ID 4688 (A new process has been created PSEXECSVC.exe) <br> Event ID 1 (Process creation PSEXESVC.exe)<br> |
| Service events | %SystemRoot%\System32\winevt\Logs\System <br> %SystemRoot%\System32\winevt\Logs\Security | Event ID 7045 (By default ServiceName: PSEXESVC) |
| Lateral Movment | %SystemRoot%\System32\winevt\Logs\Security | Event ID 4624 (Successful logon) <br>Event ID 5140  (A network share object was accessed) |
| Registry | HKLM\System\CurrentControlSet\Services | By default Key name: PSEXESVC |
| File system | %SystemRoot%\System32\winevt\Logs\SYSMON <br>C:\Windows\Tasks <br> C:\Windows\System32\Tasks|  Event ID 11 (TargetFilename is PSEXESVC.exe) <br>   Job files created in <br>  XML task files created in|

Volatile artifacts:

| Source | Artifact | Indicator |
|------------|----------|-----------|
| File system | USN Journal (FileCreate) |  PsExec-SOURCE_HOSTNAME-XXXXXXXX.key |
| Memory | Process execution |Process tree (while PsExec is executing): Wininit.exe → Services.exe → PSEXESVC.exe|
| Network | Network connection | Outbound on destination port 135 and 445|

## 3. Detection rules and collection targets

This section documents the **files and rules** generated to enhance forensic analysis of PsExec activity. These detection artifacts are designed to identify suspicious behaviors, unauthorized remote executions, and persistence mechanisms associated with PsExec.

- [file_event_win_sysinternals_psexec_service_key.yml](../../Outputs/sigmas/file_event_win_sysinternals_psexec_service_key.yml)
- [win_system_service_install_sysinternals_psexec.yml](../../Outputs/sigmas/win_system_service_install_sysinternals_psexec.yml)
- [proc_creation_win_sysinternals_psexec_paexec_escalate_system.yml](../../Outputs/sigmas/proc_creation_win_sysinternals_psexec_paexec_escalate_system.yml)


## 4. Reference

- https://dfirdominican.com/the-key-to-identify-psexec/ <br>
- https://github.com/AMikel/Windows-Lateral-Movement-Through-EDR/blob/main/docs/PsExec.md<br>
- https://redcanary.com/blog/threat-detection/threat-hunting-psexec-lateral-movement/<br>
