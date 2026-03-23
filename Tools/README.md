# 🔍 DFIR Hacking Tools Analysis Repository
*A collection of forensic analyses, behavioral breakdowns, and indicators of compromise associated with commonly encountered offensive security tools.*

---

## Objectives

- Provide **technical analyses** of commonly encountered offensive tools used in intrusions.  
- Document **artifacts**, **behaviors**, and **forensic traces**.  
- Publish **IoCs**, **log references**, and **detection opportunities**.  
- Help new DFIR analysts build familiarity with adversary tradecraft.

---

## Repository Structure

```
/
├── rat/
│   ├── AnyDesk.md
│   └── ...
├── NET/
│   ├── revsocks.md
│   └── ...
```

---

## What Each Analysis Includes

1. Technical overview
2. Summary table of artifacts
3. Installation artifacts
4. Disk artifacts
5. Runtime artifacts
6. Detection rules and collection targets

## Generic Forensic Artifacts Reference

This section provides **generic DFIR artifacts** commonly applicable to most tooling. Individual tool analyses may **reference sections of this file** instead of repeating identical content that keeps each tool analysis focused on **unique behaviors only**.

---

### 1. Execution Artifacts

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

**Notes:**
- Available only if Prefetching is enabled.
- Only applies to binaries executed from disk.

---

#### Amcache & ShimCache
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

**Notes:** Evidence may survive deletion.

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

#### PowerShell Artifacts

If ScriptBlockLogging (4104) or Transcription is enabled, commands and parameters used to invoke the binary may appear in the PowerShell Operational Log.

```
C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell/Operational.evtx
%UserProfile%\Documents\PowerShell_transcript\
```

**What to look for?**

- PowerShell invocation of the binary
- Command‑line arguments
- Operator activity before/after execution

#### Windows Error Reporting (WER)
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

---

### 2. Persistence-Related Artifacts

#### Registry Run Keys
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```
#### Scheduled Tasks
```
C:\Windows\System32\Tasks\
```
#### Services (manual creation)
```
sc.exe create <name> binPath= "<path>"
```

**What to look for:**
- Suspicious paths
- Unsigned executables
- Unexpected triggers
- Recently created services

---

### 3. File System Forensic Artifacts

#### LNK (Recent File) Artifacts
```
%APPDATA%\Microsoft\Windows\Recent\
```
**What they provide:**
- Execution path
- Working directory
- Volume information
- Timestamps

#### Shadow Copies
Copies of the binary may remain in restore points or shadow copies even if deleted afterward.

**What to look for?**

- Copies of the binary in user directories
- Operator tool staging areas

**Notes:** No fixed path — browse via vssadmin / forensic mounts