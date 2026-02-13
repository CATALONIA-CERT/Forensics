# Tool title

### <mark style="color:$primary;">Index:</mark>

[1.Technical overview](#id-1.-technical-overview "mention")

[2.Summary table of artifacts](#id-2.-summary-table-of-artifacts "mention")

[3.Installation artifacts](#id-3.-installation-artifacts "mention")

[4.Detection rules and collection targets](#id-4.-detection-rules-and-collection-targets "mention")

<br>

## <mark style="color:$primary;">1.</mark>  Technical Overview

Brief description of the tool, its purpose, and how it operates.

<table><thead><tr><th width="242.7999267578125" align="center">Category</th><th>Details</th></tr></thead><tbody><tr><td align="center"><mark style="color:$primary;"><strong>Description</strong></mark></td><td>Brief description of the tool - Example: Remote-control tool that allows unattended or interactive access to systems, with features such as file transfer and remote management. </td></tr><tr><td align="center"><mark style="color:$primary;"><strong>Tactics and Techniques</strong></mark></td><td><ul><li><strong>TA00XX</strong> – Tactic Name <br>        - T1XXX.00X – Tecnique Name </li></li></ul></td></tr><tr><td align="center"><mark style="color:$primary;"><strong>Privileges</strong></mark> </td><td>(Not) required</td></tr><tr><td align="center"><mark style="color:$primary;"><strong>Operating systems</strong></mark></td><td><ul><li>Windows</li><li>Linux</li><li>macOS</li></ul></td></tr><tr><td align="center"><mark style="color:$primary;"><strong>Communicating protocol</strong></mark> </td><td><ul><li><strong>TCP</strong>: 80, 443, 6568</li><li><strong>UDP</strong>: 50001–50003</li></ul></td></tr></tbody></table>

<br>

## <mark style="color:$primary;">2.</mark>  Summary table of artifacts

High-level table summarizing key artifacts, their locations, and relevance.

<table><thead><tr><th width="158.66650390625">Source<select><option value="yBAVrD55ExlM" label="Artifact name" color="blue"></option><option value="FCAyhC5psETt" label="Artifact name" color="blue"></option><option value="F2QHAmDGa4vY" label="Artifact name" color="blue"></option><option value="LAw3BI0AB4qD" label="Artifact name" color="blue"></option></select></th><th width="429.066650390625">Artifact</th><th width="236.0543212890625">Indicator</th></tr></thead><tbody><tr><td><span data-option="yBAVrD55ExlM">Artifact name</span></td><td><code>C:\Users&#x3C;User>%AppData%\Roaming\AnyDesk*.conf</code></td><td><p>Configuration files:</p><ul><li>system.conf</li></ul></td></tr><tr><td><span data-option="yBAVrD55ExlM">Artifact name</span></td><td><code>C:\Users&#x3C;User>%AppData%\Roaming\AnyDesk\ad.trace</code></td><td><p>Session details: </p><ul><li>IP address of the remote participant</li><li>File transfers</li></ul></td></tr><tr><td><span data-option="yBAVrD55ExlM">Artifact name</span></td><td><ul><li><code>C:\Users&#x3C;User>%AppData%\Roaming\AnyDesk\printer_driver</code></li><li><code>C:\Windows\System32\winevt\Logs\Microsoft-Windows-DeviceSetupManager\Admin.evtx</code></li></ul></td><td>Printer driver installation during setup</td></tr><tr><td><span data-option="F2QHAmDGa4vY">Artifact name</span></td><td><code>C:%PROGRAMDATA%\AnyDesk\connection_trace.txt</code></td><td>Details of incoming connection and how the connection was authorized</td></tr><tr><td><span data-option="F2QHAmDGa4vY">Artifact name</span></td><td><code>C:%PROGRAMDATA%\AnyDesk\ad_svc.trace</code></td><td><p>AnyDesk service log file that records session-related information:</p><ul><li>IP address of the remote participant</li></ul></td></tr><tr><td><span data-option="LAw3BI0AB4qD">Artifact name</span></td><td><code>HKLM\SOFTWARE\Clients\Media\AnyDesk</code><br><code>HKLM\SYSTEM\CurrentControlSet\Services\AnyDesk</code></td><td>Installation date</td></tr></tbody></table>

<br>


## <mark style="color:$primary;">3.</mark>  Installation artifacts
Explanation of artifacts created during installation:
<br> 
<br>
> _**# Example entries**:_
- _3.a Installation directories_
- _3.b Packages / installers_
- _3.c System services or daemons created_
- _3.d Initial configuration files_

### <mark style="background-color:yellow;">3.a  Installation directories </mark>

* #### <mark style="color:$info;background-color:yellow;"> Sub-artifact name </mark>

_Description of artifact function and evidence value_
<br>
> _**# Example**_ - The file <mark style="background-color:yellow;">**`ad.trace`**</mark> serves as the **user interface log** for AnyDesk. It records critical session details, including the IP address of the remote participant, their AnyDesk ID, and events related to file transfers.

```
Artifact location/path
```

> **What to look for?**

To extract _connection details_, search for the following `strings`

* _Example_ -> User interface **logging** -> `Logged in`

```
_Relevant log entries_
```

* _Example_ -> **External IP** and local host **Client ID** -> `External address`

```
_Relevant log entries_
```

***
<br>

***
<br>

## <mark style="color:$primary;">4.</mark>  Disk artifacts
- _Installation directories_
- _Packages / installers_
- _System services or daemons created_
- _Initial configuration files_

### <mark style="background-color:yellow;">4.a  Type of artifact </mark>

* #### <mark style="color:$info;background-color:yellow;"> Sub-artifact name </mark>

Artifact function and evidence value
<br>
_Example_ - The file <mark style="background-color:yellow;">**`ad.trace`**</mark> serves as the **user interface log** for AnyDesk. It records critical session details, including the IP address of the remote participant, their AnyDesk ID, and events related to file transfers.

```
Artifact location/path
```

> **What to look for?**

To extract _connection_ details, search for the following `strings`

* _Example_ -> User interface **logging** -> `Logged in`

```
_Relevant log entries_
```

* _Example_ -> **External IP** and local host **Client ID** -> `External address`

```
_Relevant log entries_
```

***
<br>


### <mark style="background-color:red;">b.  Type of artifact </mark>

Only available in the **installable version** of AnyDesk.

* #### <mark style="color:$info;background-color:red;">Sub-artifact name</mark>

Artifact function and evidence value
<br>
_Example_ - In the target system, <mark style="background-color:red;">`connection_trace.txt`</mark> logs record details of **incoming connection**, and they include information about how the connection was authorized (by a local user manually approving it or through password).

```
Artifact location/path
```

> **What to look for?**

* _Example_ -> To obtain the IP address and Client ID of the remote participant -> `Incoming`

```
_Relevant log entries_
```

***
<br>


## <mark style="color:$primary;">4.</mark>  Detection rules and collection targets

This section documents the **files and rules** generated to enhance forensic analysis of AnyDesk activity. These detection artifacts are designed to identify suspicious behaviors, unauthorized remote access attempts, and persistence mechanisms associated with AnyDesk.

_Link to the tkapes/sigmas folder within Forensics or link to tkapes/sigmas found on the internet_
<br>
_tkape_ example - https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/AnyDesk.tkape
