# v2. AnyDesk

### <mark style="color:$primary;">Index:</mark>

[1.Technical overview](#id-1.-technical-overview "mention")

[2.Summary table of artifacts](#id-2.-summary-table-of-artifacts "mention")

[3.Disk artifacts](#id-3.-disk-artifacts "mention")

[4.Detection rules and collection targets](#id-4.-detection-rules-and-collection-targets "mention")

<br>

## <mark style="color:$primary;">1.</mark>  Technical Overview

<table><thead><tr><th width="242.7999267578125" align="center">Category</th><th>Details</th></tr></thead><tbody><tr><td align="center"><mark style="color:$primary;"><strong>Description</strong></mark></td><td>Remote-control tool that allows unattended or interactive access to systems, with features such as file transfer and remote management.</td></tr><tr><td align="center"><mark style="color:$primary;"><strong>Tactics and Techniques</strong></mark></td><td><ul><li><strong>TA0010</strong> – Exfiltration<br>        - T1567.002 – Exfiltration Over Web Services</li><li><strong>TA0011</strong> – Command and Control<br>        - T1219 – Remote Access Software</li></ul></td></tr><tr><td align="center"><mark style="color:$primary;"><strong>Privileges</strong></mark> </td><td>Not required</td></tr><tr><td align="center"><mark style="color:$primary;"><strong>Operating systems</strong></mark></td><td><ul><li>Windows</li><li>Linux</li><li>macOS</li></ul></td></tr><tr><td align="center"><mark style="color:$primary;"><strong>Communicating protocol</strong></mark> </td><td><ul><li><strong>TCP</strong>: 80, 443, 6568</li><li><strong>UDP</strong>: 50001–50003</li></ul></td></tr></tbody></table>

<br>

## <mark style="color:$primary;">2.</mark>  Summary table of artifacts

<table><thead><tr><th width="158.66650390625">Source<select><option value="yBAVrD55ExlM" label="AppData Folder" color="blue"></option><option value="FCAyhC5psETt" label="Printer installation" color="blue"></option><option value="F2QHAmDGa4vY" label="ProgramData Folder" color="blue"></option><option value="LAw3BI0AB4qD" label="Registry keys" color="blue"></option></select></th><th width="429.066650390625">Artifact</th><th width="236.0543212890625">Indicator</th></tr></thead><tbody><tr><td><span data-option="yBAVrD55ExlM">AppData Folder</span></td><td><code>C:\Users&#x3C;User>%AppData%\Roaming\AnyDesk*.conf</code></td><td><p>Configuration files:</p><ul><li>system.conf</li><li>user.conf</li><li>service.conf</li></ul></td></tr><tr><td><span data-option="yBAVrD55ExlM">AppData Folder</span></td><td><code>C:\Users&#x3C;User>%AppData%\Roaming\AnyDesk\ad.trace</code></td><td><p>Session details: </p><ul><li>IP address of the remote participant</li><li>Client ID</li><li>File transfers</li></ul></td></tr><tr><td><span data-option="yBAVrD55ExlM">AppData Folder</span></td><td><ul><li><code>C:\Users&#x3C;User>%AppData%\Roaming\AnyDesk\printer_driver</code></li><li><code>C:\Windows\System32\winevt\Logs\Microsoft-Windows-DeviceSetupManager\Admin.evtx</code></li></ul></td><td>Printer driver installation during setup</td></tr><tr><td><span data-option="F2QHAmDGa4vY">ProgramData Folder</span></td><td><code>C:%PROGRAMDATA%\AnyDesk\connection_trace.txt</code></td><td>Details of incoming connection and how the connection was authorized</td></tr><tr><td><span data-option="F2QHAmDGa4vY">ProgramData Folder</span></td><td><code>C:%PROGRAMDATA%\AnyDesk\ad_svc.trace</code></td><td><p>AnyDesk service log file that records session-related information:</p><ul><li>IP address of the remote participant</li><li>Client ID</li><li>Connection timestamp</li></ul></td></tr><tr><td><span data-option="LAw3BI0AB4qD">Registry keys</span></td><td><code>HKLM\SOFTWARE\Clients\Media\AnyDesk</code><br><code>HKLM\SYSTEM\CurrentControlSet\Services\AnyDesk</code></td><td>Installation date</td></tr></tbody></table>

<br>

## <mark style="color:$primary;">3.</mark>  Disk artifacts

### <mark style="background-color:yellow;">a.  AppData Folder</mark>

* #### <mark style="color:$info;background-color:yellow;">Configuration files</mark>

```
C:\Users\<User>\%AppData%\Roaming\AnyDesk\*.conf
```

This directory contains several configuration files:

* <mark style="background-color:yellow;">**`system.conf`**</mark> and <mark style="background-color:yellow;">**`user.conf`**</mark>, store configuration variables used by AnyDesk.&#x20;
  * When the client connects, the variable `ad.session.`**`remote_`**`browser_start_path` specifies the default path on the target system for uploading or downloading files via AnyDesk. It typically includes the user’s home directory, which can reveal the username.
  * The default path on the client system appers in the variable `ad.session.`**`local_`**`browser_start_path`
* <mark style="background-color:yellow;">**`service.conf`**</mark> , stores the hash and salt of a configured password, as well as a `certificate` and a `private key`
  * Example:

```
ad.anynet.cert=-----BEGIN CERTIFICATE-----\nMIICqDCCA...mOi\n-----END CERTIFICATE-----\n
ad.anynet.pkey=-----BEGIN PRIVATE KEY-----\nMIIEvgIBA...aum\n-----END PRIVATE KEY-----\n
ad.anynet.pwd_hash=5344a7a23b2abb6314c0fa0ae9e20339a62814b7c2fa494b49c897ad63c0d7c9
ad.anynet.pwd_salt=81279b158b9f3e2e697baef91f35b35b
```


* #### <mark style="color:$info;background-color:yellow;">User interface log</mark>

The file <mark style="background-color:yellow;">**`ad.trace`**</mark> serves as the **user interface log** for AnyDesk. It records critical session details, including the IP address of the remote participant, their AnyDesk ID, and events related to file transfers.

```
C:\Users\<User>\%AppData%\Roaming\AnyDesk\ad.trace
```

> **What to look for?**

To extract connection details, search for the following `strings`

* User interface **logging** -> `Logged in`

```
info 2022-09-28 12:39:26.845 lsvc 9952 9944 21 anynet.any_socket - Client-ID: 442226597 (FPR: 8e28a2a25b30).
info 2022-09-28 12:39:26.845 lsvc 9952 9944 21 anynet.any_socket - Logged in from 12.xx.xx.21:59562 on relay 80e496c0.
```

* **External IP** and local host **Client ID** -> `External address` and `Client-ID`&#x20;

```
info 2022-09-28 12:38:44.222 lsvc 9952 9944 3 anynet.relay_conn - External address: 34.xx.xx.123:50831.
info 2022-09-28 12:38:44.222 lsvc 9952 9944 3 anynet.main_relay_conn - Main relay ID: 80e496c0y.
info 2022-09-28 12:38:44.225 lsvc 9952 9944 3 anynet.main_relay_conn - Detected 2 new networks.
info 2022-09-28 12:38:44.228 lsvc 9952 9944 2 anynet.connection_mgr - Main relay connection established.
info 2022-09-28 12:38:44.228 lsvc 9952 9944 2 anynet.connection_mgr - New user data. Client-ID: 294433414.
```

* **File transfer** events -> `file_transfer`

<pre data-overflow="wrap"><code><strong>info 2022-09-28 12:41:20.001 front 6252 496 app.prepare_task - Preparing files in 'C:\Users\lab\Downloads'.
</strong>info 2022-09-28 12:41:20.001 front 6252 496 app.local_file_transfer - Preparation of 1 files completed (io_ok)
</code></pre>

* #### <mark style="color:$info;background-color:yellow;">Printer installation</mark>

Only available in the **installable version** of AnyDesk.

Related to **printer installation,**  by default AnyDesk installs a printer driver during setup. The directory indicates the user account that triggered the installation.

<pre><code><strong>C:\Users\&#x3C;User>\%AppData%\Roaming\AnyDesk\printer_driver
</strong></code></pre>

The installation of the printer driver also generates logs in the `evtx file`

<pre><code><strong>C:\Windows\System32\winevt\Logs\Microsoft-Windows-DeviceSetupManager\Admin.evtx
</strong></code></pre>

> **What to look for?**

* USB connection - **Event ID 112** -> `AnyDesk Printer`

```
"Prop\_ContainerId":"4AB05252-BFD6-C6E9-7D0E-58FBD6159485","Prop\_DeviceName":"AnyDesk Printer","Prop\_PropertyCount":42,"Prop\_TaskCount":4,"Prop\_WorkTime\_MilliSeconds":46
```

***
<br>


### <mark style="background-color:red;">b.  ProgramData Folder</mark>

Only available in the **installable version** of AnyDesk.

* #### <mark style="color:$info;background-color:red;">Incoming connection</mark>

In the target system, <mark style="background-color:red;">`connection_trace.txt`</mark> logs record details of **incoming connection**, and they include information about how the connection was authorized (by a local user manually approving it or through password).

```
C:\%PROGRAMDATA%\AnyDesk\connection_trace.txt
```

> **What to look for?**

* To obtain the IP address and Client ID of the remote participant -> `Incoming`

```
Incoming 2022-09-28, Passwd 547911884 547911884
Incoming 2022-09-28, 12:39 User 442226597 442226597
```

* #### <mark style="color:$info;background-color:red;">**Service log file**</mark>

<mark style="background-color:red;">`ad_svc.trace`</mark> is the **AnyDesk service log file** and it records session-related information, such as the IP address of the remote participant and their AnyDesk Client ID, and the timestamp when a connection is established.

```
C:\%PROGRAMDATA%\AnyDesk\ad_svc.trace
```

> **What to look for?**

* **Local** host **External IP** address and **Client ID** -> `External address` and `Client-ID`&#x20;

```
info 2022-08-23 10:20:11.969 gsvc 4628 3528 3 anynet.relay_conn - External address: 34.xx.xx.123:46798.
info 2022-08-23 10:20:11.969 gsvc 4628 3528 3 anynet.main_relay_conn - Main relay ID: 8d9e4ddf
info 2022-08-23 10:20:11.984 gsvc 4628 3528 1 fiber.scheduler - Spawning root fiber 18.
info 2022-08-23 10:20:11.984 gsvc 4628 3528 2 anynet.connection_mgr - Main relay connection established.
info 2022-08-23 10:20:11.984 gsvc 4628 3528 2 anynet.connection_mgr - New user data. Client-ID: 609579424.
```

* **Remote** host **External IP** address and **Client ID** -> `Logged in` and `Client-ID`&#x20;

```
info 2022-08-23 10:20:17.125 gsvc 4628 3528 23 anynet.any_socket - Client-ID: 547911884 (FPR: 67a8dcc336a1).
info 2022-08-23 10:20:17.125 gsvc 4628 3528 23 anynet.any_socket - Logged in from 12.xx.xx.21:41314 on relay ad3345a7.
```

***
<br>

### <mark style="background-color:blue;">c.  Registry Keys</mark>

Only available in the **installable version** of AnyDesk.

* #### <mark style="color:$info;background-color:blue;">**Installation date**</mark>

During the **installation** of the program, specific registry keys and values are created. These artifacts can help determine the presence of the application and may also indicate the **installation date.**

```
C:\Windows\System32\Config
```

> **What to look for?**

* Last modification date of the registry key `HKLM\`**`SOFTWARE`**`\Clients\Media\AnyDesk`
* Registry modification date `HKLM\`**`SYSTEM`**`\CurrentControlSet\Services\AnyDesk`&#x20;

***
<br>


## <mark style="color:$primary;">4.</mark>  Detection rules and collection targets

This section documents the **files and rules** generated to enhance forensic analysis of AnyDesk activity. These detection artifacts are designed to identify suspicious behaviors, unauthorized remote access attempts, and persistence mechanisms associated with AnyDesk.

_tkape_ example - https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/AnyDesk.tkape
