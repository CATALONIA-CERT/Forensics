# AnyDesk

#### Index

[#technical-overview](#technical-overview "mention")

[#disk-artifacts](#disk-artifacts "mention")

[#detection-rules-and-collection-targets](#detection-rules-and-collection-targets "mention")

## Technical Overview

<details>

<summary>Description</summary>

Remote-control tool that allows unattended or interactive access to systems, with features such as file transfer and remote management.

</details>

<details>

<summary>Tactics and Techniques</summary>

**TA0010** – Exfiltration\
&#x20;       \- T1567.002 – Exfiltration Over Web Services

**TA0011** – Command and Control\
&#x20;       \- T1219 – Remote Access Software

</details>

<details>

<summary>Privileges</summary>

* [ ] Required

</details>

<details>

<summary>Operating System</summary>

* [x] Windows
* [x] Linux
* [x] macOS

</details>

<details>

<summary>Communication protocol</summary>

**TCP**: 80, 443, 6568

**UDP**: 50001–50003

</details>

## Disk artifacts

### <mark style="background-color:yellow;">AppData Folder</mark>


```
C:\Users\<User>\%AppData%\Roaming\AnyDesk\*.conf
```

This directory contains several <mark style="background-color:yellow;">**configuration files**</mark>**:**

* **`system.conf`** and **`user.conf`**, store configuration variables used by AnyDesk.&#x20;

  * When the client connects, the variable `ad.session.`**`remote_`**`browser_start_path` specifies the default path on the target system for uploading or downloading files via AnyDesk. It typically includes the user’s home directory, which can reveal the username.
  * The default path on the client system appers in the variable `ad.session.`**`local_`**`browser_start_path`

* **`service.conf`** , stores the hash and salt of a configured password, as well as a `certificate` and a `private key`


```
ad.anynet.cert=-----BEGIN CERTIFICATE-----\nMIICqDCCA...mOi\n-----END CERTIFICATE-----\n
ad.anynet.pkey=-----BEGIN PRIVATE KEY-----\nMIIEvgIBA...aum\n-----END PRIVATE KEY-----\n
ad.anynet.pwd_hash=5344a7a23b2abb6314c0fa0ae9e20339a62814b7c2fa494b49c897ad63c0d7c9
ad.anynet.pwd_salt=81279b158b9f3e2e697baef91f35b35b
```


```
C:\Users\<User>\%AppData%\Roaming\AnyDesk\ad.trace
```

The file **`ad.trace`** serves as the <mark style="background-color:yellow;">**user interface log**</mark> for AnyDesk. It records critical session details, including the IP address of the remote participant, their AnyDesk ID, and events related to file transfers.

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



```
info 2022-09-28 12:41:20.001 front 6252 496 app.prepare_task - Preparing files in 'C:\Users\lab\Downloads'.
info 2022-09-28 12:41:20.001 front 6252 496 app.local_file_transfer - Preparation of 1 files completed (io_ok)
```



```
C:\Users\<User>\%AppData%\Roaming\AnyDesk\printer_driver
```

> **Warning**
> Only available in the **installable version** of AnyDesk.

Related to <mark style="background-color:yellow;">**printer installation**</mark>**,**  by default AnyDesk installs a printer driver during setup. The directory indicates the user account that triggered the installation.

The installation of the printer driver also generates logs in the `evtx file`

```
C:\Windows\System32\winevt\Logs\Microsoft-Windows-DeviceSetupManager\Admin.evtx
```

> **What to look for?**

* USB connection - **Event ID 112** -> `AnyDesk Printer`


```
"Prop\_ContainerId":"4AB05252-BFD6-C6E9-7D0E-58FBD6159485","Prop\_DeviceName":"AnyDesk Printer","Prop\_PropertyCount":42,"Prop\_TaskCount":4,"Prop\_WorkTime\_MilliSeconds":46
```


### <mark style="background-color:red;">ProgramData Folder</mark>

> **Warning**
> Only available in the **installable version** of AnyDesk.


In the target system, these logs record details of <mark style="background-color:red;">**incoming connection**</mark><mark style="background-color:red;">,</mark> and they include information about how the connection was authorized (by a local user manually approving it or through password).

```
C:\%PROGRAMDATA%\AnyDesk\connection_trace.txt
```

> **What to look for?**

* To obtain the IP address and Client ID of the remote participant -> `Incoming`

```
Incoming 2022-09-28, Passwd 547911884 547911884
Incoming 2022-09-28, 12:39 User 442226597 442226597
```


`ad_svc.trace` is the <mark style="background-color:red;">**AnyDesk service log file.**</mark> It records session-related information, such as the IP address of the remote participant and their AnyDesk Client ID, and the **timestamp** when a connection is established.

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

* **Remote** host **External IP** address and **Client ID** -> `Logged in` and `Client-ID`

```
info 2022-08-23 10:20:17.125 gsvc 4628 3528 23 anynet.any_socket - Client-ID: 547911884 (FPR: 67a8dcc336a1).
info 2022-08-23 10:20:17.125 gsvc 4628 3528 23 anynet.any_socket - Logged in from 12.xx.xx.21:41314 on relay ad3345a7.
```


### <mark style="background-color:blue;">Registry Keys</mark>

> **Warning**
> Only available in the **installable version** of AnyDesk.

During the **installation** of the program, specific registry keys and values are created. These artifacts can help determine the presence of the application and may also indicate the <mark style="background-color:blue;">**installation date.**</mark>

```
C:\Windows\System32\Config
```

> **What to look for?**

* Last modification date of the registry key `HKLM\`**`SOFTWARE`**`\Clients\Media\AnyDesk`
* Registry modification date `HKLM\`**`SYSTEM`**`\CurrentControlSet\Services\AnyDesk`&#x20;

## Detection rules and collection targets

This section documents the **files and rules** generated to enhance forensic analysis of AnyDesk activity. These detection artifacts are designed to identify suspicious behaviors, unauthorized remote access attempts, and persistence mechanisms associated with AnyDesk.

{% embed url="<https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/AnyDesk.tkape>" %}

{% file src="<https://2750971996-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FBsthJZiTrW0BhfkoB5kN%2Fuploads%2FuTBTaXVNdJeKTUt20O7a%2Fanydesk_def.yaml?alt=media&token=bdcf1e0a-6cfa-45b5-841a-facb51137802>" %}
