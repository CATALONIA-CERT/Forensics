# netbird

- [netbird](#netbird)
	- [1. Technical overview](#1-technical-overview)
	- [2. Summary table of artifacts](#2-summary-table-of-artifacts)
		- [2.1 Windows](#21-windows)
		- [2.2 Linux](#22-linux)
	- [3. Non-Volatile Artifacts](#3-non-volatile-artifacts)
		- [3.1 Windows](#31-windows)
			- [3.1.1 NetBird Logs](#311-netbird-logs)
			- [3.1.2. 3.1.2 NetBird Configuration](#312-312-netbird-configuration)
			- [3.1.3 Windows System Event Logs](#313-windows-system-event-logs)
			- [3.1.4 Windows Firewall Event Logs](#314-windows-firewall-event-logs)
			- [3.1.5 Windows RDP Event Logs](#315-windows-rdp-event-logs)
			- [3.1.6 Sysmon](#316-sysmon)
		- [3.2 Linux](#32-linux)
			- [3.2.1 NetBird Logs and Configuration](#321-netbird-logs-and-configuration)
			- [3.2.2 Services](#322-services)
			- [3.2.3 Package sources / repos](#323-package-sources--repos)
			- [3.2.4 System Configurations](#324-system-configurations)
			- [3.2.5 System Logs](#325-system-logs)
	- [4. Volatile Artifacts](#4-volatile-artifacts)
	- [5. Detection rules and collection targets](#5-detection-rules-and-collection-targets)
	- [6. References](#6-references)

## 1. Technical overview

High‑level description of the tool’s purpose, functionality, and operating behavior.

| Section | Content |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Description | Open Source Tool that creates secure virtual networks between machines on diferent servers via creating a mesh p2p network using WireGuard tunnels.<br><br>Additionally, NetBird also implements some remote access capabilities, allowing users to RDP to machines with access enabled from the web console, or command line access to other NetBird clients through NetBird's integrated SSH.<br><br>The dashboard is used to configure the virtual network, enabling traffic between clients, or use clients to route traffic from other clients to an internal network. |
| Tactics & Techniques | TA0002 – Execution <br>• T1569.002 – System Services: Service Execution<br><br>TA0003 – Persistence<br>• T1543.002 – Create or Modify System Process: Systemd Service<br><br>TA0011 – Command and Control<br>• T1219.002 – Remote Access Tools: Remote Desktop Software<br>• T1572 – Protocol Tunneling<br>• T1090.001 – Proxy: Internal Proxy |
| Privileges | Required |
| OS | • Windows, Linux, MacOS, Android, iPhone |
| Network | • IP/100.0.0.0/8 (IPs ranges  used by NetBird) |



## 2. Summary table of artifacts
### 2.1 Windows
Overview table summarizing the main artifacts, where they reside and what information they contain.

Non-volatile Artifacts:

| Source | Artifact | Indicator |
| --------------------- | ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| NetBird Logs | `C:\ProgramData\Netbird\client.log` | - |
| NetBird Configuration | `C:\ProgramData\Netbird\*.json` | - |
| Security logs | `%systemroot%System32\winevt\Logs\Security.evtx` | • 4624 (Logon Type 3)  <br>• 4688 (Process Creation) |
| System Logs | `%systemroot%\System32\winevt\Logs\System.evtx` | • 7045 (Service Creation)<br> |
| Firewall Logs | `%systemroot%\System32\winevt\Logs\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx` | • 2097 (Firewall Rule Creation) |
| RDP Logs | `%systemroot%\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx` | • 1149 (RDP Connection) |


Volatile Artifacts:

| Source | Artifact | Indicator |
| ------------------ | ------------------------------------ | -------------------------------------------------------------- |
| Loaded modules | Memory dump / Process Information | • `wintun.dll`: Layer 3 tunneling library |
| Network Interfaces | Memory dump / Networking Information | • 100.0.0.0/8: Interfaces using subranges of this subrange<br> |

### 2.2 Linux

Non-volatile Artifacts:

| Source | Artifact | Indicator |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| SSH logins | `/var/log/secure.log`<br>`/var/log/auth.log` | • Logins from NetBird IPs |
| System Configuration  | `/etc/ssh/ssh_config.d/99-netbird.conf `<br>`/etc/systemd/networkd.conf.d/99-netbird.conf` | • Configurations related to NetBird Installation |
| Services | `/etc/systemd/system/netbird.service` | • Netbird service creation |
| NetBird Logs | `/var/log/netbird/client.log`<br> | • |
| NetBird Configuration | `/netbird/active_profile.txt`<br>`/var/lib/netbird/*.json`<br>`/home/<user>/.config/netbird/active_profile.txt<br>`<br>`/root/.config/netbird/active_profile.txt` | • |
| Netbird executables   | `/usr/bin/netbird`<br>`/usr/bin/netbird-ui`<br> | |
| Loaded modules | Memory dump / Process Information | • `wintun.dll`: Layer 3 tunneling library |


## 3. Non-Volatile Artifacts

When NetBird is installed with the official installer, by default it installs itself in the program files folder and creates various services in order to work.
Although it does not offer a portable version, the NetBird executable can be imported along the *wintun* dynamic library and run by themselves, avoiding the noise created by the installation, which makes the activity significantly more difficult to identify as NetBird.
### 3.1 Windows

#### 3.1.1 NetBird Logs
During its execution, NetBird creates various kinds of logs in its `client.log` file. The information includes relevant information like authentication type, NetBird servers, connections between peers, and more.

**Artifacts:**

 - `C:\ProgramData\Netbird\client.log`


**Indicators:**

Client Login
```
2025-12-23T17:12:22Z INFO client/internal/login.go:170: peer has been successfully registered on Management Service
```

Failed Login
```
2025-12-24T17:12:37Z WARN shared/management/client/grpc.go:136: exiting the Management service connection retry loop due to the unrecoverable error: rpc error: code = PermissionDenied desc = peer login has expired, please log in once more
```

Server used by NetBird
```
2025-12-23T17:12:23Z INFO client/internal/connect.go:267: connecting to the Relay service(s): rels://relay.netbird.io:443
```

Setup finish, Includes IP on the netbird network.
```
2025-12-23T17:12:23Z INFO client/internal/engine.go:272: I am: pg+A/Q9P7Y1J/La5VyRRiRD6LXYS5Y+sAaE83uHb6AA=
2025-12-23T17:12:25Z INFO client/internal/connect.go:286: Netbird engine started, the IP is: 100.124.101.177/16
```

NetBird SSH Server Startup and Options
*NetBird also incudes its own SSH Client/Server. The configuration loaded for a specific session can be seen in the client.log file. There is also possible to see logins from other peers (Only on the server).*
```
2025-12-29T08:17:13Z INFO client/internal/profilemanager/config.go:372: enabling SSH server 2025-12-29T08:17:13Z INFO client/internal/profilemanager/config.go:520: disabling notifications 2025-12-29T08:31:22Z INFO client/internal/profilemanager/config.go:324: switching Network Monitor to true 2025-12-29T08:31:22Z INFO client/internal/profilemanager/config.go:393: enabling SSH root login 2025-12-29T08:31:22Z INFO client/internal/profilemanager/config.go:403: enabling SSH SFTP subsystem 2025-12-29T08:31:22Z INFO client/internal/profilemanager/config.go:413: enabling SSH local port forwarding 2025-12-29T08:31:22Z INFO client/internal/profilemanager/config.go:423: enabling SSH remote port forwarding 2025-12-29T08:31:22Z INFO client/internal/profilemanager/config.go:435: enabling SSH authentication 2025-12-29T08:31:22Z INFO client/internal/profilemanager/config.go:442: updating SSH JWT cache TTL to 0 seconds
```

SSH Disabled
``` 
2025-12-23T17:12:25Z INFO client/internal/engine_ssh.go:50: SSH server is disabled in config
```

SSH Login from NetBird Peer
```
2025-12-29T11:28:00Z INFO client/ssh/server/server.go:609: SSH connection from NetBird peer 100.124.208.107:49905 allowed
```

Traffic between peers (Shows WireGuard tunnel creation but does not show source/destination)
*When two NetBird Clients communicate, or one is being used as a router for traffic directed to its local network, NetBird creates logs in client.log about the creation of WireGuard Tunnels. The information given by those logs is quite limited.*
```
2025-12-29T10:59:02Z INFO [peer: co6ZuSyTuOClF8EXFpHmeC0bIK1gvL64rjWf1KudSkI=] client/internal/peer/handshaker.go:105: received answer, running version 0.60.8, remote WireGuard listen port 51820, session id: 196834243f
```

Failed routed connection through a client towards an internal network
*Failed connections will create a log with more information, allowing to track the origin and destination of failed connections.*
```
2026-01-02T13:56:57+00:00 ERRO proxyTCP: copy error (out → in) for 100.124.208.107:50831 → 10.66.0.35:48086: writeto tcp 10.66.0.10:57525->10.66.0.35:48086: read tcp 10.66.0.10:57525->10.66.0.35:48086: wsarecv: An existing connection was forcibly closed by the remote host.
```

#### 3.1.2. 3.1.2 NetBird Configuration
The configuration of the default profile can be found inside default.json, but the user can create several profiles with different configurations.


**Artifacts:**
 - `C:\ProgramData\Netbird\*.json`


**Indicators:**

SSH service:
```
ServerSSHAllowed: true,
...
"SSHKey": "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAMxfFBVyk88AB3BGAW+8RAN36Oo4vhxkdsclETRH6rN\n-----END PRIVATE KEY-----\n",
...
```
Server Routes
*If this configuration is enabled, the machine can be used as a router to access any  machine from its internal network.* 
``` 
"DisableServerRoutes": false,
```

Client Routes
*Unless this configuration is enabled, the peer will used the routes configured by NetBird to route traffic.*
```
"DisableClientRoutes": false,
```

NetBird server location:
``` json
"ManagementURL": { 
	...
	"Host": "api.netbird.io:443", 
	... 
}, 
"AdminURL": {
	... 
	"Host": "app.netbird.io:443", 
	...
},
```


**Artifacts:**
 - `C:\Users\<Username>\AppData\Roaming\netbird\default.state.json`
**Indicator:**
Email of the user used in the last session:

```
{"email": "********@********.***"}
```

#### 3.1.3 Windows System Event Logs
The installation of NetBird creates two new services on the system, which generates System events with id 7045.

**Artifacts:**
 - `C:\Windows\System32\winevt\Logs\System.evtx`

**Indicators**
Service Creation (Wintun) - *Event ID 7045*
``` 
Service Name:  Wintun
Service File Name:  \SystemRoot\System32\drivers\wintun.sys
Service Type:  kernel mode driver
Service Start Type:  demand start
Service Account:  
```

Service Creation (Netbird) - *Event ID 7045*
``` 
Service Name:  Netbird
Service File Name:  "C:\Program Files\Netbird\Netbird.exe" service run --log-level info --daemon-addr tcp://127.0.0.1:41731 --log-file C:\ProgramData\Netbird\client.log
Service Type:  user mode service
Service Start Type:  auto start
Service Account:  LocalSystem
```


#### 3.1.4 Windows Firewall Event Logs
NetBird creates and modifies firewall 

**Artifacts:**
 - `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx`

**Indicators:**
Firewall Rule Creation - *Event ID 2097*
*Command executed during login. It shows the url contacted by the netbird executable. In some cases it will include the email of the account used to login in the `login_hint` field:*
```
Added Rule:
...
	Rule Name:	Netbird
...
	Modifying User:	SYSTEM
...
	Modifying Application:	C:\Windows\System32\netsh.exe
...

```

#### 3.1.5 Windows RDP Event Logs
The event shows as a standard RDP connection log. IP will be from the range used by NetBird (100.124.0.0/16 by default). Also can be linked to a tunnel created on the client.log file

**Artifacts:**
 - `C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx`

**Indicators:**
RDP Connection - *Event ID 1149*
```
Remote Desktop Services: User authentication succeeded:

User: **** 
Domain: ***** 
Source Network Address: 100.124.208.107
```

#### 3.1.6 Sysmon
In case sysmon is enabled, it is possible to extract relevant information about the NetBird session and, in some cases, recover the email of the NetBird user:

**Artifacts:**
 - `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`

 **Indicators:**
```
CommandLine: rundll32 url.dll,FileProtocolHandler https://login.netbird.io/authorize?audience=https%%3A%%2F%%2Fapp.wiretrustee.com%%2F&client_id=x3KvnKHEDY2j3b0n0wLq4eu8SiPDKq6o&code_challenge=xx2jYVHPvUOpZH7M1kx0iVp2XTNFwDB4FMlHy8WzcN8&code_challenge_method=S256&login_hint=**********%%40**********.***&redirect_uri=http%%3A%%2F%%2Flocalhost%%3A53000%%2F&response_type=code&scope=openid+profile+email+offline_access+api+email_verified&state=7594bb9da44fe6ea4ea6e868784c49fe8776f41295a7611b
...
ParentCommandLine: "C:\Program Files\Netbird\Netbird-ui.exe" 0
...
```
### 3.2 Linux
#### 3.2.1 NetBird Logs and Configuration
The configuration and log files on linux have the same contents than the ones found on Windows. 

**Artifacts:**

 - `/var/lib/netbird/`
 - `/var/log/netbird/`

**Indicators:**
 - [NetBird Logs](#311-netbird-logs)
 - [NetBird Configuration](#312-312-netbird-configuration)

#### 3.2.2 Services
After installation, Netbird runs as a service and, as such, it leaves traces on the file system.

**Artifacts:**

 - `/etc/systemd/system/netbird.service`

**Indicators:**

```
"[Unit]
Description=NetBird mesh network client
ConditionFileIsExecutable=/usr/bin/netbird
After=network.target syslog.target
[Service]
StartLimitInterval=5
StartLimitBurst=10
ExecStart=/usr/bin/netbird ""service"" ""run"" ""--log-level"" ""info"" ""--daemon-addr"" ""unix:///var/run/netbird.sock"" ""--log-file"" ""/var/log/netbird/client.log""
StandardOutput=file:/var/log/netbird/netbird.out
StandardError=file:/var/log/netbird/netbird.err
Restart=always
RestartSec=120
EnvironmentFile=-/etc/sysconfig/netbird
Environment=SYSTEMD_UNIT=netbird
[Install]
WantedBy=multi-user.target"
```

#### 3.2.3 Package sources / repos
The official method is used to install the service (https://docs.netbird.io/get-started/install/linux), adds a new source / repo added to the system pointing to the domain pkgs.netbird.io. The location of the new source depends on the OS and package manager:

**Artifacts:**
 - `/etc/apt/sources.list.d/*.list` (apt)
 - `/etc/apt/sources.list` (apt legacy)
 - `/etc/yum.repos.d/*.repo` (yum / dnf / rpm-ostree)
 - `/etc/zypp/repos.d/*.repo` (zypper)

**Indicators:**
 - `pkgs.netbird.io`

#### 3.2.4 System Configurations
When installed, NetBird also adds its own configuration in order to properly work on the system:

**Artifacts:**
 - `/etc/ssh/ssh_config.d/99-netbird.conf`
 - `/etc/systemd/networkd.conf.d/99-netbird.conf` 

**Indicators:**
 - ssh:
```
Host 100.124.17.204 desktop-oi7a3na-17-204.netbird.cloud desktop-oi7a3na-17-204 100.124.208.107 desktop-cccmtfp.netbird.cloud desktop-cccmtfp 100.124.111.121 ubdk24brt003.netbird.cloud ubdk24brt003
Match exec "/usr/bin/netbird ssh detect %h %p"
PreferredAuthentications password,publickey,keyboard-interactive
PasswordAuthentication yes
PubkeyAuthentication yes
BatchMode no
ProxyCommand /usr/bin/netbird ssh proxy %h %p
StrictHostKeyChecking no
UserKnownHostsFile /dev/null
CheckHostIP no
LogLevel ERROR
```
 - Network:
```
## Created by NetBird to prevent systemd-networkd from removing
## routes and policy rules managed by NetBird.

[Network]
ManageForeignRoutes=no
ManageForeignRoutingPolicyRules=no
```


#### 3.2.5 System Logs
Similarly than RDP on Windows, SSH can be used to remotely access machines running the NetBird service using NedBird's web panel or an ssh connection from another machine running NetBird with visibility to the target machine. 

SSH logins from NetBird IPs can be identified on the auth/secure log.

**Artifacts:**
 - `/var/log/auth.log`
 - `/var/log/secure.log` 

**Indicators:**
 - `2026-01-05T11:38:58.508642+01:00 UBDK login[251678]: ROOT LOGIN on '/dev/pts/1' from '100.124.35.65'`

## 4. Volatile Artifacts
N/A

## 5. Detection rules and collection targets
- [NetBird.tkape (CATALONIA-CERT)](https://github.com/CATALONIA-CERT/Forensics/blob/main/Outputs/tkapes/Netbird.tkape)

## 6. References

1. https://docs.netbird.io/manage/activity
2. https://docs.netbird.io/get-started/cli
3. https://docs.netbird.io/help/troubleshooting-client
4. https://docs.netbird.io/get-started/install/linux
