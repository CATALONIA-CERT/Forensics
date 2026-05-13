# Urban-VPN

- [Urban-VPN](#urban-vpn)
- [1. Technical overview](#1-technical-overview)
- [2. Summary table of artifacts](#2-summary-table-of-artifacts)
- [3. Non-volatile artifacts](#3-non-volatile-artifacts)
  - [3.1 Registry artifacts](#31-registry-artifacts)
  - [3.2 Services and drivers](#32-services-and-drivers)
  - [3.3 File system artifacts](#33-file-system-artifacts)
  - [3.4 Browser extensions](#34-browser-extensions)
- [4. Volatile / network artifacts](#4-volatile--network-artifacts)

---

## 1. Technical overview

Urban‑VPN is a consumer VPN solution distributed as a **Windows desktop application** and as **browser extensions** for Chromium‑based browsers. The Windows application installs system‑level services, modifies DNS behavior, and deploys OpenVPN/TAP drivers, while the browser extensions route traffic through a local proxy service.

The tool is typically used to anonymize user traffic, but from a forensic perspective it introduces persistent changes to the operating system and browser profiles that can be leveraged for detection and timeline reconstruction.

---

## 2. Summary table of artifacts

### Non‑volatile artifacts

| Mode | Source | Artifact | Description |
|----|----|----|----|
| Windows App | Registry | Urban‑VPN installation keys | Identifies application installation |
| Windows App | Registry | Application open command | Defines executable invocation |
| Windows App | Services | VPN, updater, and TAP services | Persistent background execution |
| Windows App | Driver database | TAP / OpenVPN driver entries | Virtual network interface support |
| Windows App | File system | Program and data directories | Application footprint |
| Browser Extension | Browser profile | Extension directories | Installed Urban-VPN extensions |

---

## 3. Non-volatile artifacts

### 3.1 Registry artifacts

Registry keys created during installation of the Urban-VPN Windows application:

```
HKLM\SOFTWARE\Classes\urban
HKLM\SOFTWARE\TAP-Windows
HKLM\SOFTWARE\Urban Cyber Security
HKLM\SOFTWARE\UrbanVPN
```

Application open command registration:

```
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\urban\shell\open\command

C:\Program Files\UrbanVPN\bin\urban-vpn-app.exe "%1"
```

Installer tooling reference (Advanced Installer):

```
HKLM\SOFTWARE\Caphyon\Advanced Installer
```

---

### 3.2 Services and drivers

The Windows application uses OpenVPN to create the network tunnels, which in turn uses the tap0901 driver. Multiple artifacts related to OpenVPN, including drivers, Services and configuration changes related to OpenVPN can be identified after Urban-VPN installation.

#### OpenVPN / TAP drivers

```
HKLM\DRIVERS\DriverDatabase\DriverPackages\oemvista.inf_amd64_6d4bec28a2ef0cdf\Configurations\tap0901.ndi
```

#### DNS policy configuration changes

```
HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters\DnsPolicyConfig\OpenVPNDNSRouting-0
HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\OpenVPNDNSRouting-0\GenericDNSServers
```

#### Services created during installation

```
HKLM\SYSTEM\ControlSet001\Services\tap0901
HKLM\SYSTEM\ControlSet001\Services\tap0901\Enum
HKLM\SYSTEM\ControlSet001\Services\UrbanVPN-Service
HKLM\SYSTEM\ControlSet001\Services\UrbanVPN-Updater
```


---

### 3.3 File system artifacts

Common directories created during installation and execution of the Windows application:

```
C:\Program Files\UrbanVPN
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\UrbanVPN
C:\ProgramData\UrbanVPN
C:\Users\<user>\AppData\Local\Urban Cyber Security\UrbanVPN
C:\Windows\System32\config\systemprofile\AppData\Local\Urban Cyber Security
```

These locations may contain binaries, configuration files, logs, and runtime state data.

---

### 3.4 Browser extensions

Urban VPN offers several different browser extensions for Chromium based browsers. The following **Chromium-based extension IDs** have been identified as belonging to **Urban‑VPN or Urban Cyber Security–related browser components**, including VPN, ad blocking, browser protection, and traffic routing functionality.

#### Known Urban-related Extension IDs

```
gcogpdjkkamgkakkjgeefgpcheonclca
jckkfbfmofganecnnpfndfjifnimpcel
jmjflgjpcpepeafmmgdpfkogkghcpiha
nimlmejbmnecnaghgmbahmbaddhjbecg
almalgbpmcfpdaopimbdchdliminoign
efbobpikdmjaaklfkdlgfopochnjadab
eppiocemhmnlbhjplcgkofciiegomcon
feflcgofneboehfdeebcfglbodaceghj
```

#### manifest.json forensic indicators

The `manifest.json` file inside Chromium extension directories provides high-confidence attribution when specific identifying values are present.

The following `manifest.json` fields have been observed and can be used for **content-based detection**, even if the extension ID is renamed, repackaged, or manually installed.

These values are particularly valuable because:

- They **persist across versions**
- They remain visible even if:
  - The extension is disabled
  - The extension is side-loaded
  - The extension ID is not yet known
- They allow **content-based YARA-L / filesystem scanning**

##### Identifying manifest.json values

An extension can be attributed to an extension from **Urban‑VPN** if **at least one** of the following values is present:

###### Default title indicators

```json
"default_title": "Urban AdBlocker"
```

```json
"default_title": "Urban Browser Guard"
```

```json
"default_title": "Urban Safe Browsing"
```

```json
"default_title": "Urban VPN"
```

###### Homepage URL indicator

```json
"homepage_url": "https://www.urban-vpn.com/"
```

---

These can be found on the respective browser folders:

#### Microsoft Edge

```
C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\nimlmejbmnecnaghgmbahmbaddhjbecg\
```

#### Google Chrome

```
C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Extensions\eppiocemhmnlbhjplcgkofciiegomcon\
```

#### Brave Browser

```
C:\Users\<USER>\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Extensions\<EXTENSION_ID>\
```

#### Opera / Opera GX

```
C:\Users\<USER>\AppData\Roaming\Opera Software\Opera Stable\Extensions\<EXTENSION_ID>\
C:\Users\<USER>\AppData\Roaming\Opera Software\Opera GX Stable\Extensions\<EXTENSION_ID>\
```

> Note: Opera uses a Chromium base but stores profiles under `AppData\Roaming` instead of `Local`.

#### Vivaldi

```
C:\Users\<USER>\AppData\Local\Vivaldi\User Data\Default\Extensions\<EXTENSION_ID>\
```

#### Chromium (Open-source builds)

```
C:\Users\<USER>\AppData\Local\Chromium\User Data\Default\Extensions\<EXTENSION_ID>\
```

#### Yandex Browser

```
C:\Users\<USER>\AppData\Local\Yandex\YandexBrowser\User Data\Default\Extensions\<EXTENSION_ID>\
```

---

## 4. Volatile / network artifacts

### Local proxy usage

Browser extensions route traffic through a local proxy service using the following port:

```
8081
```
Part of the traffic doesn't get encrypted, making it possible to partially recover some of the visited URLs.

### HTTP proxy headers

When operating without authenticated user credentials, the following header is observed:

```
Proxy-Authorization: Basic SzRNbndkSFBNRnJqb181c1lxRDNmQk5uNU5RYmxEZGtKN2R0amJQZGR0UW9vSUhSNlVkMmJTVXNJbHBMVm1sN3hzbnA1bzYzUEVsT1ZwRmR1aUNtWUE9PTox
```

This header indicates proxy‑based traffic routing and can be used to identify Urban‑VPN traffic during network capture and analysis (The Contents of the header are subject to change.)
