# Malicious Document Analysis | LetsDefend

## 1. Overview

**Platform:** LetsDefend  
**Challenge:** Malicious Doc  
**Tools:** PowerShell, VirusTotal  
**Focus:** Static Malware Analysis, Behavioral Analysis, IOC Extraction

The objective was to investigate a suspicious document, identify the vulnerability it exploited, and extract indicators from its execution behavior.

## 2. Investigation

### 2.1 File Identification and Hash Analysis

I started by preparing an isolated environment for the investigation. The suspicious archive was not opened directly on my host machine.

I calculated its MD5 hash using PowerShell:

```powershell
Get-FileHash C:\Users\user1\Downloads\Fractura.zip -Algorithm MD5
```

**MD5:**
```text
05c137d8e79ce59ed6e4b7cd78e5b8a2
```

I used this hash to look up the file on VirusTotal.



### 2.2 VirusTotal – Initial Analysis

VirusTotal reported **44/62 security vendors** detecting the file as malicious, along with two sandbox detections.

I reviewed the individual vendor results and noticed repeated references to RTF-related detections.

The file was tagged with:

```text
rtf.exploit
```

I also checked the Details section to verify its file format. The document was identified as an RTF (Rich Text Format) file, with TrID identifying the format with 100% certainty.

<img width="1900" height="306" alt="Screenshot 2026-11-05 231000" src="https://github.com/user-attachments/assets/5f994b4b-cbc2-4423-9495-5f39487b5bbe" />

```text
----------------------------------------------------------------------------------------------------------------------
```

<img width="1882" height="676" alt="Screenshot 2026-11-05 231045" src="https://github.com/user-attachments/assets/1b873449-7cd5-4783-b411-db9d8c6c769e" />

```text
---------------------------------------------------------------------------------------------------------------------
```

<img width="1720" height="722" alt="Screenshot 2026-11-05 231224" src="https://github.com/user-attachments/assets/e7073055-ca3a-4787-8907-7209ed36e37a" />

### 2.3 Vulnerability Identification

I revisited the Security Vendors' Analysis section to identify the vulnerability associated with the document.

Multiple vendors referenced:

```text
CVE-2017-11882
```

This vulnerability affects Microsoft Office Equation Editor and can allow remote code execution through a specially crafted document.

This established the vulnerability associated with the malicious document.

### 2.4 Behavioral Analysis – Network Activity

The static analysis provided the initial indicators, but I needed to examine the file's execution behavior to identify its network activity and dropped files.

I opened the Behavior section in VirusTotal and reviewed the available sandbox results.

Under **Network Communication → HTTP Requests**, I identified a request associated with an executable named:

```text
jan2.exe
```

This indicated that the document attempted to retrieve an executable from an external source.

I then checked **IP Traffic** and identified the destination used during the communication:

```text
185.36.74.48:80
```

The traffic used TCP over port 80.

<img width="1656" height="775" alt="Screenshot 2026-11-05 231329" src="https://github.com/user-attachments/assets/786a4d5b-8980-4536-ad8d-111dd8a19f2c" />

### 2.5 Dropped File Identification

I continued examining the Behavior section, specifically **Files Written**, to identify files created during execution.

The analysis showed that the malware wrote an executable named:

```text
aro.exe
```

The file was dropped into:

```text
%APPDATA%\
```

This provided another indicator associated with the document's execution.

<img width="1486" height="730" alt="Screenshot 2026-11-05 231604" src="https://github.com/user-attachments/assets/f8133a55-bafe-48af-bc01-291bb2327bc4" />

## 3. Investigation Findings

The following indicators were extracted during the investigation:

| Indicator | Finding |
|---|---|
| Original Archive | `Fractura.zip` |
| MD5 | `05c137d8e79ce59ed6e4b7cd78e5b8a2` |
| Exploit Type | `rtf.exploit` |
| Vulnerability | `CVE-2017-11882` |
| Downloaded Executable | `jan2.exe` |
| Destination IP | `185.36.74.48` |
| Destination Port | `80/TCP` |
| Dropped Executable | `aro.exe` |
| Drop Location | `%APPDATA%\` |

## 4. Conclusion

The investigation identified a malicious RTF document associated with CVE-2017-11882.

VirusTotal's static analysis provided the initial detection evidence and vulnerability reference. Its behavioral analysis revealed an attempted executable download (`jan2.exe`), communication with `185.36.74.48` over TCP port 80, and a dropped executable (`aro.exe`) in the user's AppData directory.

The extracted indicators provide useful starting points for further endpoint investigation, threat hunting, and detection engineering.
