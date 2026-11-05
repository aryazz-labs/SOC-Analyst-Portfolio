# Email Analysis | LetsDefend

## Overview

This investigation involved analysing a suspicious email that appeared to impersonate a legitimate company. The objective was to inspect the email, identify its sender and recipient, examine its headers, trace the originating IP address, and determine whether its attachment was malicious.

**Tools used:** Outlook, MXToolbox Email Header Analyzer, IPinfo, and VirusTotal.

## Investigation

### 1. Email Inspection

I started by downloading the email provided in the LetsDefend challenge and inspecting its contents.

I checked the basic email fields to identify the sender, recipient, and subject. I recorded the actual email address rather than relying only on the sender's display name, since display names can easily be spoofed.

- **Sender:** `yanting@united.com.sg`
- **Recipient:** `admin@malware-traffic-analysis.net`
- **Subject:** `united scientific equipment`

<img width="1100" height="633" alt="2" src="https://github.com/user-attachments/assets/551f2437-8757-4f1a-b6f9-ac42406df2f7" />

### 2. Email Header Analysis

Next, I examined the email headers to identify when the message was sent and trace its source.

I used the **MXToolbox Email Header Analyzer** to parse the raw headers into a more readable format. From the header analysis, I extracted the sending date and originating IP address.

- **Email date:** `02/08/2021`
- **Originating IP:** `71.19.248.52`

<img width="1100" height="384" alt="8" src="https://github.com/user-attachments/assets/4a7b6b16-3931-46b4-92f8-09d4f5017286" />

The originating IP was then checked using **IPinfo** to identify its associated country.

- **IP country:** `Canada`

<img width="1100" height="644" alt="12" src="https://github.com/user-attachments/assets/4b76b774-023b-45b7-b484-a665b14c9c7f" />

*Note: The originating IP is based on the available header and relay information. Email routing services can affect which IP appears in the headers.*

### 3. Attachment Extraction

I extracted the attachment from the downloaded challenge files and checked its filename.

- **Attachment filename:** `united scientific equipent.exe`

<img width="935" height="131" alt="14" src="https://github.com/user-attachments/assets/fff7b8eb-b236-4f4f-b44b-66066f4c6ea3" />

### 4. File Hash Identification

I submitted the attachment to **VirusTotal** to obtain its file hash and check whether security vendors had identified it as malicious.

I opened the file's **Details** tab and located its SHA-256 value.

- **SHA-256:** `9909753BFB0AC8AB165BAB3555233D03B01A9274A92E57C022F87CCBE51CA415`

<img width="829" height="538" alt="16" src="https://github.com/user-attachments/assets/dc8549cf-59d7-4d5f-8fa0-e6747953f28e" />

### 5. Malware Detection Check

Finally, I reviewed the VirusTotal detection results to determine whether the attachment was malicious.

The scan showed that **13 security vendors flagged the file as malicious**. This provided a strong indication that the attachment was unsafe.

- **Malicious attachment:** Yes
- **Detection results:** 13 security vendors flagged the file

<img width="1100" height="497" alt="18" src="https://github.com/user-attachments/assets/10a1b62f-ff23-4caf-9ae5-8b97c1c2c316" />

## Investigation Findings

| Investigation item | Result |
|---|---|
| Sender address | `yanting@united.com.sg` |
| Recipient address | `admin@malware-traffic-analysis.net` |
| Subject | `united scientific equipment` |
| Email date | `02/08/2021` |
| Originating IP | `71.19.248.52` |
| IP country | `Canada` |
| Attachment | `united scientific equipent.exe` |
| SHA-256 | `9909753BFB0AC8AB165BAB3555233D03B01A9274A92E57C022F87CCBE51CA415` |
| Attachment malicious? | Yes |
| VirusTotal detections | 13 vendors |

## Conclusion

The email was suspicious and its attachment was identified as malicious by 13 VirusTotal security vendors. By inspecting the email fields, analysing its headers, checking the originating IP, and scanning the attachment, I was able to collect the relevant indicators and establish that the attachment should not be trusted.

**Security note:** A malicious attachment should never be opened on a normal workstation. Any further examination should be performed in an isolated analysis environment.
