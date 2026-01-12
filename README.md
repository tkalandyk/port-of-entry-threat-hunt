<img width="469" height="691" alt="image" src="https://github.com/user-attachments/assets/13582ec1-ca24-423b-8393-99a17001c109" />


# Incident Response Report

**Date of Report:** 2026-01-11  
**Severity Level:** HIGH  
**Report Status:** Open  
**Escalated To:** N/A  
**Incident ID:** IR-2025-11-AZUKI-01  
**Analyst:** Tywin Kalandyk  

---

## Summary of Findings

- Initial access was achieved via **Remote Desktop Protocol (RDP)** from a public IP address (**88.97.178.12**).
- The **kenji.sato** user account was compromised and used for interactive access.
- Post-compromise discovery included **network neighbor enumeration (`arp -a`)**.
- Malware was staged in a **hidden and system-marked directory** under `C:\ProgramData\WindowsCache`.
- **Windows Defender exclusions** were added for multiple file extensions and a temporary directory.
- A **Windows-native LOLBin (`certutil.exe`)** was abused to download a malicious payload.
- **Persistence** was established via a scheduled task masquerading as **“Windows Update Check.”**
- **Credential dumping** activity was observed using `mm.exe` and `sekurlsa::logonpasswords`.
- **Suspected data exfiltration** occurred via a compressed archive uploaded to **Discord**.
- **Log tampering** was performed, beginning with the **Security event log**.
- **Lateral movement** was attempted to an internal host using **RDP (`mstsc.exe`)**.

---

## WHO, WHAT, WHEN, WHERE, WHY, HOW

### WHO

**Attacker**
- Source IP: `88.97.178.12`
- C2 Infrastructure: `78.141.196.6`

**Compromised**
- Account: `kenji.sato`
- Backdoor Account: `support`
- System: `AZUKI-SL`

---

### WHAT

1. Remote access via RDP from a public IP  
2. Local network discovery using ARP  
3. Creation and concealment of a malware staging directory  
4. Defender exclusion configuration  
5. Malware download via certutil  
6. Persistence via scheduled task  
7. Credential dumping from memory  
8. Data staging and suspected exfiltration  
9. Log clearing to hinder detection  
10. Lateral movement attempt via RDP  

---

### WHEN (UTC)

| Date/Time (UTC) | Event |
|-----------------|-------|
| 2025-11-19 18:36:18 | Successful RDP logon from 88.97.178.12 |
| 2025-11-19 01:04:05 | Network neighbor enumeration (`arp -a`) |
| 2025-11-19 12:59:39 | Malware staging directory created and hidden |
| 2025-11-19 – 2025-11-20 | Persistence, credential access, exfiltration |

---

### WHERE

**Compromised Host**
- `AZUKI-SL`

**Infrastructure**
- Attacker IP: `88.97.178.12`
- C2 Server: `78.141.196.6:443`

**Malware Locations**
- `C:\ProgramData\WindowsCache\svchost.exe`
- `C:\ProgramData\WindowsCache\mm.exe`
- `C:\ProgramData\WindowsCache\export-data.zip`

---

### WHY

**Root Cause**
- Externally exposed RDP service combined with compromised credentials.
- Insufficient controls around Defender exclusions.

**Attacker Objective**
- Theft of sensitive pricing and supplier contract data for competitive advantage.

---

### HOW (Attack Chain)

1. RDP access obtained using compromised credentials  
2. Network discovery via ARP enumeration  
3. Hidden staging directory created in ProgramData  
4. Defender exclusions added to evade scanning  
5. Payload downloaded using certutil  
6. Scheduled task created for persistence  
7. Credentials dumped from memory  
8. Data archived and staged  
9. Data exfiltrated via Discord  
10. Security logs cleared  
11. Lateral movement attempted via RDP  

---

## Impact Assessment

**Actual Impact**
- Suspected exposure of sensitive pricing and supplier data
- Potential loss of competitive advantage

**Risk Level:** HIGH

---

## Recommendations

### Immediate
- Disable external RDP access
- Reset credentials for `kenji.sato` and `support`
- Remove malicious scheduled task and payloads

### Short-Term (1–7 Days)
- Audit and remove unauthorized Defender exclusions
- Review RDP authentication logs environment-wide

### Long-Term
- Enforce MFA for all remote access
- Restrict RDP behind VPN or gateway
- Enhance monitoring for LOLBin abuse and log tampering

---

## Appendix

### A. Indicators of Compromise

| Category | Indicator | Description |
|--------|----------|-------------|
| Attacker IP | 88.97.178.12 | Initial access source |
| C2 Server | 78.141.196.6 | Command and control |
| Malicious Files | svchost.exe, mm.exe | Payloads |
| Accounts | kenji.sato, support | Compromised/backdoor |

---

### B. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|------|-----------|----|---------|
| Initial Access | Remote Services | T1021.001 | RDP logon |
| Execution | Command & Scripting Interpreter | T1059 | PowerShell |
| Persistence | Scheduled Task | T1053.005 | Windows Update Check |
| Defense Evasion | Hidden Files & Directories | T1564.001 | WindowsCache |
| Credential Access | OS Credential Dumping | T1003 | sekurlsa |
| Lateral Movement | Remote Services | T1021 | mstsc.exe |
| Exfiltration | Web Services | T1567 | Discord |

---

### C. Investigation Timeline

| Time (UTC) | Event | Details |
|-----------|------|---------|
| 2025-11-19 18:36 | Initial access | RDP from public IP |
| 2025-11-19 | Discovery | ARP enumeration |
| 2025-11-19 | Persistence | Scheduled task |
| 2025-11-20 | Exfiltration | ZIP via Discord |

---

### D. Evidence & Screenshots

- Microsoft Defender for Endpoint telemetry
- Process, file, network, and registry events

---

### E. Investigation Queries


#1 Flag 🚩

```kql
Query used: DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where ActionType contains "logonsuccess" 
| project TimeGenerated,AccountName,ActionType,DeviceName,LogonType,RemoteIP, RemoteIPType
| order by TimeGenerated asc
```




<img width="1142" height="256" alt="image" src="https://github.com/user-attachments/assets/f32537ec-d6bd-471a-ac6d-92cef907085f" />




#2 Flag 🚩

```kql

Query used: DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where ActionType contains "logonsuccess" 
| project TimeGenerated,AccountName,ActionType,DeviceName,LogonType,RemoteIP, RemoteIPType
| order by TimeGenerated asc
```



<img width="587" height="223" alt="image" src="https://github.com/user-attachments/assets/8a684ae4-8e59-4cd0-888c-2a583e3f73d2" />




#3 Flag 🚩

```
Query used to find:
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "arp"
| project TimeGenerated, AccountDomain,AccountName,ActionType,DeviceName,FileName,InitiatingProcessAccountDomain,InitiatingProcessAccountName,InitiatingProcessFileName,ProcessCommandLine 
| order by TimeGenerated asc
```


 <img width="1164" height="218" alt="image" src="https://github.com/user-attachments/assets/6f671a37-116d-4579-b093-0b7b7cc111dd" />


#4 Flag 🚩

```
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "attrib"
|project TimeGenerated,DeviceName,FileName,FolderPath,ProcessCommandLine
|order by TimeGenerated asc
```

<img width="1042" height="226" alt="image" src="https://github.com/user-attachments/assets/60e7f256-1414-4682-b90a-f54598729561" />



#5 Flag🚩

```
DeviceRegistryEvents
| where DeviceName contains "azuki"
| where RegistryKey contains @"windows defender\exclusions\extensions"
| order by TimeGenerated asc
```

<img width="1051" height="122" alt="image" src="https://github.com/user-attachments/assets/de8b3061-c197-4384-bf05-ee586ca60e8b" />


#6 Flag 🚩

```
DeviceRegistryEvents
| where DeviceName contains "azuki"
| where RegistryKey contains @"Exclusions\Paths"
|project TimeGenerated,DeviceName,RegistryKey,RegistryValueName
| order by TimeGenerated asc
```

<img width="1021" height="193" alt="image" src="https://github.com/user-attachments/assets/14d9a12d-401f-400a-8756-cb21931243d0" />


#7 Flag 🚩

```
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "http" or ProcessCommandLine contains "https"
|project TimeGenerated,FileName,ProcessCommandLine,DeviceName
|order by TimeGenerated asc 
```

<img width="1043" height="267" alt="image" src="https://github.com/user-attachments/assets/ab517180-1c6a-4960-a639-cb8f31cee466" />


#8 Flag 🚩

```
DeviceProcessEvents
| where DeviceName contains "azuki" 
|where ProcessCommandLine contains "schtasks.exe" or ProcessCommandLine contains "/create"
|project TimeGenerated, FileName,ProcessCommandLine,DeviceName
|order by TimeGenerated asc 
```

 <img width="1056" height="226" alt="image" src="https://github.com/user-attachments/assets/564d28f9-0cab-479e-8585-ed8c1376382b" />


#9 Flag 🚩

```
DeviceProcessEvents
| where DeviceName contains "azuki" 
|where ProcessCommandLine contains "schtasks.exe" or ProcessCommandLine contains "/create"
|project TimeGenerated, FileName,ProcessCommandLine,DeviceName
|order by TimeGenerated asc 
```

 <img width="1068" height="276" alt="image" src="https://github.com/user-attachments/assets/63906d7d-780b-42be-88d8-2e656b0914ee" />


#10 Flag 🚩

```
DeviceNetworkEvents
| where DeviceName contains "azuki" 
|where InitiatingProcessFileName  == "svchost.exe"
| where InitiatingProcessFolderPath contains @"C:\ProgramData\WindowsCache"
| project TimeGenerated,RemoteIP,RemotePort,InitiatingProcessFileName,InitiatingProcessFolderPath
| sort by TimeGenerated asc 
```

<img width="1059" height="119" alt="image" src="https://github.com/user-attachments/assets/b4b1982b-f747-49ae-8868-b09b3f8f625d" />


#11 Flag 🚩

```
DeviceNetworkEvents
| where DeviceName contains "azuki" 
|where InitiatingProcessFileName  == "svchost.exe"
| where InitiatingProcessFolderPath contains @"C:\ProgramData\WindowsCache"
| project TimeGenerated,RemoteIP,RemotePort,InitiatingProcessFileName,InitiatingProcessFolderPath
| sort by TimeGenerated asc 
```

<img width="1004" height="146" alt="image" src="https://github.com/user-attachments/assets/889c7b84-76a4-4921-9092-81347525ce43" />


#12 Flag 🚩

```
DeviceFileEvents
|where FolderPath contains "WindowsCache"
| where FileName endswith ".exe"
|project TimeGenerated,DeviceName,FileName,FolderPath,InitiatingProcessFileName
| sort by TimeGenerated asc 
```

<img width="1059" height="235" alt="image" src="https://github.com/user-attachments/assets/44425eb8-f94a-42bf-be5d-fe661503ef8b" />


#13 Flag 🚩

```
DeviceProcessEvents
| where FolderPath contains "WindowsCache"
| where FileName endswith ".exe"
| project Timestamp, FileName, FolderPath, ProcessCommandLine
| sort by Timestamp asc
```


<img width="1059" height="235" alt="image" src="https://github.com/user-attachments/assets/e88c3ac7-54e9-4588-9127-4131d4e16639" />


#14 Flag 🚩

```
DeviceFileEvents
| where DeviceName contains "azuki"
|where ActionType == "FileCreated"
| where FileName endswith ".zip"
|where FolderPath contains @"C:\ProgramData\WindowsCache"
|project TimeGenerated, DeviceName,FileName,FolderPath
|order by TimeGenerated asc 
```


<img width="1062" height="129" alt="image" src="https://github.com/user-attachments/assets/b61f9896-41a2-47f6-aefd-8fa9bdee0f32" />



#15 Flag 🚩

```
DeviceNetworkEvents
| where DeviceName contains "azuki"
| where InitiatingProcessCommandLine contains "WindowsCache"
| project Timestamp, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| sort by Timestamp asc
```



<img width="1074" height="225" alt="image" src="https://github.com/user-attachments/assets/8917a9fe-a2c1-4c12-975b-95d724eb407e" />



#16 Flag 🚩

```
DeviceProcessEvents
| where DeviceName contains "azuki"
|where ProcessCommandLine contains "wevtutil"
|project TimeGenerated,DeviceName,FileName, ProcessCommandLine  
|order by TimeGenerated asc 
```
 

<img width="1055" height="276" alt="image" src="https://github.com/user-attachments/assets/22ee3520-abd6-4b76-9090-caf8adc32ad3" />



#17 Flag 🚩

```
DeviceProcessEvents
| where DeviceName contains "azuki"
|where ProcessCommandLine contains "/add"
|project TimeGenerated,DeviceName,FileName, ProcessCommandLine  
|order by TimeGenerated asc 
```


 <img width="1041" height="264" alt="image" src="https://github.com/user-attachments/assets/9453abc7-a2de-4c6d-85f1-d26ece95e8de" />
 


#18 Flag 🚩

```
DeviceFileEvents
| where DeviceName contains "azuki"
|where FileName endswith ".ps1"
|where ActionType == "FileCreated"
|where FolderPath contains "temp"
|project TimeGenerated,DeviceName,FileName,FolderPath, InitiatingProcessCommandLine  
|order by TimeGenerated asc 
```


 <img width="1067" height="271" alt="image" src="https://github.com/user-attachments/assets/fd7f886f-bb1f-43fd-8d85-9818be0329ad" />
 


#19 Flag 🚩

```
DeviceProcessEvents
| where DeviceName contains "azuki"
|where ProcessCommandLine contains "cmdkey" or ProcessCommandLine contains "mstsc"
| project TimeGenerated,DeviceName, FileName, ProcessCommandLine
|order by  TimeGenerated asc 
```


<img width="1115" height="269" alt="image" src="https://github.com/user-attachments/assets/eb96d2b0-a707-4ed6-8d55-15c7f71369f4" />



#20 Flag 🚩

```
DeviceProcessEvents
| where DeviceName contains "azuki"
|where ProcessCommandLine contains "10.1.0.188"
| project TimeGenerated,DeviceName, FileName, ProcessCommandLine
|order by  TimeGenerated asc 
```


 <img width="1060" height="191" alt="image" src="https://github.com/user-attachments/assets/45617f45-e5fc-4214-86f9-0b25c3c76f3f" />

