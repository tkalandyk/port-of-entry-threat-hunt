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


#1 Flag Query 
<img width="1228" height="132" alt="image" src="https://github.com/user-attachments/assets/18df3fd1-a7cd-4d7c-ac3b-3bb9df914e67" />

#1 Flag Query 

#1 Flag Query 

#1 Flag Query 

#1 Flag Query 

#1 Flag Query 

#1 Flag Query 

#1 Flag Query 

#1 Flag Query 

#1 Flag Query 

#1 Flag Query 

#1 Flag Query 

#1 Flag Query 

#1 Flag Query 

#1 Flag Query 
