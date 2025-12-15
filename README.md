<img width="584" height="111" alt="image" src="https://github.com/user-attachments/assets/c4f0782c-5c24-4227-94ae-a95e87544970" />

## CTF-Cargo-Hold
## Executive Summary

On 22 November 2025, the file server azuki-fileserver01 was compromised via the fileadmin account (high-privileged admin).
The attacker conducted reconnaissance, downloaded a malicious PowerShell payload from external IP 78.141.196.6, exfiltrated sensitive data
from multiple file shares (Contracts, Financial, IT-Admin, Shipping), dumped LSASS memory for credentials using ProcDump, 
established persistence via a registry Run key, and set up ongoing command-and-control (C2) beaconing to the same external IP.
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









