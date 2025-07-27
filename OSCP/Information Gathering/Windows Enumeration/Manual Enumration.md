# Situational awareness
```
- Username and hostname
- Group memberships of the current user
- Existing users and groups
- Operating system, version and architecture
- Network information
- Installed applications
- Running processes
```

## username and group
obtain username and hostname
```
whoami
```

obtain group memberships of the current user
```
whoami /groups
```

obtain local users
```
ner user
get-localuser
```

obtain user info
```
net user USERNAME
```

obtain member of the group
```
get-localgroupmember GROUP
```

Remote Desktop Users (can access the system with RDP)
```
get-localgroupmember "Remote Desktop Users"
```

Remote Desktop Managements (can access it with WinRM.)
```
get-localgroupmember "Remote Management Users"
```

## system and network
information about the os system
```
systeminfo
```

information aboud the network config
```
ipconfig /all
```

obatain routing table
```
route print
```

obtain active network connection
```
netstat -ano
```

## gathering applications 
intalled 32bit application
```
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

installed 64bit application
```
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

running process
```
get-process
```

get process path
```
 Get-Process -Name PROCESSNAME -FileVersionInfo
```

## security patches
```
Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }
```
# Hidden in Plain View
search for password manager
```
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

Searching for sensitive information in XAMPP directory
```
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
```

Searching for text files and password manager databases in the home directory
```
Get-ChildItem -Path C:\Users\ -Include *.ini, *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

cmd
```
for %x in (ini txt pdf xls xlsx doc docx) do dir /s /b C:\Users\*.%x 2>nul
```

# Powershell Logs
powershell command history
```
get-history
```

path of the history file from PSReadline
```
(Get-PSReadlineOption).HistorySavePath
```

```
type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

Script Logging EventViewer
```
Go to Event Viewer → Events from Script Block Logging are in Application and Services → Microsoft → Windows → PowerShell → Operational
Click Filter Current Log and search for 4104 events. The event will be among the first top 5
```
# Password Spray
use nxc
```
nxc smb 192.168.x.x -u usres.txt -p passwords.txt --continue-on-success
```