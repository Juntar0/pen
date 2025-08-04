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
# Valid Credentials Check 
Check for valid credentials of logon-enabled users
```
nxc smb 192.168.x.x -u usres.txt -p passwords.txt --continue-on-success
``` 
# Check for Service Binary Hijacking
List of services with binary path
```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'} | findstr /i /v "C:\Windows"
```

check permissions
```
icacls PATH
```

icacls permission
```
|F|Full access
|M|Modify access
|RX|Read and execute access
|R|Read-only access
|W|Write-only access
```

# Check for DLL Hijacking
```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'} | findstr /i /v "C:\Windows"
```

check winPEASx64.exe (example)
```
================================================================================== 
    MySQL(MySQL)[C:\xampp\mysql\bin\mysqld.exe MySQL] - Autoload - No quotes and Space detected
    File Permissions: Authenticated Users [Allow: WriteData/CreateFiles]
    Possible DLL Hijacking in binary folder: C:\xampp\mysql\bin (Authenticated Users [Allow: WriteData/CreateFiles])
================================================================================== 
```
### check the binary folder
```
ls binaryfolder
```

check prcomon
```

```

standard DLL search order
```
1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory. 
5. The current directory.
6. The directories that are listed in the PATH environment variable.
```

# Check for Unquated Service Path
check unquated service
```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Out-String -Width 500 |findstr /i /v "C:\WINDOWS\" | findstr /i /v '\"'
```

example
```
C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
```

check for privilege
```
Start-Service GammaService
Stop-Service GammaService
```

find write permission
```
icacls "C:\"
icacls "C:\Program Files"
icacls "C:\Program Files\Enterprise Apps"
```

example : BUILTIN\Users:(OI)(CI)(RX,**W**) <- BUILDIN\Users has Write Permission
```
PS C:\Users\steve> icacls "C:\Program Files\Enterprise Apps"
C:\Program Files\Enterprise Apps NT SERVICE\TrustedInstaller:(CI)(F)
                                 NT AUTHORITY\SYSTEM:(OI)(CI)(F)
                                 BUILTIN\Administrators:(OI)(CI)(F)
                                 BUILTIN\Users:(OI)(CI)(RX,W)
                                 CREATOR OWNER:(OI)(CI)(IO)(F)
                                 APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(RX)
                                 APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(RX)

Successfully processed 1 files; Failed processing 0 files
```

# Check for Scheduled Tasks

get list of all scheduled tasks
```
schtasks /query /fo LIST /v
```

filtering 
```
chtasks /query /fo LIST /v | findstr /C:"Task To Run:" | findstr /V /I "system32 COM handler"
```

or
```
get-scheduledtask | where-object { $_.Author -and $_.Author -notmatch "Microsoft" -and $_.Author -ne "N/A" } | format-table taskname, taskpath, author, state
```

get taskinfo
```
$task = Get-ScheduledTask -TaskName "TASKNAME" -TaskPath "TASKPATH"
$info = Get-ScheduledTaskInfo -TaskName "TASKNAME" -TaskPath "TASKPATH"

[PSCustomObject]@{
    TaskName       = $task.TaskName
    Author         = $task.Author
    'Task To Run'  = ($task.Actions.Execute -join ', ')
    'Run As User'  = $task.Principal.UserId
    'Next Run Time'= $info.NextRunTime
}
```

permission on the task to run path
```
icacls PATH
```

# Find Vulnerable GPO
 check for the permissions our current user have over the GPONAME
```
import-module .\PowerView.ps1
Get-NetGPO | select displayname
Get-GPO -Name "GPONAME"
Get-GPPermission -Guid ID -TargetType User -TargetName USERNAME
```

ref:
```
https://medium.com/@raphaeltzy13/group-policy-object-gpo-abuse-windows-active-directory-privilege-escalation-51d8519a13d7
https://bit-bandits.com/sharpgpoabuse.html
```