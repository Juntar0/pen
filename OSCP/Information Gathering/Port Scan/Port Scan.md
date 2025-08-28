### Rustscan
※ 並列で行わず単体で行う
※ 再度nmapでポートスキャンすること

host lists
```
sudo rustscan -a hosts.txt --ulimit 5000 -- -Pn -sC -sV -A -oN rustscan.txt
```

one host
```
sudo rustscan -a 192.168.x.x --ulimit 5000 -- -Pn -sC -sV -A -oN rustscan.txt
```

set batchsize and timeout (tunneling)
```
sudo rustscan -a 192.168.x.x -b 50 -t 3000 --ulimit 5000 -- -Pn -sC -sV -A -oN rustscan.txt
```
###  nmap
quick scan
```
sudo nmap -Pn -F -T4 192.168.x.x
```

0-10000 port scan
```
sudo nmap -Pn -sC -sV -T4 -p 0-10000 192.168.x.x
```

full scan
```
sudo nmap -p- -sC -sV -Pn 192.168.x.x
```

### netcat
tcp
```
nc -nvv -w 1 -z 192.168.x.x 120-123
```

udp
```
nc -nv -u -z -w 1 192.168.x.x 120-123
```