# python server
```
python3 -m http.server
```

## SMB
server (linux)
```
impacket-smbserver test . -smb2support  -username kourosh -password kourosh
```

client (windows)
```
net use m: \\KALI_IP\test /user:kourosh kourosh
```

# Netcat
listener (linux)
```
nc -nvlp 9999 < file.txt
```

client (windows)
```
C:\Tools\nc.exe -nv KALI_IP 9999 > file.txt
```