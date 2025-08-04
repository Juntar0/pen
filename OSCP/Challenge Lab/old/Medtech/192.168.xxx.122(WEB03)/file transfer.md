ftp server
```
sudo apt update
sudo apt install vfstp
```

setting
```
sudo vim /etc/vsftpd.conf

# Uncomment this to enable any form of FTP write command.
write_enable=YES   <---この項目のコメントアウト#を除去して有効化
```

start ftp server
```
sudo systemctl start vsftpd
```

connect to ftp server
```
ftp 192.168.45.167
kali
kali
```

file upload
```
put id_rsa
```