# port forwading

```

```

# reverse port forwarding
check ssh service
```
sudo systemctl start ssh
```

windows -> kali
```
ssh -N -T -R port(windows):127.0.0.1:port(kali) kali@192.168.x.x
```

kali -> remote host
local port on remote host to a local port on Kali.
```
ssh -L [KALI_LOCAL_PORT]:localhost:[REMOTE_PORT] user@remote_host
```