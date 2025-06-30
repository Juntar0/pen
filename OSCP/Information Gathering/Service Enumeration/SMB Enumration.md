## nbtscan(recommend)
collect NetBIOS information
見つける場合はnbtscanでホストを発見後にenum4linuxが良い選択

```
sudo nbtscan -r 192.168.x.0/24
```
## nmap
find open ports
```
sudo nmap -n -v -Pn -p139,445 -sV --open 192.168.x.x-xxx
```

nmap scripts directory
```
ls /usr/share/nmap/scripts/smb*
```

smb-os-discovery
※ required: SMBv1 is enables on taget
```
sudo nmap -v -p 139,445 --script smb-os-discovery 192.168.x.x
```

## net
lists domains, resources, and computers belonging to a given host.
```
net view \\dc01 /all
```


## enum4linux
```
enum4linux -a IP
```

## smbclient
共有フォルダの確認( -L リスト表示、-N 認証なし)
```
smbclient -L -N IP
```

アクセス可能な共有に入る
```
smbclient //10.10.11.174/フォルダ名 -N
```