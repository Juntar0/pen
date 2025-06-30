## nmap(not recommend)
nmapだとどのポート開いてるかわからない
find open ports
```
sudo nmap -n -v -sU -Pn --open -p 161 192.168.x.x-xxx
```

## onesixtyone(recommend)
Identify SNMP servers
```
echo public > community
for i in $(seq 1 254); do echo 192.168.x.$i; done > ips
onesixtyone -c community -i ips
```

## Management Information Base (MIB) Tree

| MIB OID                  | 説明                                         |
| ------------------------ | ------------------------------------------ |
| `1.3.6.1.2.1.25.1.6.0`   | **System Processes**<br>システム上で動作しているプロセスの数 |
| `1.3.6.1.2.1.25.4.2.1.2` | **Running Programs**<br>現在実行中のプログラム名一覧     |
| `1.3.6.1.2.1.25.4.2.1.4` | **Processes Path**<br>各プロセスの実行ファイルのパス      |
| `1.3.6.1.2.1.25.2.3.1.4` | **Storage Units**<br>ストレージ（ディスクなど）の使用状況    |
| `1.3.6.1.2.1.25.6.3.1.2` | **Software Name**<br>インストールされているソフトウェアの名前  |
| `1.3.6.1.4.1.77.1.2.25`  | **User Accounts**<br>ローカルユーザーアカウント一覧       |
| `1.3.6.1.2.1.6.13.1.3`   | **TCP Local Ports**<br>現在リッスンしているTCPポート一覧  |

## snmp walk

host information
```
snmpwalk -c public -v1 192.168.x.x 1.3.6.1.2.1.1
```

user account
```
snmpwalk -c public -v1 192.168.x.x 1.3.6.1.4.1.77.1.2.25
```

process name
```
snmpwalk -c public -v1 192.168.x.x 1.3.6.1.2.1.25.4.2.1.2
```

process and full path
```
snmpwalk -c public -v1 192.168.x.x 1.3.6.1.2.1.25.4.2.1.4
```

installed software
```
snmpwalk -c public -v1 192.168.x.x 1.3.6.1.2.1.25.6.3.1.2
```

tcp port scan
```
snmpwalk -c public -v1 <IPアドレス> 1.3.6.1.2.1.6.13.1.3
```

all
```
snmpwalk -c public -v1 192.168.x.x
```

all (ASCII)
```
snmpwalk -c public -v1 192.168.x.x -Oa
```