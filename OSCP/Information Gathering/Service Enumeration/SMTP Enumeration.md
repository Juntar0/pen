## nmap
find open ports
```
sudo nmap -n -v -Pn -p 25 -sV --open 192.168.x.x-xxx
```

## nc
open a connection
```
nc -nv 192.168.x.x 25
```

### Command
find validate SMTP users
```
VRFY root
```

### Response

| Response Code | 意味                                        | 状況/理由                  |
| ------------- | ----------------------------------------- | ---------------------- |
| 250           | OK（ユーザー存在）                                | ユーザー「root」が存在し、VRFYに成功 |
| 252           | Cannot VRFY user, but will accept message | 存在の確認はできないが、配送は試みる     |
| 550           | User unknown                              | 「root」というユーザーは存在しない    |
| 551           | User not local; please try <forward-path> | 他のホストにユーザーが存在          |
| 553           | Invalid address                           | アドレスが不正（構文エラーなど）       |
| 500           | Syntax error, command unrecognized        | VRFYが無効、または書式が間違っている   |
| 502           | Command not implemented                   | サーバがVRFYコマンドをサポートしていない |
| 504           | Command parameter not implemented         | VRFYのパラメータに問題          |
| 421           | Service not available                     | 一時的なサーバエラー（接続拒否など）     |
