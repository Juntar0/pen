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

**ポイント：ドメインコントローラは常にこのフラグが有効**

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