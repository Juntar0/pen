MSSQLサーバに接続するのに有名なツール一覧
[PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)
[SQLRecon](https://github.com/skahwah/SQLRecon)
[SQL-BOF](https://github.com/Tw1sm/SQL-BOF)
[go-sqlcmd](https://github.com/microsoft/go-sqlcmd)
[HeidiSQL](https://www.heidisql.com/)
[SSMS](https://learn.microsoft.com/en-us/ssms/install/install)

CRTOでは主にSQL-BOFを利用する

## 列挙
### SPNs
SQLサーバインスタンスを列挙する方法はKeberos認証が利用されている前提で、ldapsearchで問い合わせる方法
```
ldapsearch (&(samAccountType=805306368)(servicePrincipalName=MSSQLSvc*)) --attributes name,samAccountName,servicePrincipalName
```
### PortScan
Kerberos認証がサポートされてないならポートで探す
arpをつけるとL2レベルで生存確認を先にする。1024はスレッド数
```
portscan 10.10.120.0/23 1433 arp 1024
```
### SQL server info
1434/UDPでSQLBrowserサービスが動作している場合、サーバ名、インスタンス、バージョン情報を入手可能
```
sql-1434udp 10.10.120.20
```

ユーザがパブリックロール持ってればさらに多くの情報を見れる。例えば、プロセスのPIDまで見ることが可能
```
sql-info lon-db-1
```

SQLインスタンスにおける現在のユーザーの権限に関する情報を照会
```
sql-whoami lon-db-1
```

### DB管理系のドメイングループを検索
```
ldapsearch (&(samAccountType=268435456)(|(name=*SQL*)(name=*DB*)(name=*Database*))) --attributes distinguishedName,member
```
- `samAccountType=268435456` → **グループオブジェクト**（`0x10000000`）に絞り込み
- `name=*SQL* OR *DB* OR *Database*` → DB管理系のグループ名を検索
- 取得属性は `distinguishedName` と `member`（メンバー一覧）
### Querying
パブリックロールでは、データベースインスタンスへのクエリを実行する権限も付与される
```
sql-query lon-db-1 "SELECT @@SERVERNAME"
```

SQL-BOFのほかのコマンド一覧

`sql-databases` : インスタンス上のDB一覧を取得
`sql-tables` : テーブル一覧取得
`sql-columns` : テーブルの列構造を確認
`sql-search` : キーワード検索（列名を横断検索可能）