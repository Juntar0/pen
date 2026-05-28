ペイロードには被害端末上で実行される悪意のあるコードが含まれ、デコイはユーザーがトリガーとやり取りした後に表示させたいコンテンツ

## DLL sise-loading
DLLハイジャッキングとは、正規アプリケーションに悪意のあるDLLを読み込ませる技法
WindowsのDLL検索順序
- アプリケーションが存在するディレクトリ
- システムディレクトリ（通常 C:\Windows\System32）
- 16ビットシステムディレクトリ（通常 C:\Windows\System）
- Windowsディレクトリ（通常 C:\Windows）
- 現在の作業ディレクトリ
- PATH環境変数に含まれるディレクトリ

Process Monitorを使用して以下フィルタを設定
- The path ends in **.dll**.
- The result is **NAME NOT FOUND**.

現在はWindowsOSの組み込みアプリで脆弱性を見つけるのは難しいため、DLLサイドロードが重要

WinSxSにより、同一ライブラリの複数バージョンを共存させることが可能。Windowsアップデートでふるい依存ライブラリがこのディレクトリに保存されるため、脆弱な旧バージョンが残ってる可能性

古いバージョンのexe検索
```powershell
ls -Path C:\Windows\WinSxS -Recurse -Filter ngentask.exe | Select -expand FullName
```

## AppDomainManager
.NETアプリにDLLをロードさせる別の方法として、検索順序に依存しない方法。.NETのスタートアップフック

DLLは、ロード先の.NETアプリケーションと同じディレクトリに配置する必要
コード例
```c#

using System;
using System.Windows.Forms;

namespace AppDomainHijack;

public sealed class DomainManager : AppDomainManager
{
    public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
    {
        MessageBox.Show("Hello World", "Success");
    }
}

```

### アプリに DLL をロードさせる方法1
`APPDOMAIN_MANAGER_ASM`と`APPDOMAIN_MANAGER_TYPE`の2つの変数を利用

```powershell
$env:APPDOMAIN_MANAGER_ASM = 'AppDomainHijack, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null'
$env:APPDOMAIN_MANAGER_TYPE = 'AppDomainHijack.DomainManager'
```
変数が適切に設定されると、アプリケーションを実行することでDLLがロードされる

### アプリに DLL をロードさせる方法2
2つ目は`.config`内の`appDomainManagerAssembly`と`appDomainManagerType`を使用する方法

ファイル名にはアプリケーション名をプレフィックスとして付ける必要
例：`ngentask.exe.config`

```xml
<configuration>
   <runtime>
      <appDomainManagerAssembly value="AppDomainHijack, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />  
      <appDomainManagerType value="AppDomainHijack.DomainManager" />  
   </runtime>
</configuration>
```

## Windows Installer
インストーラ形式で、初期アクセス分類ではコンテナとしても機能する
セットアッププロジェクトを作成
![](images/Pasted%20image%2020260526125140.png)

ペイロード実行可能ファイルをアプリケーション ディレクトリに配置
任意の場所を右クリックし、追加>ファイルを選択して、ペイロード (`C:\Payloads\http_x64.exe`) を追加
![](images/Pasted%20image%2020260526125240.png)

ドロップ後に非表示にするか、ファイル名等を変更可能
![](images/Pasted%20image%2020260526131642.png)

インストール中にペイロードが実行されるアクションを追加
プロジェクトを右クリック>表示>カスタムアクションを選択
![](images/Pasted%20image%2020260526131746.png)

インストール手順を右クリック後、カスタムアクションの追加を選択
ポップアップウィンドウが表示されたら、アプリケーションフォルダを選択して、ペイロードファイルを選択
![](images/Pasted%20image%2020260526131824.png)

ぺイロードは64ビットなので、アクションプロパティでRun64BitをTrueに設定
引数なども渡すことが可能
![](images/Pasted%20image%2020260526131846.png)

プロジェクトのプロパティを変更して、インストーラーに会社名、製品名、対象プラットフォームなどを追加
![](images/Pasted%20image%2020260526131911.png)

プロジェクトをビルドした後（ビルド > ソリューションのビルド）、2 つのファイルが生成される
EXE は MSI を実行するためのラッパーにすぎないため、被害者に配布する際に含める必要なし

## Excel Add-in's
*.xlamファイルはExcelにカスタム機能を追加するために設計されたマクロ有効なExcelアドイン

保護ビューはMotWが含まれているファイル・電子メールの添付ファイル、または信頼されていない場所から開いたファイルを開くときにマクロを無効にする。
適切なコンテナを使用するとMotWを削除し、信頼できる場所の問題も会費可能

既定の信頼できる場所一覧
- %ProgramFiles%\Microsoft Office\root\Office16\Library\
- %ProgramFiles%\Microsoft Office\root\Office16\STARTUP\
- %ProgramFiles%\Microsoft Office\root\Office16\XLSTART\
- %ProgramFiles%\Microsoft Office\root\Templates\
- %APPDATA%\Microsoft\Excel\XLSTART\
- %APPDATA%\Microsoft\Templates\

標準ユーザーは `%ProgramFiles%` 配下のどのディレクトリにも書き込みを行うことはできないが、`%APPDATA%` には書き込み可能
Excel は XLSTART ディレクトリ内に存在するすべてのブック、テンプレート、またはアドインを自動的に読み込む

### 作り方
新しい空のワークブックを作成し、Alt+F11を使用してVBエディタを開く。
VBAProcejtを右クリックし、Inert>Module
![](images/Pasted%20image%2020260526132725.png)

マクロコードを追加
```vb
Private Sub Auto_Open()
   MsgBox "Hello World", vbOKOnly, "pwned"
End Sub
```

エディタを閉じて、File>Save AsからExcel Add-In(*.xlam)ファイルとして新規保存
XLAMファイルを`%APPDATA%\Microsoft\Excel\XLSTART`にコピーしてEXCELを再度開きなおす
![](images/Pasted%20image%2020260526132903.png)