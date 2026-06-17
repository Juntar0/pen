アンチウイルスでペイロードをチェックする方法

Find-AVSignature
https://github.com/PowerShellMafia/PowerSploit/blob/master/AntivirusBypass/Find-AVSignature.ps1

ps1ファイルがある場所でインポート
```powershell
Import-Module .\Find-AVSignature.ps1
```

開始バイト（-StartByte）、終了バイト（-EndByte）（`max`で最後まで対象にできる）、ファイルを区切る（-Interval）
入力ファイル（-Path）、出力フォルダ（-OutPath）、詳細出力（-Verbose）、強制的ファイル出力（-Force）
```powershell
Find-AVSignature -StartByte 0 -EndByte max -Interval 10000 -Path C:\Tools\met.exe -OutPath C:\Tools\avtest1 -Verbose -Force
```

ClamAVのスキャン機能でセグメントに区切ったファイルをスキャンして詳細に探していく
```powershell
cd 'C:\Program Files\ClamAV\'
.\clamscan.exe C:\Tools\avtest1
```