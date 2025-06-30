## SCP

## HTTP

apache web server  

python web server  
カレントディレクトリのファイルをリモート側でダウンロードさせる  
```
python3 -m http.server
```

download command  
windows  
```
iwr -Uri "URL" -OutFile "保存先のファイルパス"
```
## SMB
impacket-smb server
```
impacket-smbserver root /home/kali
```
