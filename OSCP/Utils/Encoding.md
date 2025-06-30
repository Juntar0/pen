# URL Encoding
## python

```
python3 -c "import urllib.parse; print(urllib.parse.quote(r'STRING'))"
```

for burp
```
python3 -c "import urllib.parse; print(urllib.parse.quote(r'STRING').replace('%20','+'))"
```

# Base64 Encoding
## powershell
for kali
```
pwsh
```

encoding
```
$command = 'PAYLOAD'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
[Convert]::ToBase64String($bytes)
```