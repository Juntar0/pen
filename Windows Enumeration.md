# User infomation
```
whoami /all
```

# System Architecture
```
[System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE", [System.EnvironmentVariableTarget]::Process)
```

# administrators group users
```
net localgroup administrators
```
# AD Users
```
net user
net user USERNAME
```

# GPO
```
get-gpo -all
```

check for permissions our current user
```
get-gppermission -guid ID -targettype user -targetname USERNAME
```

# file search
```
Get-ChildItem -Path C:\ -Include local.txt -File -Recurse -ErrorAction SilentlyContinue
```