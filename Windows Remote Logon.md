# winrm
requirements
1. 5985 port
## evil-winrm
```
evilwinrm -i IP -u [domain\]user -p pass
```
# PsExec
requirements
1. user has administarotor local group
2. ADMIN$ share must be available
3. printer share on
## PsExec.exe
## impacket-psexec
```
impacket-psexec DOMAIN/USER@IP
```

# RDP
password logon
```
xfreerdp /u:USER /p:PASS /v:192.168.0.0
```