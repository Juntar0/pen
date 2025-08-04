# rustscan
## command
```
rustscan -a ./hosts.txt -- -sV -A -oN rustscan.txt
```
## result

### summary
```
Open 192.168.247.189:25
Open 192.168.247.245:21
Open 192.168.247.191:80
Open 192.168.247.245:80
Open 192.168.247.246:80
Open 192.168.247.247:80
Open 192.168.247.248:80
Open 192.168.247.249:80
Open 192.168.247.189:110
Open 192.168.247.189:135
Open 192.168.247.191:135
Open 192.168.247.247:135
Open 192.168.247.248:135
Open 192.168.247.249:135
Open 192.168.247.250:135
Open 192.168.247.189:139
Open 192.168.247.191:139
Open 192.168.247.247:139
Open 192.168.247.248:139
Open 192.168.247.249:139
Open 192.168.247.250:139
Open 192.168.247.189:143
Open 192.168.247.189:587
Open 192.168.247.245:443
Open 192.168.247.246:443
Open 192.168.247.250:445
Open 192.168.247.249:445
Open 192.168.247.248:445
Open 192.168.247.247:443
Open 192.168.247.247:445
Open 192.168.247.191:445
Open 192.168.247.189:445
Open 192.168.247.245:2222
Open 192.168.247.246:2222
Open 192.168.247.191:3389
Open 192.168.247.247:3389
Open 192.168.247.248:3389
Open 192.168.247.249:3389
Open 192.168.247.250:3389
Open 192.168.247.250:5040
Open 192.168.247.191:5985
Open 192.168.247.189:5985
Open 192.168.247.247:5985
Open 192.168.247.248:5985
Open 192.168.247.249:5985
Open 192.168.247.245:8000
Open 192.168.247.249:8000
Open 192.168.247.247:14020
Open 192.168.247.247:14080
Open 192.168.247.189:47001
Open 192.168.247.191:47001
Open 192.168.247.247:47001
Open 192.168.247.248:47001
Open 192.168.247.249:47001
Open 192.168.247.191:49664
Open 192.168.247.189:49664
Open 192.168.247.247:49664
Open 192.168.247.248:49664
Open 192.168.247.189:49665
Open 192.168.247.249:49664
Open 192.168.247.191:49665
Open 192.168.247.250:49664
Open 192.168.247.248:49665
Open 192.168.247.249:49665
Open 192.168.247.247:49665
Open 192.168.247.189:49666
Open 192.168.247.250:49665
Open 192.168.247.191:49666
Open 192.168.247.247:49666
Open 192.168.247.248:49666
Open 192.168.247.249:49666
Open 192.168.247.250:49666
Open 192.168.247.189:49667
Open 192.168.247.191:49667
Open 192.168.247.247:49667
Open 192.168.247.248:49667
Open 192.168.247.249:49667
Open 192.168.247.189:49668
Open 192.168.247.191:49668
Open 192.168.247.250:49667
Open 192.168.247.247:49668
Open 192.168.247.248:49668
Open 192.168.247.249:49668
Open 192.168.247.189:49669
Open 192.168.247.250:49668
Open 192.168.247.191:49669
Open 192.168.247.247:49669
Open 192.168.247.248:49669
Open 192.168.247.250:49669
Open 192.168.247.249:49669
Open 192.168.247.189:49670
Open 192.168.247.191:49670
Open 192.168.247.248:49670
Open 192.168.247.247:49670
Open 192.168.247.250:49670
Open 192.168.247.191:49671
Open 192.168.247.248:49965

```
### 189
```
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sV -A -oN rustscan.txt" on ip 192.168.247.189
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-18 02:13 JST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:13
Completed NSE at 02:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:13
Completed NSE at 02:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:13
Completed NSE at 02:13, 0.00s elapsed
Initiating Ping Scan at 02:13
Scanning 192.168.247.189 [2 ports]
Completed Ping Scan at 02:13, 0.09s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 02:13
Completed Parallel DNS resolution of 1 host. at 02:13, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 02:13
Scanning 192.168.247.189 [16 ports]
Discovered open port 135/tcp on 192.168.247.189
Discovered open port 25/tcp on 192.168.247.189
Discovered open port 587/tcp on 192.168.247.189
Discovered open port 139/tcp on 192.168.247.189
Discovered open port 110/tcp on 192.168.247.189
Discovered open port 143/tcp on 192.168.247.189
Discovered open port 445/tcp on 192.168.247.189
Discovered open port 49667/tcp on 192.168.247.189
Discovered open port 49669/tcp on 192.168.247.189
Discovered open port 49670/tcp on 192.168.247.189
Discovered open port 49664/tcp on 192.168.247.189
Discovered open port 49665/tcp on 192.168.247.189
Discovered open port 49666/tcp on 192.168.247.189
Discovered open port 49668/tcp on 192.168.247.189
Discovered open port 47001/tcp on 192.168.247.189
Discovered open port 5985/tcp on 192.168.247.189
Completed Connect Scan at 02:13, 0.19s elapsed (16 total ports)
Initiating Service scan at 02:13
Scanning 16 services on 192.168.247.189
Service scan Timing: About 62.50% done; ETC: 02:14 (0:00:33 remaining)
Completed Service scan at 02:13, 55.09s elapsed (16 services on 1 host)
NSE: Script scanning 192.168.247.189.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:13
Completed NSE at 02:14, 8.53s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:14
Completed NSE at 02:14, 2.80s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:14
Completed NSE at 02:14, 0.00s elapsed
Nmap scan report for 192.168.247.189
Host is up, received conn-refused (0.092s latency).
Scanned at 2024-05-18 02:13:04 JST for 66s

PORT      STATE SERVICE       REASON  VERSION
25/tcp    open  smtp          syn-ack hMailServer smtpd
| smtp-commands: MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
110/tcp   open  pop3          syn-ack hMailServer pop3d
|_pop3-capabilities: USER TOP UIDL
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
143/tcp   open  imap          syn-ack hMailServer imapd
|_imap-capabilities: IMAP4 ACL OK SORT completed QUOTA CAPABILITY IDLE CHILDREN NAMESPACE RIGHTS=texkA0001 IMAP4rev1
445/tcp   open  microsoft-ds? syn-ack
587/tcp   open  smtp          syn-ack hMailServer smtpd
| smtp-commands: MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: MAIL; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-05-17T17:14:01
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 20770/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 16769/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 52749/udp): CLEAN (Failed to receive data)
|   Check 4 (port 11086/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: -1s

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:14
Completed NSE at 02:14, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:14
Completed NSE at 02:14, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:14
Completed NSE at 02:14, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 67.01 seconds

```
### 191
```
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sV -A -oN rustscan.txt" on ip 192.168.247.191
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-18 02:11 JST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:11
Completed NSE at 02:11, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:11
Completed NSE at 02:11, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:11
Completed NSE at 02:11, 0.00s elapsed
Initiating Ping Scan at 02:11
Scanning 192.168.247.191 [2 ports]
Completed Ping Scan at 02:11, 0.09s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 02:11
Completed Parallel DNS resolution of 1 host. at 02:11, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 02:11
Scanning 192.168.247.191 [15 ports]
Discovered open port 80/tcp on 192.168.247.191
Discovered open port 3389/tcp on 192.168.247.191
Discovered open port 135/tcp on 192.168.247.191
Discovered open port 139/tcp on 192.168.247.191
Discovered open port 445/tcp on 192.168.247.191
Discovered open port 49667/tcp on 192.168.247.191
Discovered open port 49666/tcp on 192.168.247.191
Discovered open port 5985/tcp on 192.168.247.191
Discovered open port 47001/tcp on 192.168.247.191
Discovered open port 49669/tcp on 192.168.247.191
Discovered open port 49670/tcp on 192.168.247.191
Discovered open port 49671/tcp on 192.168.247.191
Discovered open port 49668/tcp on 192.168.247.191
Discovered open port 49664/tcp on 192.168.247.191
Discovered open port 49665/tcp on 192.168.247.191
Completed Connect Scan at 02:11, 0.18s elapsed (15 total ports)
Initiating Service scan at 02:11
Scanning 15 services on 192.168.247.191
Service scan Timing: About 53.33% done; ETC: 02:13 (0:00:48 remaining)
Completed Service scan at 02:12, 55.11s elapsed (15 services on 1 host)
NSE: Script scanning 192.168.247.191.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:12
Completed NSE at 02:13, 8.55s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:13
Completed NSE at 02:13, 0.42s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:13
Completed NSE at 02:13, 0.00s elapsed
Nmap scan report for 192.168.247.191
Host is up, received syn-ack (0.091s latency).
Scanned at 2024-05-18 02:11:59 JST for 64s

PORT      STATE SERVICE       REASON  VERSION
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=192.168.247.191
|_http-title: 401 - Unauthorized: Access is denied due to invalid credentials.
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
| ssl-cert: Subject: commonName=login.relia.com
| Issuer: commonName=login.relia.com
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-04-07T16:54:43
| Not valid after:  2024-10-07T16:54:43
| MD5:   6905:c267:fa78:3014:588e:857e:8e5c:9fb8
| SHA-1: d7a7:fb27:c9af:85b6:7386:62f0:96a6:975c:c507:b6c8
| -----BEGIN CERTIFICATE-----
| MIIC4jCCAcqgAwIBAgIQcKMEMdZ6xr5F2NRqZQ5ogDANBgkqhkiG9w0BAQsFADAa
| MRgwFgYDVQQDEw9sb2dpbi5yZWxpYS5jb20wHhcNMjQwNDA3MTY1NDQzWhcNMjQx
| MDA3MTY1NDQzWjAaMRgwFgYDVQQDEw9sb2dpbi5yZWxpYS5jb20wggEiMA0GCSqG
| SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDgQIm8wIlsqz2zFZc9fOn+V/g9m/s6sI1d
| bIh4OA4OGk9COCJIhhENXmdrgR6WIIv3i+1xx3/APd8i1YFNC3v5Y+tpo3vZGQ+H
| EuHknZ+e5DFhiBpET6HVB4lfHedKRcCMxax7lT7bcex79XVcji9C3I2Bm3aLk2ph
| rE9kpyMPOdl76rVgq4u6sUFvemPC5tES/jmw2EHIU/fHzc28qTpTYSWnhzUGtc77
| ccI7ce7HZCUbAlAce97rOMOJnB3lrzjH1nPMjZ2jc5km9EyeVOGFuTExYW2fBsBI
| YxVG/agfvOiJf8VZiKIWPZqssoIzN5W0iSHFg1nNCQ6h6EbWP0MdAgMBAAGjJDAi
| MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsF
| AAOCAQEAn+u7wxtGSfE+uzZ+ZlTVU1f4gwcuQnQ7rkQqDyl8C/P9PIW1/UxgXlgL
| aS6VFX+4xuQ0OtZ2R4+1/omw4ZAdFvvQc8NicJAQC/+11Kqi4MReBzWnMmCopXNM
| v7R/xuJgThpVbWK7HPXx7qfpDhTbBhBdW4DcINjymCcl/BgGz+wOJywHChQKOMAe
| A/TsvSAmRQ1ShMW4V6dedi/SPONc6wSTBeCPAx8HTZc41oyBgEmQGmHqkVoPtdxL
| pNEPdFiqd6lRurMyVaml9NusKFTbL4YWhpqBuhVWG2bpNNdPBcWWooLK4Wg5JYo5
| FOI7wjVMO7hbCv9VZTh11uEHjdpeZA==
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: RELIA
|   NetBIOS_Domain_Name: RELIA
|   NetBIOS_Computer_Name: LOGIN
|   DNS_Domain_Name: relia.com
|   DNS_Computer_Name: login.relia.com
|   DNS_Tree_Name: relia.com
|   Product_Version: 10.0.20348
|_  System_Time: 2024-05-17T17:12:55+00:00
|_ssl-date: 2024-05-17T17:13:03+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-05-17T17:12:56
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 28052/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 53348/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 63375/udp): CLEAN (Timeout)
|   Check 4 (port 56814/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 0s, deviation: 0s, median: 0s

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:13
Completed NSE at 02:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:13
Completed NSE at 02:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:13
Completed NSE at 02:13, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 64.60 seconds

```



### 245
```
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sV -A -oN rustscan.txt" on ip 192.168.247.245
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-18 02:15 JST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:15
Completed NSE at 02:15, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:15
Completed NSE at 02:15, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:15
Completed NSE at 02:15, 0.00s elapsed
Initiating Ping Scan at 02:15
Scanning 192.168.247.245 [2 ports]
Completed Ping Scan at 02:15, 0.09s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 02:15
Completed Parallel DNS resolution of 1 host. at 02:15, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 02:15
Scanning 192.168.247.245 [5 ports]
Discovered open port 443/tcp on 192.168.247.245
Discovered open port 21/tcp on 192.168.247.245
Discovered open port 80/tcp on 192.168.247.245
Discovered open port 8000/tcp on 192.168.247.245
Discovered open port 2222/tcp on 192.168.247.245
Completed Connect Scan at 02:15, 0.09s elapsed (5 total ports)
Initiating Service scan at 02:15
Scanning 5 services on 192.168.247.245
Completed Service scan at 02:15, 12.49s elapsed (5 services on 1 host)
NSE: Script scanning 192.168.247.245.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:15
NSE: [ftp-bounce 192.168.247.245:21] PORT response: 500 Illegal PORT command.
Completed NSE at 02:15, 3.59s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:15
Completed NSE at 02:15, 1.71s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:15
Completed NSE at 02:15, 0.00s elapsed
Nmap scan report for 192.168.247.245
Host is up, received syn-ack (0.091s latency).
Scanned at 2024-05-18 02:15:32 JST for 18s

PORT     STATE SERVICE  REASON  VERSION
21/tcp   open  ftp      syn-ack vsftpd 2.0.8 or later
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.218
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp   open  http     syn-ack Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8)
| http-methods: 
|   Supported Methods: POST OPTIONS HEAD GET TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.49 (Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8
|_http-title: RELIA Corp.
443/tcp  open  ssl/http syn-ack Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8)
|_http-server-header: Apache/2.4.49 (Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8
| ssl-cert: Subject: commonName=web01.relia.com/organizationName=RELIA/stateOrProvinceName=Berlin/countryName=DE/organizationalUnitName=IT Department/localityName=Munich
| Issuer: commonName=web01.relia.com/organizationName=RELIA/stateOrProvinceName=Berlin/countryName=DE/organizationalUnitName=IT Department/localityName=Munich
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-10-12T08:55:44
| Not valid after:  2032-10-09T08:55:44
| MD5:   fa8f:53d5:841c:47dc:ac0c:8d5a:3acb:43a7
| SHA-1: 9fd6:3372:2dfd:ed09:0915:6b60:2604:b238:f02a:eab7
| -----BEGIN CERTIFICATE-----
| MIIFwzCCA6ugAwIBAgIUeHYKv7Q6RVr2ddFUOW0AXtsILAEwDQYJKoZIhvcNAQEL
| BQAwcTELMAkGA1UEBhMCREUxDzANBgNVBAgMBkJlcmxpbjEPMA0GA1UEBwwGTXVu
| aWNoMQ4wDAYDVQQKDAVSRUxJQTEWMBQGA1UECwwNSVQgRGVwYXJ0bWVudDEYMBYG
| A1UEAwwPd2ViMDEucmVsaWEuY29tMB4XDTIyMTAxMjA4NTU0NFoXDTMyMTAwOTA4
| NTU0NFowcTELMAkGA1UEBhMCREUxDzANBgNVBAgMBkJlcmxpbjEPMA0GA1UEBwwG
| TXVuaWNoMQ4wDAYDVQQKDAVSRUxJQTEWMBQGA1UECwwNSVQgRGVwYXJ0bWVudDEY
| MBYGA1UEAwwPd2ViMDEucmVsaWEuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
| MIICCgKCAgEAsY6LfzTZE+dzfwOewiq+M27qwGIR6RP98e8SeE5/BFWcuI+C0v0q
| iEjF+srnl8uXzcrcQI2UoAltroZSlWODmXW2azKMqmhVnVHUR1QDthJdU70aNzEN
| uAYaZiVtqjtjeIGvPNiaCmtfZ/2J8ows8R5eh/RRLBA7QCPJrnbeCEodKY8oyHLK
| KyBiu83Qrz0QsgOFDd/grmcGh+LqXaGfKE7mO8qazGxwDCCbTUEG6W/xK1gG74TL
| OkstIlBODsdr9s4dPobMSmT0TsOCcwzBGgyMVyYf3eiD1Xqz6ysrxwxPvRmNOa3c
| P5Hj6gn2SgAqP4sZEgy47k6XuSz7ZGDDG473SE4FFJ9bt7PQ77onCsiav2icJ52v
| JMWbTpErXaTvkcsbxS1xgEfD/1+XeoAe3cfKu4BEZMwZ61a2sgnOWZfIH5Is/g3X
| 4f1/b0oFDWxH/Xz/eHouZpLbu64Jil0+WVG4eI5dY/x/F2y/uSjmO2NTxQhO5nHl
| Xf1kiPLDO4iKbtyf3G4sSwVUyXXiQREE69eKtQIiVhfoEJ7CCYakNXBLdcReemTV
| W48FqqKWhJ+27mhMUAj42mCLjDb8DUBmLPYMpkxupbN2osiATuHO9diBFMTZ27Oh
| BOp9S7MpYl1y9iybUnISwMFxjORLWyBC4rAmzu59yYErbvUi12ge/AkCAwEAAaNT
| MFEwHQYDVR0OBBYEFA6/MNuj3vksQVoClyEc0RHjulrJMB8GA1UdIwQYMBaAFA6/
| MNuj3vksQVoClyEc0RHjulrJMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
| BQADggIBAFsl8YDtmYCcjjC1Oja36hpyktF1LWEuVpR/eBXzwmfxxqyRZ/BTnARx
| Mj83mvizGUBEp3OgaJtAPlvBZr/lb8VT+DE7Y32ULBAboC0cpAtCl1+sjsFpy943
| 5RUZZqqIi4nfu12yIxsvVTiGzmPOoWjZuHQ60qgZBhPDUggbqySR2NBjYddGzxlx
| N4J02WB19bv1Z56G48YPMxKmweIvmXrRqs/cKRCy6p0j/8dp9us7MwEMgbGm8EPp
| Z59LYoD6V6KgX2ybhCtt1sPINuwGZ8DCnc5Hyk9Nvr791euzIpIcFhxXHmUGNwil
| HuCulKvaX3jEujG3PDOONuN7sqXdzWbIbj0MuRJGwMLRjFmSgg4XA5CMAHtHAeiT
| /S8cjaLwDptGLrgHvQhjfbvuC+2Qk3HCZC4bZdWBEjr62VmLiGynXI+6VtYNlAj8
| eJYf2lAGpJjwVh+ZtZE9dh2fIPxLTkwS69H2yzl0KfWJX0I/u0dJGD5lTb/21nfe
| Q8AwiecYICAggab3VcY5RzSSZ0Iwc7b5AijjqP4WBPasCQWcCG3l7uOoAsY/21eg
| FQbyRupm5N2B0+BMBNNA4o7z75mMpe/liQyeRBWlrrU4a9aX9iDKQRN2stfmxeBx
| ocvN1oS/2IZbuPCdsg7/xgo+CplY0cBFwHFz8mhspJbvaFzQXWeA
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| http-methods: 
|   Supported Methods: POST OPTIONS HEAD GET TRACE
|_  Potentially risky methods: TRACE
|_http-title: RELIA Corp.
2222/tcp open  ssh      syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 30:0c:6c:9b:ac:07:47:5e:df:6d:ff:38:63:38:2a:fd (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCkRPaVboTfq+VZYyf1bsUlg+WZrPP1F6fRrA0TNkHmamfuFAhW9XfCiuh2GOnSkNeGUXLcMAgMtbki6uj4l6vTw5/pqM/jBz00be6Ty+g0CDz9gmb+p0iX+8vCeG6aB0vea9bvkjaABticCS1CmUEbfEe/jCn/11c4NmHleCFfVxE8PBRE2OyVWlFQkkcB74O0FS4AOfbnrAx3pAF4rcd7XsTgi4V1e/sKZ8RIcTlueVdnzZEMcpLeZXUR1cXsJ9zwklFLuMWuUjonYC7BFvT+Bf81jlO1/e9B0RxfalfCfeUthSoa2VGwpfvesCdHl0exvy1PXaeR2XUX5ZJ0jmoP7cvj1rb+ZrnUU/Sie0qpVklHpkjggz0li7Mk4h/CI+est9oeHP+UXVv+Xl/jpnXz/RX/1y03wkTe9Pygxo3NsLdrs22/UCQ5GZ5x78UJQBXCCI93KHY1BG28B9V8xT9PGmpFDgjnF3pFuZoMevmeHSVNBlNQV42/qFCJr48XbAM=
|   256 f3:a9:70:76:c8:d4:c4:17:f4:39:1f:be:58:9d:1f:a5 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK6SiUV5zqxqNJ9a/p9l+VpxxqiXnYri40OjXMExS/tP0EbTAEpojn4uXKOgR3oEaMmQVmI9QLPTehCFLNJ3iJo=
|   256 21:a0:79:82:2d:e6:2a:76:11:24:2f:7e:2e:a8:c7:83 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ9WPZpl/+VGWtnGi3tQSn1u5FAiDr9bKTV2xCUqje/c
8000/tcp open  http     syn-ack Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8)
|_http-title: Site doesn't have a title (text/html).
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.49 (Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8
| http-methods: 
|   Supported Methods: POST OPTIONS HEAD GET TRACE
|_  Potentially risky methods: TRACE
Service Info: Host: RELIA; OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:15
Completed NSE at 02:15, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:15
Completed NSE at 02:15, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:15
Completed NSE at 02:15, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.30 seconds

```


### 246
```
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sV -A -oN rustscan.txt" on ip 192.168.247.246
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-18 02:16 JST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:16
Completed NSE at 02:16, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:16
Completed NSE at 02:16, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:16
Completed NSE at 02:16, 0.00s elapsed
Initiating Ping Scan at 02:16
Scanning 192.168.247.246 [2 ports]
Completed Ping Scan at 02:16, 0.09s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 02:16
Completed Parallel DNS resolution of 1 host. at 02:16, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 02:16
Scanning 192.168.247.246 [3 ports]
Discovered open port 443/tcp on 192.168.247.246
Discovered open port 80/tcp on 192.168.247.246
Discovered open port 2222/tcp on 192.168.247.246
Completed Connect Scan at 02:16, 0.09s elapsed (3 total ports)
Initiating Service scan at 02:16
Scanning 3 services on 192.168.247.246
Completed Service scan at 02:17, 12.49s elapsed (3 services on 1 host)
NSE: Script scanning 192.168.247.246.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:17
Completed NSE at 02:17, 4.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:17
Completed NSE at 02:17, 1.75s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:17
Completed NSE at 02:17, 0.00s elapsed
Nmap scan report for 192.168.247.246
Host is up, received syn-ack (0.090s latency).
Scanned at 2024-05-18 02:16:56 JST for 18s

PORT     STATE SERVICE  REASON  VERSION
80/tcp   open  http     syn-ack Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Code Validation
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
443/tcp  open  ssl/http syn-ack Apache httpd 2.4.52 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
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
| tls-alpn: 
|_  http/1.1
|_http-title: Code Validation
|_ssl-date: TLS randomness does not represent time
2222/tcp open  ssh      syn-ack OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 42:2d:8d:48:ad:10:dd:ff:70:25:8b:46:2e:5c:ff:1d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEpVNr/0MSfOq95rNQVnUXG+NF7yHDkPeFEXylLHxnZSqLAEqWi+z67gxHF0QVSjtaeEVbOnind7C3LKLGe1b8g=
|   256 aa:4a:c3:27:b1:19:30:d7:63:91:96:ae:63:3c:07:dc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFcUmhqn+iJNZi0wDswh/Jusg6ZX0SGGoKcsNCB69vQA
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:17
Completed NSE at 02:17, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:17
Completed NSE at 02:17, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:17
Completed NSE at 02:17, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.77 seconds

```

### 247
```
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sV -A -oN rustscan.txt" on ip 192.168.247.247
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-18 02:14 JST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:14
Completed NSE at 02:14, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:14
Completed NSE at 02:14, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:14
Completed NSE at 02:14, 0.00s elapsed
Initiating Ping Scan at 02:14
Scanning 192.168.247.247 [2 ports]
Completed Ping Scan at 02:14, 0.09s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 02:14
Completed Parallel DNS resolution of 1 host. at 02:14, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 02:14
Scanning 192.168.247.247 [17 ports]
Discovered open port 80/tcp on 192.168.247.247
Discovered open port 139/tcp on 192.168.247.247
Discovered open port 445/tcp on 192.168.247.247
Discovered open port 135/tcp on 192.168.247.247
Discovered open port 3389/tcp on 192.168.247.247
Discovered open port 443/tcp on 192.168.247.247
Discovered open port 49667/tcp on 192.168.247.247
Discovered open port 49669/tcp on 192.168.247.247
Discovered open port 49668/tcp on 192.168.247.247
Discovered open port 5985/tcp on 192.168.247.247
Discovered open port 49666/tcp on 192.168.247.247
Discovered open port 49670/tcp on 192.168.247.247
Discovered open port 14080/tcp on 192.168.247.247
Discovered open port 49664/tcp on 192.168.247.247
Discovered open port 49665/tcp on 192.168.247.247
Discovered open port 14020/tcp on 192.168.247.247
Discovered open port 47001/tcp on 192.168.247.247
Completed Connect Scan at 02:14, 0.18s elapsed (17 total ports)
Initiating Service scan at 02:14
Scanning 17 services on 192.168.247.247
Service scan Timing: About 64.71% done; ETC: 02:15 (0:00:33 remaining)
Completed Service scan at 02:15, 62.73s elapsed (17 services on 1 host)
NSE: Script scanning 192.168.247.247.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:15
Completed NSE at 02:15, 16.24s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:15
Completed NSE at 02:15, 1.74s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:15
Completed NSE at 02:15, 0.00s elapsed
Nmap scan report for 192.168.247.247
Host is up, received syn-ack (0.091s latency).
Scanned at 2024-05-18 02:14:11 JST for 81s

PORT      STATE SERVICE       REASON  VERSION
80/tcp    open  http          syn-ack Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: RELIA - New Hire Information
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      syn-ack Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
| tls-alpn: 
|_  http/1.1
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
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
| http-methods: 
|_  Supported Methods: POST OPTIONS
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds? syn-ack
3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
|_ssl-date: 2024-05-17T17:15:30+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=WEB02
| Issuer: commonName=WEB02
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-03-29T21:13:19
| Not valid after:  2024-09-28T21:13:19
| MD5:   8de7:aa77:1bb9:b1b4:7171:2165:9190:97ee
| SHA-1: 12d0:4d32:f6d1:a78c:ed60:a39a:1d00:014f:e09f:efa7
| -----BEGIN CERTIFICATE-----
| MIICzjCCAbagAwIBAgIQG1XActHUL7tHdeHkV2el9zANBgkqhkiG9w0BAQsFADAQ
| MQ4wDAYDVQQDEwVXRUIwMjAeFw0yNDAzMjkyMTEzMTlaFw0yNDA5MjgyMTEzMTla
| MBAxDjAMBgNVBAMTBVdFQjAyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
| AQEAq7YTTp3QLpbmSzkz9k5pvC4wAMYLx0g8Cnq8raM5eh+D1E/bwaWBYXmZoe4z
| zEjtY+N/ln/UT0OX6vjgPaR59Q7iAuqTqwLd+BDe6Ngm8N4NOpYfkEqKZ5Ae0HLX
| tz+oaU8sOgEW/k1jSuDerR18opzOHeQwcxLIvlKSYO3YAp546tkv9YSr5jXNFWY5
| HTMNMBc8AOzS6QX4jL54cXext90uCoawNj8DtsBTnIEWPgZSIjSoBbmHt4u7Aq6A
| lOmbuspkiaVbzvCK9ByZ1X9X11jLJICDX+WrjoOuoxVjpCD7TGgXGTmp7InIM5N5
| MuCK5AHUUKC/r7YQDW0Yc7BkmQIDAQABoyQwIjATBgNVHSUEDDAKBggrBgEFBQcD
| ATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBAELl4vFr4kEv/t/Mc1ZM
| CqmOOjbovmHsY/iSnt60D042zyzz8bivQMlSdhZMSslK9QMNcna3VNfjF/hMmkTT
| 5ej9dkledmcOTjcfHOIKdINfamwoaEQ5Se4V0Zx4tciHNqrb7Vj182D1ltEK3vcf
| RaKNTaTckz2DRb/mjWViH2ge2LUEwfbgm+xRWfxiGotqsYmg6fHZQJXXJ11KSb18
| WoMGmMlwhUZ6kE8p4w1dvrC2gF69AZLPHV+hayPz6Dfxd7Jz8favxTUVWTnetncF
| DAuPPXeLCpk5GhxVbS0AyW0yJ9Vev1E2yFyYxvaNUS8qPQ7ycgvVhA9AAhga76a1
| aLk=
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: WEB02
|   NetBIOS_Domain_Name: WEB02
|   NetBIOS_Computer_Name: WEB02
|   DNS_Domain_Name: WEB02
|   DNS_Computer_Name: WEB02
|   Product_Version: 10.0.20348
|_  System_Time: 2024-05-17T17:15:15+00:00
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
14020/tcp open  ftp           syn-ack FileZilla ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r--r--r-- 1 ftp ftp         237639 Nov 04  2022 umbraco.pdf
|_ftp-bounce: bounce working!
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
14080/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Bad Request
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 24393/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 21264/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 42102/udp): CLEAN (Failed to receive data)
|   Check 4 (port 32950/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2024-05-17T17:15:15
|_  start_date: N/A
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:15
Completed NSE at 02:15, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:15
Completed NSE at 02:15, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:15
Completed NSE at 02:15, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 81.31 seconds

```

### 248
```
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sV -A -oN rustscan.txt" on ip 192.168.247.248
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-18 02:15 JST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:15
Completed NSE at 02:15, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:15
Completed NSE at 02:15, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:15
Completed NSE at 02:15, 0.00s elapsed
Initiating Ping Scan at 02:15
Scanning 192.168.247.248 [2 ports]
Completed Ping Scan at 02:15, 0.09s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 02:15
Completed Parallel DNS resolution of 1 host. at 02:15, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 02:15
Scanning 192.168.247.248 [15 ports]
Discovered open port 445/tcp on 192.168.247.248
Discovered open port 139/tcp on 192.168.247.248
Discovered open port 3389/tcp on 192.168.247.248
Discovered open port 135/tcp on 192.168.247.248
Discovered open port 80/tcp on 192.168.247.248
Discovered open port 5985/tcp on 192.168.247.248
Discovered open port 47001/tcp on 192.168.247.248
Discovered open port 49670/tcp on 192.168.247.248
Discovered open port 49669/tcp on 192.168.247.248
Discovered open port 49668/tcp on 192.168.247.248
Discovered open port 49664/tcp on 192.168.247.248
Discovered open port 49667/tcp on 192.168.247.248
Discovered open port 49665/tcp on 192.168.247.248
Discovered open port 49666/tcp on 192.168.247.248
Discovered open port 49965/tcp on 192.168.247.248
Completed Connect Scan at 02:15, 0.18s elapsed (15 total ports)
Initiating Service scan at 02:15
Scanning 15 services on 192.168.247.248
Service scan Timing: About 53.33% done; ETC: 02:17 (0:00:38 remaining)
Completed Service scan at 02:16, 55.08s elapsed (15 services on 1 host)
NSE: Script scanning 192.168.247.248.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:16
Completed NSE at 02:16, 8.85s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:16
Completed NSE at 02:16, 0.64s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:16
Completed NSE at 02:16, 0.00s elapsed
Nmap scan report for 192.168.247.248
Host is up, received syn-ack (0.091s latency).
Scanned at 2024-05-18 02:15:50 JST for 65s

PORT      STATE SERVICE       REASON  VERSION
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
| http-robots.txt: 16 disallowed entries 
| /*/ctl/ /admin/ /App_Browsers/ /App_Code/ /App_Data/ 
| /App_GlobalResources/ /bin/ /Components/ /Config/ /contest/ /controls/ 
| /Documentation/ /HttpModules/ /Install/ /Providers/ 
|_/Activity-Feed/userId/
|_http-title: Home
|_http-favicon: Unknown favicon MD5: 2DE6897008EB657D2EC770FE5B909439
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
| ssl-cert: Subject: commonName=EXTERNAL
| Issuer: commonName=EXTERNAL
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-03-29T20:11:03
| Not valid after:  2024-09-28T20:11:03
| MD5:   1cb7:0f15:a108:e1b8:172d:6c39:fac5:83ad
| SHA-1: f5e6:9058:74dc:994c:9663:02ca:f6ac:5b17:3c88:a334
| -----BEGIN CERTIFICATE-----
| MIIC1DCCAbygAwIBAgIQTPFRA/9oZIBPhOMHh9rz1DANBgkqhkiG9w0BAQsFADAT
| MREwDwYDVQQDEwhFWFRFUk5BTDAeFw0yNDAzMjkyMDExMDNaFw0yNDA5MjgyMDEx
| MDNaMBMxETAPBgNVBAMTCEVYVEVSTkFMMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEAsM7zUkCsctKKKBNixs8aEVbMf+KRuTbUXASUY1sD6mLTB7cMj/Lb
| +GOy+1rqBS3HLvKLJ7TkV5zItilowIPmcT1ZVwNahGVBgMltRhv4s8g0EwUX51k6
| QxzaIS7E5rzzSyJ0yuK0COSl2S1H2HxF3iE3PZVWKhLgPIuEB0Q8ycY3sUiJCyU2
| xZawrePsxpItrh5tIwcRy4Kw0abbJmHSeY6Dv/l3sQYsOyf9oX2KLxvUh96UHF/I
| DPUIjOUcAyB9bjYBL12y17+10xta6Gx4M20MhwZQ0NrLzgVDWVrpNpSMO0O8wmGP
| UFz17I+t85nmF3n3aMpihLU26QerV1MSSQIDAQABoyQwIjATBgNVHSUEDDAKBggr
| BgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBAGuIMFWlIe/w
| v84Mwi+XohIkUpdpY3cb6wBB3H/ua5I1LzR43G+Ati3FS4h9LWg73Q1Gayd/gma0
| HrkCa06TpWAqGUCRow/W+yo3s4TWj39EgKUTpEY1H1ZqDaymK5I8dud9SSoCTkhN
| 4IbnlZNqDRbzddWQigDkiXfWvcklVqoUDXbK7qB7U0ToPrqc+4uejBcqcBHHjfFX
| YI/bVwkPcKL/Ba1nZgAYfjndAjirVGcbtgwS5XMfE5GgHChuV+3vcaXP9sEKjvPF
| U+c/N4Hqax/fqmP1oVUv7ZfqhoKbp4m3/PZUaKthZvY4tdXX3KP3NVuhp59FaBKe
| 009XIEarbM4=
|_-----END CERTIFICATE-----
|_ssl-date: 2024-05-17T17:16:55+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: EXTERNAL
|   NetBIOS_Domain_Name: EXTERNAL
|   NetBIOS_Computer_Name: EXTERNAL
|   DNS_Domain_Name: EXTERNAL
|   DNS_Computer_Name: EXTERNAL
|   Product_Version: 10.0.20348
|_  System_Time: 2024-05-17T17:16:46+00:00
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack Microsoft Windows RPC
49965/tcp open  ms-sql-s      syn-ack Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2024-05-17T17:16:55+00:00; 0s from scanner time.
| ms-sql-info: 
|   192.168.247.248:49965: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 49965
| ms-sql-ntlm-info: 
|   192.168.247.248:49965: 
|     Target_Name: EXTERNAL
|     NetBIOS_Domain_Name: EXTERNAL
|     NetBIOS_Computer_Name: EXTERNAL
|     DNS_Domain_Name: EXTERNAL
|     DNS_Computer_Name: EXTERNAL
|_    Product_Version: 10.0.20348
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-03-30T20:11:08
| Not valid after:  2054-03-30T20:11:08
| MD5:   bbb3:82b7:788c:9893:800f:180c:efef:457b
| SHA-1: 1c5b:779e:d775:0567:68c6:8dd2:ddfc:aa94:0af5:22ac
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQF/nvjueajKZO8chBXrW9jTANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjQwMzMwMjAxMTA4WhgPMjA1NDAzMzAyMDExMDhaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM2tmOB8
| kV1hJiDOB2AxyjxjHaz0+ZZbTwJqta6YRoHq1HYQFhg5UM+lr5LGFM/WwrkbaCP9
| WaIr50CuEc1x8HViL7l143Rxam3kn5SYXKEsAea6JjtVidU78j3D3UWB2+I5X8l8
| /QyZfTRtCRZ4V0k0qbJVUjJ/yTwm+QmtrckaqI95oilHjBqVb9q/aPRS9UzJwo8Y
| yC4wGxDiuNZjLeVRGkjFlhIVEvv7e+WXWKq1a5Gas+Znm05AznIT5HUY6XFkNL0N
| K7krYwWd89Y610QnDlXky+QcGOgliQgWIzPyosQif/5qmYTpQa6aWQ7/T4LQ8LeO
| LqLVbUYjbQBZ9CECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAJepC0ErPICzvssZQ
| LA2/cWdeVmoBb1DjfpLH+3hbc7QKqcEFuub4sTXx///BRdJ9FKZzDqVbkU/WUlDp
| NRfFmacp9ETTGl/hJ2adeXiMR0Z1tWtSj+K2MdKX+ewaehK8ZIK+I+5KmiJDWzFN
| PlOWI4Sz61f9IISYFmteZ4L3JpILiIE1bm5p+aSOzcKW8XPsswUK8RHAAkSIz//7
| QS3HYhBHIwCUjwsS9xUcXqtt7U7i+oyI/SDCR4rk4aIpms0+xsJtPESFjRabyF7g
| woxSIl3gX4DwOmVtU538MPYhXdSAgyLc+cXDSNAUtyjDUjvaUrStyAZ3RzpFKO98
| kSINoA==
|_-----END CERTIFICATE-----
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 48654/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 39878/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 60141/udp): CLEAN (Timeout)
|   Check 4 (port 18871/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2024-05-17T17:16:50
|_  start_date: N/A

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:16
Completed NSE at 02:16, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:16
Completed NSE at 02:16, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:16
Completed NSE at 02:16, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.25 seconds

```

### 249
```
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sV -A -oN rustscan.txt" on ip 192.168.247.249
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-18 02:17 JST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:17
Completed NSE at 02:17, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:17
Completed NSE at 02:17, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:17
Completed NSE at 02:17, 0.00s elapsed
Initiating Ping Scan at 02:17
Scanning 192.168.247.249 [2 ports]
Completed Ping Scan at 02:17, 0.09s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 02:17
Completed Parallel DNS resolution of 1 host. at 02:17, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 02:17
Scanning 192.168.247.249 [14 ports]
Discovered open port 80/tcp on 192.168.247.249
Discovered open port 135/tcp on 192.168.247.249
Discovered open port 445/tcp on 192.168.247.249
Discovered open port 3389/tcp on 192.168.247.249
Discovered open port 139/tcp on 192.168.247.249
Discovered open port 47001/tcp on 192.168.247.249
Discovered open port 49666/tcp on 192.168.247.249
Discovered open port 49664/tcp on 192.168.247.249
Discovered open port 5985/tcp on 192.168.247.249
Discovered open port 49669/tcp on 192.168.247.249
Discovered open port 8000/tcp on 192.168.247.249
Discovered open port 49665/tcp on 192.168.247.249
Discovered open port 49667/tcp on 192.168.247.249
Discovered open port 49668/tcp on 192.168.247.249
Completed Connect Scan at 02:17, 0.18s elapsed (14 total ports)
Initiating Service scan at 02:17
Scanning 14 services on 192.168.247.249
Service scan Timing: About 64.29% done; ETC: 02:18 (0:00:31 remaining)
Completed Service scan at 02:18, 55.10s elapsed (14 services on 1 host)
NSE: Script scanning 192.168.247.249.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:18
Completed NSE at 02:18, 8.47s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:18
Completed NSE at 02:18, 0.42s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:18
Completed NSE at 02:18, 0.00s elapsed
Nmap scan report for 192.168.247.249
Host is up, received syn-ack (0.091s latency).
Scanned at 2024-05-18 02:17:14 JST for 65s

PORT      STATE SERVICE       REASON  VERSION
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: LEGACY
|   NetBIOS_Domain_Name: LEGACY
|   NetBIOS_Computer_Name: LEGACY
|   DNS_Domain_Name: LEGACY
|   DNS_Computer_Name: LEGACY
|   Product_Version: 10.0.20348
|_  System_Time: 2024-05-17T17:18:10+00:00
| ssl-cert: Subject: commonName=LEGACY
| Issuer: commonName=LEGACY
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-03-29T19:20:08
| Not valid after:  2024-09-28T19:20:08
| MD5:   37cc:5dc1:42dc:3db5:af2e:a5b1:22d6:7f6e
| SHA-1: 22c7:2202:888b:9126:9f8a:da50:a86b:468d:ebdd:2f38
| -----BEGIN CERTIFICATE-----
| MIIC0DCCAbigAwIBAgIQYJ7SeOenX45Md2MJoh2L7jANBgkqhkiG9w0BAQsFADAR
| MQ8wDQYDVQQDEwZMRUdBQ1kwHhcNMjQwMzI5MTkyMDA4WhcNMjQwOTI4MTkyMDA4
| WjARMQ8wDQYDVQQDEwZMRUdBQ1kwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
| AoIBAQCiXug6pNyeUi3PKGj5pud+WRg70sVILuvD9YxUcg1bgq4dKy7kbGrzCNFA
| gE9gZQNDrcvQOUYZYLAQrdyJ0bOlTyrPYTkqP8ETg2LrVLnFmUZnILGHgeQ1OS5e
| jjyG46v2P1EZfSOPIjEs9AJOeLA7wT/G15i234pX8XRNPfBTsxrNNagtvndvTTuG
| RcVo3ZWZmYuaaUVfjRTYcugXuoG9HKYWIMNqzPhwbUwYjptmASl3m6hOjXZD4PzU
| E85QY7ukj4PB00LAFS9noXmwTP9umnX+g8SbCU/5xU7VtDDj6cvuWPlcWPzQEfWv
| M97jT8CPmuzRUkbW1enSmgAUkcGlAgMBAAGjJDAiMBMGA1UdJQQMMAoGCCsGAQUF
| BwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsFAAOCAQEAXLLc8AXkJp5NYV1+
| GCVr/4wPWPO6548rJaW0vmh/uH5lXPoVatket639Dajs8eMi1S8yWDS/ctPTqV4z
| AHIGrPq+drWVyJ7obx3VdAoaGhmCKauqQaRkaQ9xvEE5pRRg3E8W4/8wODZ2d2w/
| mD+fD9lgceSJ6lzlgFmc3brU/ngk5xbU9ukfEZ5zHr16MxwY0NhE/aRDLr+l4C3c
| dNNQU2OH9zABEFGXdu8cU3Hk0KYK9S+s++08T6VwLJZF+WMFawZ78nZnEtXPrBYP
| 8nVZcwzVWNtP/A0PbFpd2dZXfEbzJvh0z7jskxjAcV+Y6bgRZMMMvxn/7MqD1FD5
| S8trNg==
|_-----END CERTIFICATE-----
|_ssl-date: 2024-05-17T17:18:18+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8000/tcp  open  http          syn-ack Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/7.4.30)
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.247.249:8000/dashboard/
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/7.4.30
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-open-proxy: Proxy might be redirecting requests
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-05-17T17:18:15
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 16327/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 48803/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 26089/udp): CLEAN (Timeout)
|   Check 4 (port 55430/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:18
Completed NSE at 02:18, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:18
Completed NSE at 02:18, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:18
Completed NSE at 02:18, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 64.58 seconds

```

### 250
```
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sV -A -oN rustscan.txt" on ip 192.168.247.250
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-18 02:09 JST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:09
Completed NSE at 02:09, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:09
Completed NSE at 02:09, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:09
Completed NSE at 02:09, 0.00s elapsed
Initiating Ping Scan at 02:09
Scanning 192.168.247.250 [2 ports]
Completed Ping Scan at 02:09, 0.09s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 02:09
Completed Parallel DNS resolution of 1 host. at 02:09, 0.00s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 02:09
Scanning 192.168.247.250 [12 ports]
Discovered open port 139/tcp on 192.168.247.250
Discovered open port 445/tcp on 192.168.247.250
Discovered open port 3389/tcp on 192.168.247.250
Discovered open port 135/tcp on 192.168.247.250
Discovered open port 49667/tcp on 192.168.247.250
Discovered open port 49670/tcp on 192.168.247.250
Discovered open port 49669/tcp on 192.168.247.250
Discovered open port 49666/tcp on 192.168.247.250
Discovered open port 49668/tcp on 192.168.247.250
Discovered open port 49665/tcp on 192.168.247.250
Discovered open port 49664/tcp on 192.168.247.250
Discovered open port 5040/tcp on 192.168.247.250
Completed Connect Scan at 02:09, 0.19s elapsed (12 total ports)
Initiating Service scan at 02:09
Scanning 12 services on 192.168.247.250
Service scan Timing: About 33.33% done; ETC: 02:11 (0:01:50 remaining)
Completed Service scan at 02:11, 158.76s elapsed (12 services on 1 host)
NSE: Script scanning 192.168.247.250.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:11
Completed NSE at 02:11, 14.95s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:11
Completed NSE at 02:11, 1.19s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:11
Completed NSE at 02:11, 0.00s elapsed
Nmap scan report for 192.168.247.250
Host is up, received conn-refused (0.092s latency).
Scanned at 2024-05-18 02:09:03 JST for 176s

PORT      STATE SERVICE            REASON  VERSION
135/tcp   open  msrpc              syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn        syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?      syn-ack
3389/tcp  open  ssl/ms-wbt-server? syn-ack
|_ssl-date: 2024-05-17T17:11:58+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=WINPREP
| Issuer: commonName=WINPREP
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-05-11T20:58:23
| Not valid after:  2024-11-10T20:58:23
| MD5:   34e4:d334:3856:76b5:1c25:bc2d:cd18:4a18
| SHA-1: ea7b:76d9:4a06:b1d2:a7aa:7c84:fac9:5b25:99ae:0510
| -----BEGIN CERTIFICATE-----
| MIIC0jCCAbqgAwIBAgIQdGtevstUboNJ4EvAQB4NHDANBgkqhkiG9w0BAQsFADAS
| MRAwDgYDVQQDEwdXSU5QUkVQMB4XDTI0MDUxMTIwNTgyM1oXDTI0MTExMDIwNTgy
| M1owEjEQMA4GA1UEAxMHV0lOUFJFUDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
| AQoCggEBALQWegb8SZ+Ypv2VWteqA1EIE1FPVm6ISmfn1DCGeEhVE0KPVy4bDX6q
| F0Bqm7suAw+9X2ptPqyspr4hn/qAMW+jm+y+v2xzLzJNJHXeuCf2gvrjIAS50+Fc
| cahTVJzacC8oN8JznnW2e2TrKYcR0nHfpBBvetzBiA1K1RuI+piAb7ZnD7N3+hQm
| ztV484lfIhLVFMitt/bDHZpz18Y3fiqB7Qtdftuuv1Zgwxq57BHwKCVttD8YD5Nx
| ZPTzETGc6kuLZPQ4RYPNG75Wt0PxQYEyzhZAIV3TwdPHOx+9Z5/jU1Oktu4p3On8
| Uiys5YQ92BZf3EkPwL1frwHb4ZqS7XECAwEAAaMkMCIwEwYDVR0lBAwwCgYIKwYB
| BQUHAwEwCwYDVR0PBAQDAgQwMA0GCSqGSIb3DQEBCwUAA4IBAQBfanlvS9XnGea5
| ZyDPlArR1AvY9UL7nkL5iVr96VINGuMUEHGtXvvrNT9LosLGj9bTuF3iN76JNJuI
| AMMcYVIgJqth5r7TKYG41YHOYhVxwHTwxOgAA9CzUdi9sLWU+y6aT56QAK1HD7Ts
| rfp939NUm7csWOiiGeUWo/AVD1ZMiMQhlr8Xm+i66t5eahETqLxAbzG8QCbRAelx
| BTowsRrstnhHTDtiRMm+KqBd5LsUvX+KCiUGRHp5gXeLGkHdGtDsyqpHSn+QL1fy
| NfqmznZms1D5UQvLBrqx+lAUyDXS+vTsA9r0tj1X8sfTiBvHjoEIncBaNSa1Uxpp
| nXcRJd7i
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: WINPREP
|   NetBIOS_Domain_Name: WINPREP
|   NetBIOS_Computer_Name: WINPREP
|   DNS_Domain_Name: WINPREP
|   DNS_Computer_Name: WINPREP
|   Product_Version: 10.0.22000
|_  System_Time: 2024-05-17T17:11:43+00:00
5040/tcp  open  unknown            syn-ack
49664/tcp open  msrpc              syn-ack Microsoft Windows RPC
49665/tcp open  msrpc              syn-ack Microsoft Windows RPC
49666/tcp open  msrpc              syn-ack Microsoft Windows RPC
49667/tcp open  msrpc              syn-ack Microsoft Windows RPC
49668/tcp open  msrpc              syn-ack Microsoft Windows RPC
49669/tcp open  msrpc              syn-ack Microsoft Windows RPC
49670/tcp open  msrpc              syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 14493/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 36041/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 41377/udp): CLEAN (Timeout)
|   Check 4 (port 64211/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2024-05-17T17:11:45
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 0s, deviation: 0s, median: 0s

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:11
Completed NSE at 02:11, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:11
Completed NSE at 02:11, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:11
Completed NSE at 02:11, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 175.55 seconds

```

