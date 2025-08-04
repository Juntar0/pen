### directry scan

## 246
```
feroxbuster -u http://192.168.247.246 -x txt,aspx,php,html,htm
```

```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.219.246
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 280]
/.hta                 (Status: 403) [Size: 280]
/.htpasswd            (Status: 403) [Size: 280]
/css                  (Status: 301) [Size: 316] [--> http://192.168.219.246/css/]
/fonts                (Status: 301) [Size: 318] [--> http://192.168.219.246/fonts/]
/index.php            (Status: 200) [Size: 1516]
/js                   (Status: 301) [Size: 315] [--> http://192.168.219.246/js/]
/server-status        (Status: 403) [Size: 280]
/submit               (Status: 301) [Size: 319] [--> http://192.168.219.246/submit/]
===============================================================
Finished
===============================================================
```

```
└─$ whatweb http://192.168.219.246
http://192.168.219.246 [200 OK] Apache[2.4.52], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[192.168.219.246], JQuery[1.12.4], Script, Title[Code Validation]
```
### 245
```
gobuster dir -u http://192.168.219.245 --wordlist /usr/share/wordlists/dirb/common.txt -z 
```

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://192.168.219.245 --wordlist /usr/share/wordlists/dirb/common.txt -z 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.219.245
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 199]
/.hta                 (Status: 403) [Size: 199]
/.htpasswd            (Status: 403) [Size: 199]
/css                  (Status: 301) [Size: 235] [--> http://192.168.219.245/css/]
/fonts                (Status: 301) [Size: 237] [--> http://192.168.219.245/fonts/]
/img                  (Status: 301) [Size: 235] [--> http://192.168.219.245/img/]
/index.html           (Status: 200) [Size: 46262]
/js                   (Status: 301) [Size: 234] [--> http://192.168.219.245/js/]
===============================================================
Finished
===============================================================
```

```
http://192.168.219.245 [200 OK] Apache[2.4.49][mod_wsgi/4.9.4], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Unix][Apache/2.4.49 (Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8], IP[192.168.219.245], JQuery, OpenSSL[1.1.1f], Python[3.8], Script[text/javascript], Title[RELIA Corp.], X-UA-Compatible[IE=edge]
```


### 247
```
feroxbuster -u http://192.168.247.247 -x txt,aspx,php,html,htm
```