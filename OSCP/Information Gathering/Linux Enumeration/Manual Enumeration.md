
### Information about the users
current user
```
id
```

all users
```
cat /etc/passwd
```

example:
```
joe:x:1000:1000:joe,,,:/home/joe:/bin/bash
```

| field | contents       | description                                                                 | example   |
| ----- | -------------- | --------------------------------------------------------------------------- | --------- |
| 1     | Login Name     | Username user to login                                                      | joe       |
| 2     | Password       | Password Hash(if x, the actual hash is sotred in /etc/shadow)               | x         |
| 3     | UID            | user ID( root is 0, regular users typically start from 1000)                | 1000      |
| 4     | GID            | Group ID (primary group the user belongs to)                                | 1000      |
| 5     | Comment        | User description or real name                                               | joe,,,    |
| 6     | Home Directory | Directory the user is placed in after login                                 | /home/joe |
| 7     | Login Shell    | Default shell ( if set to nologin, the account cannnot login interactively) | /bin/bash |
information about the hostname
```
hostname
```

### os system and architecture
os version
```
cat /etc/issue
```

os details
```
cat /etc/os-release
```

kernel version and architechture
```
uname -a
```

### running process
running processs single snapshot ( *check the high level privilege*)
```
ps aux
```

monitoring running processes
```
watch -n 1 "ps -aux | grep pass"
```

## network
full tcp/ip configuration on all available dapters
```
ip a
```

network routes
```
routel
```

active network connections
```
ss -anp
```

iptables
```
cat /etc/iptables/rules.v4
```

tcpdump sniffing
```
sudo tcpdump -i lo -A | grep "pass"
```

## Cronjob
all cron jobs
```
ls -lah /etc/cron*
```

cronjobs for current user
```
crontab -l
```

cronjobs for root user
```
sudo crontab -l
```

inspecting cron log file
```
grep "CRON" /var/log/syslog
```

```
tail -f /var/log/cron.log
```

## Packages
all installed packages
```
dpkg -l
```

## Listing Directory and File Permissions
find writable directories
```
find / -writable -type d 2>/dev/null
```

find writable files
```
find / -writable -type f 2>/dev/null
```
## Monting Drive
lists all drives that will be mounted at boot time
```
cat /etc/fstab
```

list all mounted filesystems
```
mount
```

view all available disks
```
lsblk
```

## driver and kernel module
listing loaded drivers
```
lsmod
```

information about a module
```
/sbin/modinfo libata
```

## Set-ID Permissions
SUID
```
find / -perm -u=s -type f 2>/dev/null
```

SGID
```
find / -perm -g=s -type f 2>/dev/null
```


## User Trails
Environment valiable
```
env
```

inspecting .bashrc
```
cat .bashrc
```

sudo capabilitis
```
sudo -l
```