# User infomation
```
whoami /all
```

# administrators group users
```
net localgroup administrators
```
# AD Users
```
net user
net user USERNAME
```

# GPO
```
get-gpo -all
```

check for permissions our current user
```
get-gppermission -guid ID -targettype user -targetname USERNAME
```