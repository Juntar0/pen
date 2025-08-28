
# Connection
remote access
```
mysql -h hostname -u root -P 3306
mysql -h hostname -u root@localhost -P port
```

use password
```
mysql -h hostname -u root -p'password' -P 3306
```

skip ssl
```
mysql -h hostname -u root -p'root' -P 3306 --skip-ssl-verify-server-cert
```

help
```
mysql --help
```

# commands
version info
```
mysql version();
```

current session's user
```
select system_user();
```

listing all databases
```
show databases;
```

user's password
```
SELECT User, Host, authentication_string FROM mysql.user;
```

# post-exploitation
https://hackviser.com/tactics/pentesting/services/mysql#common-mysql-commands