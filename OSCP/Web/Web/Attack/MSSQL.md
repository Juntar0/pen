# Connections
access to mssql with impacket tools
```
impacket-mssqlclient Administrator:Lab123@ip -windows-auth
```

# Commands
windows OS version
```
SELECT @@version;
```

databases
```
SELECT name FROM sys.databases;
```

show tables in the database
```
SELECT * FROM database.information_schema.tables;
```

MSSQL rule
```
<データベース名>.<スキーマ名>.<テーブル名>
例：offsec.dbo.users
```

Exploring Users Table Records
```
select * from offsec.dbo.users;
```

show all objects in database
```
SELECT name FROM sys.all_objects;
```

show all objects in database and filter
```
SLECT name FROM sys.all_objects WHERE name LIKE '%user%'
```

# xp_cmdshell
configuration advanced options
```
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
```

enable xp_cmdshell
```
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

execute cmd
```
EXECUTE xp_cmdshell 'whoami';
```