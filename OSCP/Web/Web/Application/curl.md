## GET
basic
```
curl [オプション] <URL>
```

with header
```
curl -H "Authorization: Bearer <token>" <URL>
```


## POST
basic
```
curl -X POST -d '<データ>' <URL>
```

json data
```
curl -X POST -H "Content-Type: application/json" -d '{"username":"alice","password":"secret"}' <URL>
```


## PUT
basic
```
curl -X PUT -d '<データ>' <URL>
```

change users password
```
curl -X PUT \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <JWT>" \
  -d '{"password":"newpass123"}' \
  <URL>
```


## option list
| オプション                 | 説明                           | 使用例                                                                       |
| --------------------- | ---------------------------- | ------------------------------------------------------------------------- |
| `-X <METHOD>`         | HTTPメソッドを明示的に指定（GET, POSTなど） | `curl -X POST http://example.com/api/login`                               |
| `-d '<データ>'`          | リクエストボディにデータを指定（POST/PUT用）   | `curl -X POST -d 'username=admin&password=1234' http://...`               |
| `-H '<ヘッダー>'`         | HTTPヘッダーを追加                  | `curl -H "Content-Type: application/json" -H "Authorization: Bearer ..."` |
| `-i`                  | レスポンスのヘッダーも表示                | `curl -i http://example.com`                                              |
| `-s`                  | サイレントモード（進捗などを非表示）           | `curl -s http://example.com`                                              |
| `-k`                  | 自己署名証明書を許可（HTTPS用）           | `curl -k https://selfsigned.example.com`                                  |
| `-L`                  | リダイレクト（3xx）を自動で追従            | `curl -L http://example.com`                                              |
| `--proxy <host:port>` | 通信をプロキシ経由で行う                 | `curl --proxy 127.0.0.1:8080 http://target.com`                           |
| `-o <file>`           | レスポンスをファイルに保存                | `curl -o output.html http://example.com`                                  |
| `-u <user:pass>`      | ベーシック認証（Basic Auth）に使用       | `curl -u admin:password http://example.com/protected`                     |
