# 攻撃概要
![[Pasted image 20260910231805.png]]

# テナント情報のエンドポイント

企業が認証にEntra IDを使用しているかどうかを手動確認エンドポイント
```
https://login.microsoftonline.com/getuserrealm.srf?login=megabigtech.com&xml=1
```

`.well-known/openid-configuration`エンドポイント
OAuth2.0, OIDCのIDフローでは必須のエンドポイントでEntraIDの情報を入手可能
```
https://login.microsoftonline.com/megabigtech.com/.well-known/openid-configuration
```

# AADInternals

### インストール
```powersehll
Install-Module AADInternals
Import-Module AADInternals
```

### 操作方法
テナントID取得
```powershell
Get-AADIntTenantID -Domain megabigtech.com
```

ドメイン情報列挙
```powershell
Invoke-AADIntReconAsOutsider -DomainName megabigtech.com
```

サブドメイン列挙
```
git clone https://github.com/yuyudhn/AzSubEnum
cd AzSubEnum
pip install -r ./requirements.txt --break-system-packages
python3 azsubenum.py -b megabigtech --thread 10
```

公式サイト等の従業員名等からメールを推測
```
yuki.tanaka@megabigtech.com
yamamoto.sota@megabigtech.com
takahashi.hina@megabigtech.com
kato.sara@megabigtech.com
```

omnisprayによる有効なユーザ名の確認（失敗するときがあるので何回か実施）
```
git clone https://github.com/0xZDH/Omnispray
python3 omnispray.py --type enum -uf users.txt --module o365_enum_office
```

