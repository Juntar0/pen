RealmとはADドメインと同義（RFCの文脈で言ってるだけ）

**「ドメインAのKDCが発行したTGTは、ドメインBのKDCでは読めない」** という問題
通常のKerberos認証では、TGTは `krbtgt` アカウントのパスワードハッシュで暗号化されています。このハッシュは各ドメインで固有のため、ドメインBはドメインAのTGTを復号不可

ドメインAとドメインBで信頼関係を無図ぶ際に共有するのが、Inter-Realm Key（共有鍵）
共有鍵を使って「Realm間TGT」を発行->ドメイン間でもKerberos認証が成立

## フロー

|     | Trusted Realm        | Trusting Realm     |
| --- | -------------------- | ------------------ |
| 日本語 | 信頼される側               | 信頼する側              |
| 立場  | ユーザーが**いる**側         | リソースが**ある**側       |
| 例   | CONTOSO.COM（クライアント側） | partner.com（サービス側） |

ドメインA(CONTOSO.COM)のコンピュータがドメインB(PARTNER.COM)のサービスに認証したい例：

1. コンピュータ -> ドメインAのKDCへTGS-REQ
   req-bodyの中身
   ![[images/Pasted image 20260521222240.png]]
2. KDCはInter-Realm TGTを含めたTGS-REPを返す
   帰ってきたInter-Realm TGTの中身
   ![[images/Pasted image 20260521222551.png]]
3. Inter-Realm TGTを使用してドメインBのKDCにTGS-REQを送る
   その時のTGS-REQのreq-body
   ![[images/Pasted image 20260521222652.png]]
4. ドメインBはサービスチケットをTGS-REPで返す

## Trust accounts
Trustが作成され、Inter-Realm keyが共有されるとTrusting Realmのチケット発行サービスが、Trusted RealmのKDCにプリンシパルとして登録される。

登録にはRealmのflat name(NetBIOS name)が登録される。
アカウントはADUCツールでは表示されないが、ldapでsamAccountTypeが`SAM_TRUST_ACCOUNT`タイプのアカウントをクエリして発見可能

PARTNER$という名前のプリンシパルがcontoso.comのCN=Usersコンテナに登録される

```bash
ldapsearch (samAccountType=805306370) --attributes samAccountName
# 出力例
Binding to 10.10.120.1

[*] Distinguished name: DC=contoso,DC=com
[*] targeting DC: \\lon-dc-1.contoso.com
[*] Filter: (samAccountType=805306370)
[*] Scope of search value: 3
[*] Returning specific attribute(s): samAccountName

--------------------
sAMAccountName: PARTNER$
```

Inter-Realm keyはこのアカウントのパスワードとして使用されている