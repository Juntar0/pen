Using LDAP to search for objects requires you to provide a **filter** that defines the criteria of the search.

# 通常のフィルタ
`sAMAccountType` 属性を使うことで、オブジェクトの種別を絞り込める。通常のユーザーアカウント（`SAM_NORMAL_USER_ACCOUNT`）は `805306368`（16進数で `0x30000000`）
```
ldapsearch (samAccountType=805306368)
```

**AND条件（`&`）**：複数の条件をすべて満たすオブジェクトを検索
```
# adminCountが1のユーザーアカウントを検索
ldapsearch (&(samAccountType=805306368)(adminCount=1))
```

**OR条件（`|`）**：いずれかの条件を満たすオブジェクトを検索
```
# descriptionに"admin"を含む、またはusernameに"adm"を含むユーザーを検索
ldapsearch (&(samAccountType=805306368)(|(description=*admin*)(samaccountname=*adm*)))
```

### attibutesで情報を絞る場合
`--attributes` オプションで取得するフィールドを指定できる。
```
ldapsearch (&(samAccountType=805306368)(adminCount=1)) --attributes name,memberof,ntsecuritydescriptor
```

> **`ntsecuritydescriptor`について** 
> オブジェクトのセキュリティ記述子（ACL）をbase64文字列として取得できる。BloodHoundでACLベースの攻撃パスを可視化するには必須。BOFHoundがこれをパース・デコードしてBloodHound形式に変換する。

### ビットフィルタ

userAccountControl の **524288 ビット（TRUSTED_FOR_DELEGATION）**が立っているアカウントを検索。
```
ldapsearch (&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288)) --attributes samaccountname
```

## BOF Hound
ldap searchのログを解析してBloodHoundの形式にパースできる。

LDAPクエリ
```
# ドメイン / OU / GPO
ldapsearch (|(objectClass=domain)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)) --attributes *,ntsecuritydescriptor

# ユーザー / コンピュータ / グループ
ldapsearch (|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)) --attributes *,ntsecuritydescriptor

# 特定オブジェクトの追加収集
ldapsearch (objectsid=<SID>) --attributes *,ntsecuritydescriptor
```

copy cobaltstrike logs to desktop.
```
scp -r attacker@10.0.0.5:/opt/cobaltstrike/logs .
```

bofhound against copied log directory
```
bofhound -i logs/
ls -l
```

bofhoundによって吐き出されたjsonファイルをblood houndに入れる


## Restricted groups
LDAPだけでは収集不可なものにrestricted groupがある。SYSVOLを直接参照する

ファイルの場所
```
\\<domain>\SysVol\<domain>\Policies\{GPO_GUID}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
```

GptTmpl.infの読み方
```
[Group Membership]
*S-1-5-21-...-1107__Memberof = *S-1-5-32-544
```

| 項目             | 意味                               |
| -------------- | -------------------------------- |
| 左辺のSID         | メンバーに追加するドメイングループ                |
| 右辺のSID         | 追加先のローカルグループ                     |
| `S-1-5-32-544` | Builtin\Administrators (ローカル管理者) |

→ **Server Admins のメンバーが対象 OU のコンピュータにローカル管理者権限を持つ**
blood hound上のCypherクエリで手動追加（反映）
```
MATCH (x:Computer{objectid:'...-1110'}) 
MATCH (y:Group{objectid:'...-1107'}) 
MERGE (y)-[:AdminTo]->(x)
```

## WMI Filter
GPO はリンクされた OU の全オブジェクトに適用されるが、**WMI フィルターで実際の適用対象を絞れる**。

WMIフィルターは、GPOのgPCWQLFilter属性を変更することによってGPOに適用されます。

WMIフィルタの確認
```
# GPO に紐づくフィルターの GUID を確認
ldapsearch (objectClass=groupPolicyContainer) --attributes displayname,gPCWQLFilter

# フィルターの実体を取得
ldapsearch (objectClass=msWMI-Som) --attributes name,msWMI-Name,msWMI-Parm2 \
  --dn "CN=SOM,CN=WMIPolicy,CN=System,DC=<domain>,DC=<tld>"
```

msWMI-Param2の読み方
```
beacon> ldapsearch (objectClass=msWMI-Som) --attributes name,msWMI-Name,msWMI-Parm2 --dn "CN=SOM,CN=WMIPolicy,CN=System,DC=contoso,DC=com"

Binding to 10.10.120.1

[*] Distinguished name: CN=SOM,CN=WMIPolicy,CN=System,DC=contoso,DC=com
[*] targeting DC: \\lon-dc-1.contoso.com
[*] Filter: (objectClass=msWMI-Som)
[*] Scope of search value: 3
[*] Returning specific attribute(s): name,msWMI-Name,msWMI-Parm2

--------------------
name: {E91C83FB-ADBF-49D5-9E93-0AD41E05F411}
msWMI-Name: Windows 10+
msWMI-Parm2: 1;3;10;61;WQL;root\CIMv2;SELECT * from Win32_OperatingSystem WHERE Version like "10.%";
```

msWMI-Nameは表示名、msWMI-Parm2はフィルタの値。

→ このGPOがWindows 7、Vista、8などを実行しているコンピューターを含むOUにリンクされている場合、それらのコンピューターはフィルター内のWMIクエリに一致しないため、GPOは適用されません。