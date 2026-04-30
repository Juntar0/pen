Browsers will typically encrypt these credentials using the [Windows Data Protection API](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/) (DPAPI) and store them in a local database.
### DPAPIとは
Windowsのアプリケーションが利用する暗号化用のAPI
- 2通りのユーザ権限による暗号化
	- ユーザDPAPI
		- Master Key Path: `%APPDATA%\Microsoft\Protect\{SID}\`
		- Master Keyの復号に必要なもの
			- ドメインユーザでない場合：パスワードのSHA1ハッシュ
			- ドメインユーザである場合：NTLMハッシュ, ドメインバックアップキー（PVKファイル）
	- システムDPAPI
		- Master Keyの復号に必要なもの
			- SYSTEM DPAPIキー（LSAシークレット）
				- LSAのシークレットでDPAPI_SYSYTEMによって保護、
				- SYSTEM, SCURITY, SAMレジストリハイブからLSAシークレットを抽出可能
- DPAPI BLOB
	- DPAPIによって暗号化されたデータそのもの

### BLOBの場所
Most Chromium-base broser keep a SQLite database
- Path : `%LOCALAPPDATA%\<vendor>\<browser>\User Data\Default\Login Data`

Chrome database
- Path : `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`

### 攻撃コマンド
```
execute-assembly C:\Tools\SharpDPAPI\SharpChrome\bin\Release\SharpChrome.exe logins
```


![[Images/Pasted image 20260118165328.png]]