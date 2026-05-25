AppLockerはWindowsに組み込まれたアプリケーション制御技術

ポリシーで承認されていない以下の実行を防ぐ
- アプリケーション
- スクリプト
- パッケージ

ポリシーには１つ以上の適用ルールが必要で、各ルールはPermission, Conditionで構成される

Permissionは許可または拒否 & ルールを適用するユーザ・グループを定義
Conditionはポリシーが適用するルール自体を定義


Confitionは以下に基づく
- Publisher : 署名済みアプリの発行元に基づく
- Path: ファイルまたはフォルダのパスに基づく
- File Hash: ファイルのハッシュに基づく

ポリシーはシステム管理者が定義、GPO, Intune等でコンピュータに展開

デフォルトルール
- **実行可能ファイルルール（Executable Rules）** `.exe`や`.com`などの実行可能ファイルに適用されるルールです。
    - 許可 | Everyone | パス | %PROGRAMFILES%*
    - 許可 | Everyone | パス | %WINDIR%*
    - 許可 | BUILTIN\Administrators | パス | *
- **Windowsインストーラールール（Windows Installer Rules）** `.msi`、`.msp`、`.mst`などのインストーラーファイルに適用されるルールです。
    - 許可 | Everyone | 発行元 | *
    - 許可 | Everyone | パス | %WINDIR%\Installer*
    - 許可 | BUILTIN\Administrators | パス | _._
- **スクリプトルール（Script Rules）** `.ps1`、`.bat`、`.cmd`、`.vbs`、`.js`などのスクリプトファイルに適用されるルールです。
    - 許可 | Everyone | パス | %PROGRAMFILES%*
    - 許可 | Everyone | パス | %WINDIR%*
    - 許可 | BUILTIN\Administrators | パス | *
- **パッケージアプリルール（Packaged App Rules）** `.appx`形式のパッケージアプリケーションに適用されるルールです。
    - 許可 | Everyone | 発行元 | *

拒否されたエラー
![[images/Pasted image 20260523200751.png]]