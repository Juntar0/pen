Artifact KitとはCobalt Strikeが生成するペイロード（.exe / .svc.exe / .dll）のテンプレートのソースコード一式
#### Beaconペイロード生成の仕組み

```
Cobalt Strike
    │
    ├─ Beacon シェルコードを生成
    │
    └─ テンプレートにシェルコードをパッチ（埋め込む）
            │
            ├─ artifact64big.exe  （64bit ステージレス実行ファイル）
            ├─ artifact64.x64.dll （64bit DLL）
            ├─ artifact64svc.exe  （64bit サービスバイナリ）
            └─ ...（他のバリアント）
```

テンプレートの役割は**シェルコードインジェクター**のみ。Beaconシェルコードを受け取ってメモリに注入して実行することだけが仕事

Artifact Kitでソースコードを改変することで、**同じ機能を持ちながら異なるバイナリを生成**し、シグネチャ検出を回避できる

### ファイル構造

```
artifact/
├── src-main/
│   ├── main.c        ← .exe のエントリポイント
│   ├── svcmain.c     ← .svc.exe のエントリポイント
│   ├── dllmain.c     ← .dll のエントリポイント
│   └── resource.rc   ← バイナリのメタ情報（CompanyName等）
│
├── src-common/
│   ├── bypass-mailslot.c    ← アンチサンドボックス技術①
│   ├── bypass-*.c           ← アンチサンドボックス技術（複数）
│   ├── patch.c              ← シェルコード注入のメインロジック
│   ├── injector.c           ← ヘルパー関数
│   └── start_thread.c       ← ヘルパー関数
│
├── README.md         ← 各bypassテクニックの説明
└── build.sh          ← ビルドスクリプト
```

新しいテンプレートを作成するにはbuild.shを実行する。
### ビルドコマンドの構文
```bash
./build.sh <techniques> <allocator> <stage size> <rdll size> <include resource file> <stack spoof> <syscalls> <output directory>
```

|引数|説明|選択肢|
|---|---|---|
|`techniques`|使用するbypassテンプレート（スペース区切りで複数指定可）|`mailslot` 等|
|`allocator`|シェルコード用メモリ確保に使うAPI|`HeapAlloc` / `VirtualAlloc` / `MapViewOfFile`|
|`stage size`|Beaconシェルコードのために予約するメモリサイズ|`344564` 等（CSのバージョンで変化）|
|`rdll size`|ステージサイズの検証用。カスタムローダー未使用時は `0`|`0`|
|`include resource file`|バイナリのメタ情報（CompanyName等）を含めるか|`true` / `false`|
|`stack spoof`|スタックスプーフィングを有効にするか|`true` / `false`|
|`syscalls`|システムコール呼び出し方式|`none` / `embedded` / `indirect` / `indirect_randomized`|
|`output directory`|生成したアーティファクトの保存先|任意のパス|
#### 実行例
```bash
./build.sh mailslot VirtualAlloc 344564 0 false false none /mnt/c/Tools/cobaltstrike/custom-artifacts
```

これを分解すると：

- `mailslot` → bypass-mailslot.c を使用
- `VirtualAlloc` → メモリ確保にVirtualAllocを使用
- `344564` → Beaconシェルコード用に344564バイトを予約
- `0` → カスタムローダーなし
- `false` → resource.rcのメタ情報は埋め込まない
- `false` → スタックスプーフィング無効
- `none` → syscallsは使わない
### ビルド出力物

```
mailslot/
├── artifact.cna          ← Aggressorスクリプト（CSに読み込む）
├── artifact32.dll
├── artifact32.exe
├── artifact32big.dll
├── artifact32big.exe
├── artifact32svc.exe
├── artifact32svcbig.exe
├── artifact64.exe
├── artifact64.x64.dll
├── artifact64big.exe     ← 64bit ステージレス実行ファイル
├── artifact64big.x64.dll
├── artifact64svc.exe
└── artifact64svcbig.exe
```

# AV検出テスト
VirusTotalにアップロードするとシグネチャ作られる
ThreatCheckを使う。バイナリを細かい断片に分割し、各断片をWindowsDefenderでスキャンし、悪意判定される最小バイト列を特定
#### ThreatCheck実行例

```
PS> ThreatCheck.exe -f .\artifact64big.exe
[+] Target file size: 413184 bytes
[+] Analyzing...
[!] Identified end of bad bytes at offset 0x9CE
000008CE   00 00 48 83 EC 28 48 8B  05 65 33 06 00 C7 00 01   ..H.ì(H..e3..Ç..
...
000009BE   83 E2 07 8A 54 15 00 32  14 07 88 14 03 48 FF C0   .â..T..2.....HÿA
[*] Run time: 10.93s
```

オフセット `0x9CE` に問題のあるバイト列が存在する

## Ghidraで解析
ThreatCheckの出力は生のバイト列であり、人間が読むには難しい。Ghidraで逆アセンブルして問題箇所を特定

Navigation > Go To からfile(0x9ce)をエンターそしてクリックokすると関数にジャンプする。そこからさらに絞り込オムニはThreatCheckの出力から特定のバイトシーケンスを調べる。

アーティファクトのソースに戻り、問題箇所を異なるアセンブルにコンパイルされるように変更する。（forループで引っかかってるなら逆向きのWhileにするなど）

再度チェック
```
PS C:\Tools\cobaltstrike\custom-artifacts\mailslot> C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f .\artifact64big.exe
[+] No threat found!
[*] Run time: 0.34s
```

## 取り込み方法
クライアントから Cobalt Strike > Script Mnagerに移動、Loadをクリックして、テンプレートを選択

新しいペイロードを生成するとテンプレートが使用される。