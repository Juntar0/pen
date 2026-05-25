Beaconが新しいプロセスを起動する際は基本的に`CreateProcessA`というWindows APIを使用

Windowsカーネルには`PsSetCreateProcessNotifyRoutineEx`というルーチンがあり、Defenderなどのドライバがここに**コールバック関数を登録可能**

```
プロセス起動のタイミングで...

ドライバのコールバックが呼ばれる
  → PPS_CREATE_NOTIFY_INFO 構造体を受け取る
       ├─ ImageFileName  → 実行ファイル名
       ├─ CommandLine    → コマンドライン文字列  ← ここを検査
       └─ CreationStatus → ここに結果を書き込む

悪意あるパターンを検出した場合：
  → CreationStatus = STATUS_ACCESS_DENIED をセット
  → プロセスの起動がブロックされる
```
これが「Defenderにブロックされました」ではなく**「アクセス拒否」エラーとして表示される**理由。Defenderがカーネルレベルでプロセス生成そのものを拒否しているため。

## バイパス法
カーネル脆弱性の悪用 
脆弱なドライバの悪用（BYOVD）

現実的なアプローチ
同じタスクをAPIやCOMオブジェクト経由でトリガーする