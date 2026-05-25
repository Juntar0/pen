それぞれのコマンドにおけるOPSEC
## ハウスキーピングコマンド
設定変更や管理用。OPSECリスクは低いが、一部はBeaconへのタスク送信が発生する。
```
タスクを送信するもの（Beaconが動く）：
  checkin / sleep / cancel / powershell-import / spawnto / ppid

クライアント側だけで完結するもの（Beaconは動かない）：
  help / clear / downloads / jobs / note
```


## API-onlyコマンド
Beaconに組み込まれていてWindows APIだけで動く。新しいプロセスやスレッドを生成しないためOPSECリスクが低い。
```
代表的なもの：
  pwd / cd / ls / getuid
  download / upload
  make_token / steal_token / rev2self
  kill / exit
```

## Inline コマンド（BOF）
**Beacon Object File**という仕組みで、コンパイル済みCコードをBeaconのスレッド内で直接実行

OPSECな設定
```c
process-inject {
    # BOFのメモリ確保に使うAPIを指定する。
    # 選択肢は VirtualAlloc、MapViewOfFile、HeapAlloc の3つ。
    set bof_allocator "VirtualAlloc";
    
    # BOF実行後にメモリ確保領域をどう扱うかを制御する。
    # true  → 領域を保持したままゼロクリアする（次のBOFのために再利用）
    # false → 領域を解放する（bof_allocatorの種類による）
    # 次のBOFに対してメモリが不足している場合は、
    # この設定にかかわらず解放して再確保される。
    set bof_reuse_memory "true";
    
    # 最初のメモリ確保サイズを指定する（バイト単位）。
    # メモリの解放・再確保イベントを減らしたい場合は、
    # 普段実行するBOFを収容できる十分な大きさに設定すること。
    set min_alloc "8192";
    
    # メモリ確保直後（待機中）の権限を制御する。
    # true  → RWX（読み取り・書き込み・実行）を使用する
    # false → RW（読み取り・書き込みのみ）を使用する
    # bof_reuse_memory が true の場合、BOF実行後にこの権限に戻される。
    set startrwx "false";
    
    # BOFのエントリポイントを呼び出す直前の最終的なメモリ権限を制御する。
    # true  → RWX に切り替える
    # false → コードセクションはRX、データセクションはRW に切り替える
    set userwx "false";
}
```

## Fork & Run コマンド 
**OPSECリスクが最も高い分類。** ポストエクスプロイテーション機能をDLL化してプロセスにインジェクト
##### Spawnのみ（新しい犠牲プロセスを起動する）
```
execute-assembly  → .NETアセンブリをメモリで実行
powerpick         → PowerShellをアンマネージドで実行
```
##### Explicitのみ（既存プロセスにインジェクト）
```
psinject  → powerpickと同機能、対象プロセスを指定
```
##### 両方対応
```
portscan / keylogger / printscreen / desktop / mimikatz
```

process-injectionの設定
```c
process-inject {
    # ターゲットプロセスにメモリを確保するAPIを指定する。
    # 選択肢は VirtualAllocEx と NtMapViewOfSection の2つ。
    # NtMapViewOfSection は同一アーキテクチャへのインジェクションにしか使えない点に注意。
    # クロスアーキテクチャ（x64→x86等）の場合は常に VirtualAllocEx が使われる。
    set allocator "VirtualAllocEx";
    
    # これらのオプションはBOFの場合と同様に機能する。
    # startrwx: メモリ確保直後の権限。falseにするとRWX（実行可能）を避けてRWになる。
    # userwx:   シェルコード実行直前の権限。falseにするとRWXを避けてRX/RWになる。
    set startrwx "false";
    set userwx "false";
    
    # このサブブロックは新しいスレッドを生成するAPIを指定する。
    # 主にクロスアーキテクチャインジェクションへの対応のため、複数の選択肢が用意されている。
    # 各オプションと技術の詳細は以下の通り：
    #
    # CreateThread        : 現在のプロセス内へのインジェクションのみ対応。
    # CreateRemoteThread  : x64 → x86 インジェクションに対応。
    # NtQueueApcThread    : 同一アーキテクチャへのインジェクションのみ対応。
    # NtQueueApcThread-s  : "Early Bird" インジェクションパターン（同一アーキテクチャのみ）。
    # ObfSetThreadContext : 同一アーキテクチャへのインジェクションのみ対応。
    # RtlCreateUserThread : x86 → x64 インジェクションに対応するが、RWXメモリが必須。
    # SetThreadContext    : x64 → x86 インジェクションにも対応。
    #
    # Beaconは上から順に評価するため、優先したい技術を上に、
    # バックアップとなる技術を下に配置すること。
    # 対応していないケースが発生した場合、インジェクションは失敗する。
    #
    # CreateThread、CreateRemoteThread、ObfSetThreadContext は
    # "module!function+0x##" 構文を使って別の関数のアドレスを偽装できる。
    # これらのスレッドはサスペンド状態で生成され、
    # レジュームされる前にシェルコードを指すように更新される。
    # これによりメモリスキャンのトリガーを回避しやすくなる。
    execute {
        CreateThread "ntdll.dll!RtlUserThreadStart+0x2c";
        NtQueueApcThread-s;
        NtQueueApcThread;
        SetThreadContext;
    }
}
```

post-exの設定
```c
post-ex {
    # Spawn variant（新プロセスを起動する方式）で使う
    # x64・x86 ポストエクスプロイテーションDLLの
    # デフォルトプロセスパスを指定する。
    # 環境変数は使用可能だが、system32 の代わりに
    # 必ず sysnative（x64）と syswow64（x86）を使うこと。
    # 実行時に spawnto コマンドで上書き可能。
    set spawnto_x64 "%windir%\sysnative\msiexec.exe";
    set spawnto_x86 "%windir%\syswow64\msiexec.exe";

    # post-ex DLL がローダーをメモリから解放するかどうかを指定する。
    # true にするとDLL実行後にローダーがメモリから削除される。
    set cleanup "true";

    # post-ex の名前付きパイプ名をデフォルトの "postex_####" から変更する。
    # カンマ区切りのリストにすると、Cobalt Strike が毎回ランダムに選択する。
    # '#' は1文字ずつランダムな16進数文字に置き換えられる。
    set pipename "dotnet-diagnostic-#####, ########-####-####-####-############";

    # 一部のpost-ex DLL（ポートスキャナー等）は処理を高速化するために
    # 複数のスレッドを生成する。
    # このオプションはDLLが新しいスレッドを生成する際に
    # 指定した偽装開始アドレスを使うよう指示する。
    set thread_hint "ntdll.dll!RtlUserThreadStart+0x2c";

    # メモリパッチング技術を使って
    # powerpick、execute-assembly、psinject における
    # AMSIを無効化する。
    set amsi_disable "true";

    # このサブブロックはpost-ex DLL内の文字列を置換するために使う。
    # x86 DLLには transform-x86 を使うこと。
    transform-x64 {

        # strrep はすべてのpost-ex DLLに対して文字列を置換する。
        # どのDLLにも共通して存在する汎用的な文字列に適している。
        strrep "This program cannot be run in DOS mode." "This is totally not a PE.";

        # strrepex は特定のpost-ex DLLだけを対象に文字列を置換する。
        # 特定のDLLにしか存在しない文字列に適している。
        #
        # 指定可能なpost-ex名：
        # BrowserPivot, ExecuteAssembly, Hashdump, Keylogger, Mimikatz,
        # NetView, PortScanner, PowerPick, Screenshot, SSHAgent
        strrepex "PowerPick" "CLRCreateInstance failed w/hr 0x%08lx" "CLRCreateInstance failed: 0x%08lx";
        strrepex "PowerPick" "Failed to get default AppDomain w/hr 0x%08lx" "Failed to get default AppDomain: 0x%08lx";
        strrepex "ExecuteAssembly" "Invoke_3 on EntryPoint failed." "Unhandled exception.";
        strrepex "ExecuteAssembly" "Failed to load the assembly w/hr 0x%08lx" "Failed to load the assembly: 0x%08lx";
    }
}
```

## プロセス実行コマンド
ディスク上のプログラムを直接実行
```
execute   → 出力なしで実行
run       → 出力ありで実行
runas     → 別の認証情報で実行
shell     → cmd.exe経由
powershell → powershell.exe経由
           ※jump winrm / remote-exec winrm もこれに依存
```

## サービス作成コマンド
Windowsサービスを作ってコマンドやBeaconを実行
```
elevate svc-exe          → 高権限→SYSTEM昇格
jump psexec/psexec64     → ラテラルムーブメント
remote-exec psexec       → リモートでコマンド実行
```
**重要な注意点：**
```
サービス経由のペイロードはデフォルトで rundll32 を spawnto に使う

post-ex.spawnto は使えない
  → SYSTEMコンテキストでは %windir% 等の環境変数が無効なため

→ Artifact Kit の ak-settings で絶対パスを直接指定する必要がある
   例：C:\Windows\System32\msiexec.exe
```