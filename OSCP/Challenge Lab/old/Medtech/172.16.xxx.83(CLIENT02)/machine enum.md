user
```
whoami /all
```

```

USER INFORMATION
----------------

User Name     SID
============= ============================================
medtech\wario S-1-5-21-976142013-3766213998-138799841-1109


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Distributed COM Users          Alias            S-1-5-32-562 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users           Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users        Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                   Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== =======
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Enabled
SeTimeZonePrivilege           Change the time zone                 Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

```
winpeas upload
```
upload /home/kali/WinPeasx86.exe winpeas.exe
```

```
.\winpeas.exe
```

```
   =================================================================================================

    auditTracker(auditTracker)[C:\DevelopmentExecutables\auditTracker.exe] - Autoload - isDotNet
    File Permissions: Everyone [AllAccess], Authenticated Users [WriteData/CreateFiles]
    Possible DLL Hijacking in binary folder: C:\DevelopmentExecutables (Everyone [AllAccess], Authenticated Users [WriteData/CreateFiles])
    Tracks the security event log for audit events
   =================================================================================================                                                                                                              
```

check audittracker.exe
```
icacls C:\DevelopmentExecutables\auditTracker.exe
```

```
C:\DevelopmentExecutables\auditTracker.exe Everyone:(I)(F)
                                           BUILTIN\Administrators:(I)(F)
                                           NT AUTHORITY\SYSTEM:(I)(F)
                                           BUILTIN\Users:(I)(RX)
                                           NT AUTHORITY\Authenticated Users:(I)(M)

```

