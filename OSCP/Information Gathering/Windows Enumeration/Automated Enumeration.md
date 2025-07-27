# winpeas
download x64
```
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe
```

download x86
```
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx86.exe
```
# seatbelt
ghostpack-compiledbinaries
```
https://github.com/r3motecontrol/Ghostpack-CompiledBinaries
```

download seatbelt
```
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/refs/heads/master/Seatbelt.exe
```

# PowerUp
copy to current directory
```
cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
```

Import PowerUp.ps1 and execute Get-ModifiableServiceFile
```
powershell -ep bypass
. .\PowerUp.ps1
Get-ModifiableServiceFile
Get-UnquotedService
```
