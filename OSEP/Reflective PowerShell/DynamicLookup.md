Add-Typeを利用したシェルコードは実際にはファイルへ書き込みが行われていた
![[images/Pasted image 20260609203603.png]]

動的ルックアップテクニックで.NETアセンブリをインメモリで作成する。

条件に合うアセンブリの抽出
※量が多すぎるので注意
```powershell
$Assemblies = [AppDomain]::CurrentDomain.GetAssemblies()

$Assemblies |
  ForEach-Object {
    $_.GetTypes()|
      ForEach-Object {
          $_ | Get-Member -Static| Where-Object {
            $_.TypeName.Contains('Unsafe')
          }
      } 2> $null
    }
```


関数アドレスの動的ルックアップとしてGetModuleHandleとGetProcAddressを利用できるため、これの参照を取得する。

リフレクションを通じたGetModuleHandleの呼び出し
```powershell
$systemdll = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }) 
$unsafeObj = $systemdll.GetType('Microsoft.Win32.UnsafeNativeMethods') $GetModuleHandle = $unsafeObj.GetMethod('GetModuleHandle')
```

Invokeで実際に使用するとuser32.dllの開始アドレスがルックアップできる。（整数をHEXに変換）
```powershell
$GetModuleHandle.Invoke($null, @("user32.dll"))
```

実際に実行して確かめた例
![[images/Pasted image 20260609204914.png]]

GetProcAddressの呼び出しは`$unsafeObj`に複数のGetProcAddressがあるので、同じように呼び出そうとするとエラーがでる

`ForEach-Object`で配列で取得し、その配列`$tmp`の1つ目を使用。
以下は`MessageBoxA`のアドレスを取得する例
```powershell
$user32 = $GetModuleHandle.Invoke($null, @("user32.dll"))
$tmp=@()
$unsafeObj.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
$GetProcAddress = $tmp[0]
$GetProcAddress.Invoke($null, @($user32, "MessageBoxA"))
```


最終的な動的ルックアップ関数
```powershell
function LookupFunc {

	Param ($moduleName, $functionName)

	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
      Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}
```

CreateFileAを動的ルックアップする例
```powershell
LookupFunc "kernel32.dll" "CreateFileA"
```