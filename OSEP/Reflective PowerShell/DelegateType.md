解決した関数のメモリアドレスに対して、引数の数とそれぞれのデータ型を対応杖kる必要がある。

**ステップ1：アセンブリ名オブジェクトの作成**
```powershell
$MyAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
```
アセンブリに「ReflectedDelegate」という名前を付ける。まだ実体はなく名前だけ。

---

**ステップ2：動的アセンブリの作成とアクセスモード設定**
```powershell
$Domain = [AppDomain]::CurrentDomain
$MyAssemblyBuilder = $Domain.DefineDynamicAssembly($MyAssembly, 
  [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
```
`AssemblyBuilderAccess::Run`を指定することで**メモリ内でのみ実行可能・ディスクに書き込まない**という設定になる。これがEDR回避の重要なポイント。

---

**ステップ3：モジュールの作成**
```powershell
$MyModuleBuilder = $MyAssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
```
アセンブリの中にモジュールを作る。`$false`はシンボル情報（デバッグ情報）を含めないという指定。

---

**ステップ4：カスタム型の定義**
```powershell
$MyTypeBuilder = $MyModuleBuilder.DefineType('MyDelegateType', 
  'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
```
属性の意味：

|属性|意味|
|---|---|
|`Class`|クラスとして定義（インスタンス化できる）|
|`Public`|外部からアクセス可能|
|`Sealed`|継承不可|
|`AnsiClass`|文字列をANSIとして扱う|
|`AutoClass`|文字列マーシャリングを自動判定|

`MulticastDelegate`を継承することで複数の引数を持つデリゲート型になる。

---

**ステップ5：コンストラクタの定義**
```powershell
$MyConstructorBuilder = $MyTypeBuilder.DefineConstructor(
  'RTSpecialName, HideBySig, Public', 
    [System.Reflection.CallingConventions]::Standard, 
      @([IntPtr], [String], [String], [int]))
$MyConstructorBuilder.SetImplementationFlags('Runtime, Managed')
```
ここで**MessageBoxAの引数の型**を定義している：

|引数|型|MessageBoxAでの意味|
|---|---|---|
|第1引数|`IntPtr`|親ウィンドウハンドル|
|第2引数|`String`|表示するテキスト|
|第3引数|`String`|タイトルバーのテキスト|
|第4引数|`int`|ボタンの種類などのオプション|

`SetImplementationFlags('Runtime, Managed')`は「このコンストラクタはランタイムが管理する」という宣言。

---

**ステップ6：Invokeメソッドの定義**
```powershell
$MyMethodBuilder = $MyTypeBuilder.DefineMethod('Invoke', 
  'Public, HideBySig, NewSlot, Virtual', 
    [int], 
      @([IntPtr], [String], [String], [int]))
$MyMethodBuilder.SetImplementationFlags('Runtime, Managed')
```

デリゲート型を実際に呼び出すための`Invoke`メソッドを定義する。

|引数|値|意味|
|---|---|---|
|第1引数|`"Invoke"`|メソッド名|
|第2引数|`Public, HideBySig, NewSlot, Virtual`|メソッド属性|
|第3引数|`[int]`|戻り値の型（MessageBoxAはintを返す）|
|第4引数|`@([IntPtr],[String],[String],[int])`|引数の型配列|

`Virtual`と`NewSlot`はvtable（仮想関数テーブル）に新しいスロットを確保するために必要。

---

**ステップ7：型の確定**
```powershell
$MyDelegateType = $MyTypeBuilder.CreateType()
```
ここまでの定義を確定させ、実際に使えるデリゲート型を生成する。

---

#### 最終コード例
MessageBoxを呼び出す
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

# ① MessageBoxAのアドレスを解決
$MessageBoxA = LookupFunc user32.dll MessageBoxA

# ② デリゲート型をメモリ内に構築
$MyAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
$Domain = [AppDomain]::CurrentDomain
$MyAssemblyBuilder = $Domain.DefineDynamicAssembly($MyAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
$MyModuleBuilder = $MyAssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
$MyTypeBuilder = $MyModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
$MyConstructorBuilder = $MyTypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, @([IntPtr], [String], [String], [int]))
$MyConstructorBuilder.SetImplementationFlags('Runtime, Managed')
$MyMethodBuilder = $MyTypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', [int], @([IntPtr], [String], [String], [int]))
$MyMethodBuilder.SetImplementationFlags('Runtime, Managed')
$MyDelegateType = $MyTypeBuilder.CreateType()

# ③ アドレスとデリゲート型を結合して呼び出す
$MyFunction = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($MessageBoxA, $MyDelegateType)
$MyFunction.Invoke([IntPtr]::Zero, "Hello World", "This is My MessageBox", 0)
```

WinExecを呼び出す
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

# ① MessageBoxAのアドレスを解決
$WinExec = LookupFunc kernel32.dll WinExec

# ② デリゲート型をメモリ内に構築
$MyAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
$Domain = [AppDomain]::CurrentDomain
$MyAssemblyBuilder = $Domain.DefineDynamicAssembly($MyAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
$MyModuleBuilder = $MyAssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
$MyTypeBuilder = $MyModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
$MyConstructorBuilder = $MyTypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, @([String], [int]))
$MyConstructorBuilder.SetImplementationFlags('Runtime, Managed')
$MyMethodBuilder = $MyTypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', [int], @([String], [int]))
$MyMethodBuilder.SetImplementationFlags('Runtime, Managed')
$MyDelegateType = $MyTypeBuilder.CreateType()

# ③ アドレスとデリゲート型を結合して呼び出す
$MyFunction = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WinExec, $MyDelegateType)
$MyFunction.Invoke("C:\Windows\System32\notepad.exe", 0)
```