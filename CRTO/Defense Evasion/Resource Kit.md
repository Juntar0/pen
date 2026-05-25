Resource Kitはスクリプトテンプレートを変更するのに使用する

## AMSIとは
Windows Antimalware Scan Interface（AMSI）は、アプリケーションおよびサービスがマシン上のアンチウイルス製品と連携するための標準規格

AMSIをバイパスする方法は多数存在し、一般的にはアプリケーションとアンチウイルスエンジンの間の「橋」を寸断することを狙うことだが、それ自体が検出される

### ビルドの実行
Resource Kitのビルドスクリプトが必要とするのは出力ディレクトリのみです。

```bash
attacker@DESKTOP-FGSTPS7:/mnt/c/Tools/cobaltstrike/arsenal-kit/kits/resource$ ./build.sh /mnt/c/Tools/cobaltstrike/custom-resources
[Resource Kit] [+] Copy the resource files
[Resource Kit] [+] Generate the resources.cna from the template file.
[Resource Kit] [+] The resource kit files are saved in '/mnt/c/Tools/cobaltstrike/custom-resources'
```

| 出力ファイル名               | 概要                       |
| --------------------- | ------------------------ |
| compress.ps1          | GZIP圧縮・Base64エンコード用スクリプト |
| resources.cna         | Aggressorスクリプト（CS読み込み用）  |
| template.exe.hta      | HTA形式EXEテンプレート           |
| template.hint.x64.ps1 | 64ビットヒントテンプレート           |
| template.hint.x86.ps1 | 32ビットヒントテンプレート           |
| template.psh.hta      | HTA形式PowerShellテンプレート    |
| template.py           | Pythonテンプレート             |
| template.vbs          | VBScriptテンプレート           |
| template.x64.ps1      | 64ビットPowerShellテンプレート    |
| template.x86.ps1      | 32ビットPowerShellテンプレート    |
| template.x86.vba      | 32ビットVBAテンプレート           |

# 回避方法
### template.x64.ps1
このテンプレートは、`jump winrm64`のようなワークフローで64ビットのステージレスPowerShellペイロードを生成するために使用

ThreatCheckのAMSIエンジンでスキャンして確認
**実際の悪意あるシェルコードがパッチされていない状態でも検出される**
```
PS C:\Tools\cobaltstrike\custom-resources> ThreatCheck.exe -f .\template.x64.ps1 -e AMSI -t Script
[+] Target file size: 2362 bytes
[+] Analyzing...
[!] Identified end of bad bytes at offset 0x10B
...（省略）...
```

ThreatCheckの出力から、問題のあるコードは5行目のこの部分
```powershell
('System.dll')
```

文字列連結は手軽に試せる手法なので、次のように変更
```powershell
('Syst'+'em.dll')
```

### compress.ps1
このスクリプトはCobalt StrikeのScripted Web Deliveryアタックでのペイロードホスティングなど、複数の場面で使用

ThreatCheckでは検出しないが、Script Web Deliveryでペイロードをホスティングして実行すると検出される。
これは、PowershellがAMSIにサンプルを順番に送るため。デコードされたペイロードをメモリに呼ぶ`New-Object IO.MmeoryStream`を呼ぶ前にAMSIに送信する。

Daniel BohnonのInvoke-Obfuscationスクリプトによる難読化
```powershell
PS C:\Users\Attacker> ipmo C:\Tools\Invoke-Obfuscation\Invoke-Obfuscation.psd1
PS C:\Users\Attacker> Invoke-Obfuscation
```

スクリプトブロックをcompress.ps1の内容に設定
```
Invoke-Obfuscation> SET SCRIPTBLOCK '$s=New-Object IO.MemoryStream(...)'
```

その後、任意の難読化を適用
変更できない唯一の部分は`%%DATA%%`プレースホルダでここは検出トリガーになることはふつうない

## 取り込み方法
Artifact Kitと一緒