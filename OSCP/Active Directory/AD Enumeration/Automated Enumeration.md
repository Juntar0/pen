# BloodHound
## Collecting Data with SharpHound
download
```
wget https://github.com/SpecterOps/SharpHound/releases/download/v2.6.8-rc2/SharpHound_v2.6.8-rc2_windows_x86.zip
unzip SharpHound_v2.6.8-rc2_windows_x86.zip
```

### SharpHound.ps1
importing the SharpHound script
```
powershell -ep bypss
Import-Module .\SharpHound.ps1
```

running SharpHound
```
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\NAME
```

## Launch BloodHound
install package
```
sudo apt update && sudo apt install -y bloodhound
```

setup
```
sudo bloodhound-setup
```

access neo4j
```
http://localhost:7474

default credentials
user : neo4j
pass : neo4j
```

update the bhapi.json
```
sudo vim /etc/bhapi/bhapi.json
```

launch bloodhound
```
sudo bloodhound
```