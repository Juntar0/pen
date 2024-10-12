## John the Ripper
zip2john
```
zip2john ZIPFILE > zip.hash
```

ssh2john
```
ssh2john SSHKEY > ssh.hash
```


## Hashcat

crack with rules
```
hashcat -m 0 test.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/base64.rule --force
```

find hash type
```
hashcat --help | grep -i "HASHNAME"
```
