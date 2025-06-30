## hash identifier
hash-identifier
```
hash-identifier 'HASH'
```

hashid
```
hashid 'HASH'
```

## John the Ripper
### zip2john
```
zip2john ZIPFILE > zip.hash
```

### ssh2john
```
ssh2john SSHKEY > ssh.hash
```

if use hashcat, remove "id_rsa:"
```
sed -i 's/^id_rsa://' ssh.hash
```
### keepas2john
```
keepass2john Database.kdbx > keepass.hash
```

if use hashcat, remove "Database:"
```
sed -i 's/^Database://' keepass.hash
```

password crack command
```
john --wordlist=/usr/share/wordlists/rockyou.txt test.hash
```

## Hashcat

crack with rules
```
hashcat -m 0 test.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/base64.rule --force
```

NTLM crack command
```
hashcat -m 1000 adrian.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

find hash type
```
hashcat --help | grep -i "keyword"
```