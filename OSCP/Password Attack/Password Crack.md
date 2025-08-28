# hash identifier
hash-identifier
```
hash-identifier 'HASH'
```

hashid
```
hashid 'HASH'
```

# crackstation
**Supports:** LM, NTLM, md2, md4, md5, md5(md5_hex), md5-half, sha1, sha224, sha256, sha384, sha512, ripeMD160, whirlpool, MySQL 4.1+ (sha1(sha1_bin)), QubesV3.1BackupDefaults
```
https://crackstation.net/
```
# John the Ripper
## john
password crack command
```
john --wordlist=/usr/share/wordlists/rockyou.txt test.hash
```
## zip2john
```
zip2john ZIPFILE > zip.hash
```
## ssh2john
```
ssh2john SSHKEY > ssh.hash
```

if use hashcat, remove "id_rsa:"
```
sed -i 's/^id_rsa://' ssh.hash
```
## keepas2john
```
keepass2john Database.kdbx > keepass.hash
```

if use hashcat, remove "Database:"
```
sed -i 's/^Database://' keepass.hash
```

# Hashcat

## hashcat
crack with rules
```
sudo hashcat -m 0 test.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/base64.rule --force
```
## crack mode
NTLM
```
sudo hashcat -m 1000 ntlm.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

NTLM-v2
```
sudo hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
```

AS-REP ([[../Active Directory/Authentication Attacks|Authentication Attacks]])
```
sudo hashcat -m 18200 asreproast.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

TGS-REP ([[../Active Directory/Authentication Attacks|Authentication Attacks]]
```
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```
## command utils
find hash type
```
hashcat --help | grep -i "keyword"
```

show already cracked hashes
```
sudo hashcat FILE --show
```
## rules

| コマンド  | 説明            | 例（元: `password` → 結果）           |
| ----- | ------------- | ------------------------------- |
| `:`   | 何もしない         | `password` → `password`         |
| `l`   | 小文字化          | `Password` → `password`         |
| `u`   | 大文字化          | `password` → `PASSWORD`         |
| `c`   | 先頭のみ大文字化      | `password` → `Password`         |
| `d`   | 文字列を複製        | `password` → `passwordpassword` |
| `r`   | 逆順            | `password` → `drowssap`         |
| `$1`  | 末尾に `1` を追加   | `password` → `password1`        |
| `^!`  | 先頭に `!` を追加   | `password` → `!password`        |
| `s@A` | `@` を `A` に置換 | `p@ssword` → `pAssword`         |
| `x`   | 最初の文字を削除      | `password` → `assword`          |
| `O`   | 最後の文字を削除      | `password` → `passwor`          |

using rule command example
```
hashcat -m 0 -a 0 hashes.txt wordlist.txt -r myrules.rule --force
```

rule test
```
hashcat --stdout wordlist.txt -r myrules.rule
```