## gobuster

generate pattern file
```
echo -e "{GOBUSTER}/v1\n{GOBUSTER}/v2" > pattern.txt
```

enumeration path
```
gobuster dir -u http://ip:port -w /usr/share/wordlists/dirb/common.txt -p pattern.txt
```

## feroxbuster
find api endpoints
```
feroxbuster -u http://ip:port/users/v1 -w /usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt
```


ffuf
content-size filter 12
```
ffuf -u http://offsecwp:5002/users/v1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt -mc all -fs 12
```