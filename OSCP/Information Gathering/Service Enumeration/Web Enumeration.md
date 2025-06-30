## View Page Sources
firefox
```
right click -> view pagesources
```

curl
```
curl http://192.168.x.x/
```

## feroxbuster
directory scan
```
feroxbuster -k -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -u http://ip:port
```

file scan
```
feroxbuster -k -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -x php,html,cgi,pl,js,sh,py,txt,bak,zip,tar.gz,conf,log,xml -u http://ip:port/
```

filter status code whitelist 200
```
feroxbuster -k -s 200 -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -u http://ip:port
```


## ffuf
subdomain enumeration
```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<HOST>/ -H  "Host:FUZZ.<HOST>" -fc 301 
```

## Banner grabbing
```
whatewb IP
```

## WPScan

Scanning the target
```
wpscan --url URL
```

Active Enumeration 
all plugin
```
wpscan --url URL --enumerate ap --plugins-detection aggressive --api-token TOKEN
```

all theme
```
wpscan --url URL --enumerate at --plugins-detection aggressive --api-token TOKEN
```

## API Enumration
### gobuster
generate pattern file
```
echo -e "{GOBUSTER}/v1\n{GOBUSTER}/v2" > pattern.txt
```

enumeration path
```
gobuster dir -u http://ip:port -w /usr/share/wordlists/dirb/common.txt -p pattern.txt
```

