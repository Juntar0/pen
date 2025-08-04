find
```
find / -type f \( -name "local.txt" -o -name "proof.txt" \) 2>/dev/null
```

```
# find / -type f \( -name "local.txt" -o -name "proof.txt" \) 2>/dev/null
/home/offsec/local.txt
/root/proof.txt
```