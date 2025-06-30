powershell
```
Get-ChildItem -Path C:\Users\ -Include local.txt, proof.txt -File -Recurse -ErrorAction SilentlyContinue
```


bash
```
find / -type f \( -name "local.txt" -o -name "proof.txt" -o -name "flag.txt" \) 2>/dev/null
```
