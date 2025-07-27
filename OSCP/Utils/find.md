## File
powershell
```
Get-ChildItem -Path C:\Users\ -Include local.txt, proof.txt, flag.txt -File -Recurse -ErrorAction SilentlyContinue
```


bash
```
find / -type f \( -name "local.txt" -o -name "proof.txt" -o -name "flag.txt" \) 2>/dev/null
```

keyword in file
```
Select-String -Path "ファイルパス" -Pattern "検索したい文字列"
```