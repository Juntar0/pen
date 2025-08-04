```
Get-ChildItem -Path C:\Users\ -Include local.txt, proof.txt -File -Recurse -ErrorAction SilentlyContinue
```

```
    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         5/13/2024   9:19 AM             34 proof.txt                                                            


    Directory: C:\Users\yoshi\Desktop


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         5/13/2024   9:19 AM             34 local.txt     
```

