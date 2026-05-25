## 概要
DCSync は、Active Directory の**ドメインコントローラー間レプリケーション機能を悪用**した資格情報ダンプ手法

DCSync を実行するには、以下のいずれかの権限が必要

| 権限                                   | 備考                         |
| ------------------------------------ | -------------------------- |
| Domain Admins                        | 最も一般的な経路                   |
| Enterprise Admins                    | フォレストレベルの管理者               |
| DCコンピューターアカウント                       | DC自体への侵害が必要                |
| `DS-Replication-Get-Changes-All` ACE | 委任設定ミスで一般ユーザーに付与されているケースあり |

### 悪用方法
```
dcsync contoso.com CONTOSO\krbtgt
```

### OPSEC
イベントログ4622は`An operation was performed on an object`でデフォルトではでてこない。送信元IPがちゃんとしたDCかどうかを見られる