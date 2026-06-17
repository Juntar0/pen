ラボのロールバック時にファイルが消されないようにするため

samba設定ファイル編集
```bash
sudo mv /etc/samba/smb.conf /etc/samba/smb.conf.old
sudo nano /etc/samba/smb.conf
```

smb.confの設定
```
[visualstudio]
 path = /home/kali/data
 browseable = yes
 read only = no
```

smbユーザ作成・サービス起動
```bash
sudo smbpasswd -a kali
sudo systemctl start smbd
sudo systemctl start nmbd
```

共有フォルダ作成
```bash
mkdir /home/kali/data
sudo chmod -R 777 /home/kali/data
```

エクスプローラーで`\\KALIIP`を検索し、資格情報を入力
![[../../Pasted image 20260608205623.png]]


プロジェクトにもLocationに共有フォルダのUNCを入力
![[../../Pasted image 20260608205650.png]]

