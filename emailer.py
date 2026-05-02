import smtplib
import threading
import time
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

SENDER   = os.getenv("EMAIL_SENDER")
PASSWORD = os.getenv("EMAIL_PASSWORD")
RECEIVER = os.getenv("EMAIL_RECEIVER")

# Cooldown tracker — prevent spam
# Key = alert type, Value = last sent timestamp
_last_sent = {}
from config import load_config
_cfg             = load_config()
COOLDOWN_SECONDS = _cfg["alerts"]["email"]["cooldown_seconds"]   # 5 minutes between same alert type


def _should_send(alert_key):
    """Check if enough time has passed since last email of this type."""
    now  = time.time()
    last = _last_sent.get(alert_key, 0)
    if now - last >= COOLDOWN_SECONDS:
        _last_sent[alert_key] = now
        return True
    return False


def _send_email(subject, body):
    """Actually send the email via Gmail SMTP."""
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = SENDER
        msg["To"]      = RECEIVER

        # Plain text version
        text_part = MIMEText(body, "plain")

        # HTML version — looks nicer in inbox
        html_body = f"""
        <html><body style="font-family:monospace; background:#0a0e1a; color:#e0e6f0; padding:20px;">
          <div style="border:1px solid #1e3a5f; border-radius:8px; padding:20px; max-width:600px;">
            <h2 style="color:#ef4444; margin:0 0 16px;">⚠ Security Alert</h2>
            <pre style="background:#111827; padding:16px; border-radius:6px; color:#e0e6f0; white-space:pre-wrap;">{body}</pre>
            <p style="color:#555; font-size:12px; margin-top:16px;">
              Sent by Network Packet Analyzer at {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            </p>
          </div>
        </body></html>
        """
        html_part = MIMEText(html_body, "html")

        msg.attach(text_part)
        msg.attach(html_part)

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SENDER, PASSWORD)
            server.sendmail(SENDER, RECEIVER, msg.as_string())

        print(f"[EMAIL] Alert sent: {subject}")

    except Exception as e:
        print(f"[EMAIL ERROR] {e}")


def send_alert(alert_type, src_ip, message, technique=None):
    """
    Send an email alert in a background thread.
    alert_type is used as cooldown key so same alert
    doesn't spam your inbox.
    """
    if not SENDER or not PASSWORD:
        return   # silently skip if not configured

    cooldown_key = f"{alert_type}:{src_ip}"
    if not _should_send(cooldown_key):
        return   # still in cooldown period

    subject = f"[ALERT] {alert_type} detected — {src_ip}"

    body = f"""
NETWORK PACKET ANALYZER — SECURITY ALERT
==========================================
Time     : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Type     : {alert_type}
Source IP: {src_ip}
Details  : {message}
"""
    if technique:
        body += f"""
MITRE ATT&CK
  Technique: {technique.get('id')} — {technique.get('name')}
  Tactic   : {technique.get('tactic')}
"""

    body += """
==========================================
Check your dashboard at http://127.0.0.1:5000
"""

    # Send in background thread so it never blocks packet capture
    threading.Thread(
        target=_send_email,
        args=(subject, body),
        daemon=True
    ).start()