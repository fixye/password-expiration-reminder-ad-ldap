import datetime
import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from ldap3 import Server, Connection, ALL, SUBTREE

AD_SERVER = os.environ.get("AD_SERVER")
AD_USER = os.environ.get("AD_USERNAME")
AD_PASSWORD = os.environ.get("AD_PASSWORD")
BASE_DN = os.environ.get("BASE_DN")

SMTP_SERVER = os.environ.get("SMTP_SERVER")
SMTP_PORT = 25
SMTP_USER = os.environ.get("SMTP_USER")

# Password expiry period in days (typically 90 days, adjust as needed)
PASSWORD_EXPIRY_DAYS = 90

# Calculate the current date and the thresholds (naive datetimes)

now = datetime.datetime.now()
thresholds = {
    14: now + datetime.timedelta(days=14),
    7: now + datetime.timedelta(days=7),
    1: now + datetime.timedelta(days=2)
}

# LDAP filter for finding all users
search_filter = '(objectClass=user)'

# Connect to the AD server
server = Server(AD_SERVER, get_info=ALL)
conn = Connection(server, user=AD_USER, password=AD_PASSWORD, auto_bind=True)

# Perform the search
conn.search(BASE_DN, search_filter, search_scope=SUBTREE, attributes=['cn', 'mail', 'pwdLastSet'])

# Convert aware datetime to naive datetime by removing timezone info
def make_naive(dt):
    return dt.replace(tzinfo=None)

def send_email(to_email, subject, message):
    msg = MIMEMultipart()
    msg['From'] = 'Password Expiration Reminder'
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(message, 'plain'))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.send_message(msg)

# Prepare the email content based on the days left
def prepare_email_content(days_left):
    return f"Your password will expire in {days_left} {'days' if days_left < 1 else 'day'}. Please change it as soon as possible."


# Process each entry and send emails based on thresholds
for entry in conn.entries:
    if entry.mail and entry.pwdLastSet:  # Check if the mail and pwdLastSet attributes exist and are not empty
        pwd_last_set = entry.pwdLastSet.value
        if isinstance(pwd_last_set, datetime.datetime):
            pwd_last_set_naive = make_naive(pwd_last_set)
            pwd_expiry_date = pwd_last_set_naive + datetime.timedelta(days=PASSWORD_EXPIRY_DAYS)
            
            for days_left, threshold_date in thresholds.items():
                # Check if the password expiry date matches the threshold date
                if pwd_expiry_date.date() == threshold_date.date():
                    email_subject = f"Password Expiry Notification - {days_left} days left"
                    email_content = prepare_email_content(days_left)
                    send_email(entry.mail.value, email_subject, email_content)
                    print(f"Email sent to: {entry.mail}, Password Expiry Date: {pwd_expiry_date.strftime('%Y-%m-%d')}, Days Left: {days_left + 1}")

conn.unbind()

