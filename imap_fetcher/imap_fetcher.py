# imap_fetcher.py
import os
import json
import boto3
import email
import imaplib
import uuid
from datetime import datetime
from botocore.exceptions import ClientError

SECRETS_NAME = os.getenv("GMAIL_SECRET_NAME", "/email-bot/gmail")
S3_BUCKET = os.getenv("RAW_S3_BUCKET", "email-bot-raw-smdelfin")
S3_PREFIX = os.getenv("RAW_S3_PREFIX", "raw-emails/")

secrets = boto3.client("secretsmanager")
s3 = boto3.client("s3")

def get_gmail_credentials():
    resp = secrets.get_secret_value(SecretId=SECRETS_NAME)
    secret = resp.get("SecretString")
    cred = json.loads(secret)
    return cred["username"], cred["password"]  # password = app password

def save_raw_email_to_s3(raw_bytes, subject):
    key = f"{S3_PREFIX}{datetime.utcnow().strftime('%Y/%m/%d/')}{uuid.uuid4().hex}.eml"
    s3.put_object(Bucket=S3_BUCKET, Key=key, Body=raw_bytes)
    return key

def lambda_handler(event, context):
    username, password = get_gmail_credentials()
    # connect to Gmail IMAP
    M = imaplib.IMAP4_SSL("imap.gmail.com")
    try:
        M.login(username, password)
    except imaplib.IMAP4.error as e:
        print("Login failed:", e)
        raise

    M.select("INBOX")
    # Search for UNSEEN messages
    typ, msgnums = M.search(None, '(UNSEEN)')
    if typ != "OK":
        print("IMAP search failed", typ)
        M.logout()
        return {"status": "no-messages"}

    ids = msgnums[0].split()
    print("Found", len(ids), "unseen messages")
    for num in ids:
        typ, data = M.fetch(num, '(RFC822)')
        if typ != "OK":
            print("Failed to fetch", num)
            continue
        raw_bytes = data[0][1]
        # parse for subject for logging (not necessary)
        try:
            msg = email.message_from_bytes(raw_bytes)
            subject = msg.get("Subject", "")
        except Exception:
            subject = ""
        s3_key = save_raw_email_to_s3(raw_bytes, subject)
        print("Saved message", num, "to s3://%s/%s" % (S3_BUCKET, s3_key))
        # mark as SEEN
        M.store(num, '+FLAGS', '\\Seen')
    M.logout()
    return {"status": "done", "fetched": len(ids)}
