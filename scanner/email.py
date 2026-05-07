import os
import smtplib
import ssl
import socket
import logging
from email.message import EmailMessage

import requests

from .config import (SENDER_EMAIL, SENDER_PASSWORD, SMTP_SERVER,
                     MAILGUN_API_KEY, MAILGUN_DOMAIN)
from .reports import generate_simplified_report, generate_html_report


def send_email_report(recipient_email, ip, scan_results):
    print(f"[*] Preparing to send email report to {recipient_email}...")

    simple_report  = generate_simplified_report(ip, scan_results)
    html_report    = generate_html_report(ip, scan_results)
    full_email_body = f"{simple_report}\n\n\n=== TECHNICAL RAW OUTPUT ===\n{scan_results}"

    # --- SendGrid ---
    SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')
    if SENDGRID_API_KEY:
        print("[*] Attempting to send via SendGrid API...")
        try:
            from sendgrid import SendGridAPIClient
            from sendgrid.helpers.mail import Mail

            message = Mail(
                from_email=SENDER_EMAIL,
                to_emails=recipient_email,
                subject=f"Network Health Report: {ip}",
                plain_text_content=full_email_body,
                html_content=html_report,
            )
            sg = SendGridAPIClient(SENDGRID_API_KEY)
            response = sg.send(message)
            if 200 <= response.status_code < 300:
                print(f"[+] Email sent successfully via SendGrid! (Status: {response.status_code})")
                logging.info(f"Email sent via SendGrid to {recipient_email}")
                return True, "Email sent successfully via SendGrid API!"
            else:
                print(f"[-] SendGrid failed (Status {response.status_code})")
        except Exception as e:
            print(f"[-] Error trying to use SendGrid: {e}")
            logging.error(f"SendGrid exception: {e}")

    # --- Mailgun ---
    if MAILGUN_API_KEY and MAILGUN_DOMAIN:
        print("[*] Attempting to send via Mailgun API...")
        try:
            mailgun_sender = (
                f"Network Scanner <postmaster@{MAILGUN_DOMAIN}>"
                if "sandbox" in MAILGUN_DOMAIN
                else f"Network Scanner <{SENDER_EMAIL}>"
            )
            response = requests.post(
                f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages",
                auth=("api", MAILGUN_API_KEY),
                data={
                    "from": mailgun_sender,
                    "to": [recipient_email],
                    "subject": f"Network Health Report: {ip}",
                    "text": full_email_body,
                },
            )
            if response.status_code == 200:
                print("[+] Email sent successfully via Mailgun!")
                logging.info(f"Email sent via Mailgun to {recipient_email}")
                return True, "Email sent successfully via Mailgun API!"
            else:
                print(f"[-] Mailgun failed (Status {response.status_code}): {response.text}")
                logging.error(f"Mailgun error: {response.text}")
        except Exception as e:
            print(f"[-] Error trying to use Mailgun: {e}")
            logging.error(f"Mailgun exception: {e}")

    # --- SMTP fallback ---
    if not SENDER_EMAIL or not SENDER_PASSWORD:
        msg = "SMTP credentials not configured. Set SENDER_EMAIL and SENDER_PASSWORD env vars."
        logging.error(msg)
        return False, msg

    print("\n[*] Falling back to standard SMTP (Gmail).")

    email_msg = EmailMessage()
    email_msg.set_content(full_email_body)
    email_msg['Subject'] = f"Network Health Report: {ip}"
    email_msg['From']    = SENDER_EMAIL
    email_msg['To']      = recipient_email

    context = ssl.create_default_context()

    original_getaddrinfo = socket.getaddrinfo

    def ipv4_getaddrinfo(*args, **kwargs):
        responses = original_getaddrinfo(*args, **kwargs)
        return [r for r in responses if r[0] == socket.AF_INET]

    socket.getaddrinfo = ipv4_getaddrinfo
    try:
        # Diagnostics
        try:
            ipv4_addr = ipv4_getaddrinfo(SMTP_SERVER, 465, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
            print(f"[*] Resolved {SMTP_SERVER} to IPv4: {ipv4_addr}")
            socket.create_connection(("google.com", 80), timeout=5).close()
            print("[+] Internet is reachable.")
        except Exception as diag_err:
            print(f"[!] Diagnostics: {diag_err}")

        # Port 465 (SSL)
        try:
            server = smtplib.SMTP_SSL(SMTP_SERVER, 465, context=context, timeout=8)
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(email_msg)
            server.quit()
            logging.info(f"Email sent to {recipient_email} via port 465")
            return True, "Email sent successfully via port 465!"
        except Exception as e1:
            print(f"[-] Port 465 failed: {e1}")

        # Port 587 (STARTTLS)
        try:
            server = smtplib.SMTP(SMTP_SERVER, 587, timeout=8)
            server.ehlo(); server.starttls(context=context); server.ehlo()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(email_msg)
            server.quit()
            logging.info(f"Email sent to {recipient_email} via port 587")
            return True, "Email sent successfully via port 587!"
        except Exception as e2:
            print(f"[-] Port 587 failed: {e2}")

        # Port 2525 (STARTTLS)
        try:
            server = smtplib.SMTP(SMTP_SERVER, 2525, timeout=8)
            server.ehlo(); server.starttls(context=context); server.ehlo()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(email_msg)
            server.quit()
            logging.info(f"Email sent to {recipient_email} via port 2525")
            return True, "Email sent successfully via port 2525!"
        except Exception as e3:
            raise e3

    except Exception as e:
        error_msg = f"SMTP failed: {e}"
        print(f"[-] {error_msg}")
        logging.error(error_msg)
        return False, error_msg
    finally:
        socket.getaddrinfo = original_getaddrinfo
