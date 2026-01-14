import smtplib
import ssl
import os
from email.message import EmailMessage

# 1. Credentials (as configured in the app)
SENDER_EMAIL = 'networksecscanner@gmail.com'
# The app password provided by user
SENDER_PASSWORD_RAW = 'nrep tddh kksq isnp'
SENDER_PASSWORD = SENDER_PASSWORD_RAW.replace(' ', '')

SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587

def test_smtp():
    print("=== SMTP Configuration Test ===")
    print(f"Sender: {SENDER_EMAIL}")
    print(f"Password (processed): {SENDER_PASSWORD[:4]}...{SENDER_PASSWORD[-4:]}")
    
    recipient = input("Enter your email address to receive the test: ").strip()
    if not recipient:
        print("No email provided.")
        return

    msg = EmailMessage()
    msg.set_content(f"This is a test email to verify credentials.\n\nSent from Local Test Script.")
    msg['Subject'] = "SMTP Test - Network Health Checker"
    msg['From'] = SENDER_EMAIL
    msg['To'] = recipient

    context = ssl.create_default_context()

    print(f"[*] Connecting to {SMTP_SERVER}:{SMTP_PORT}...")
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            # server.set_debuglevel(1) # Uncomment to see full protocol headers
            server.starttls(context=context)
            print("[*] STARTTLS success. Attempting login...")
            
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            print("[+] Login SUCCESS!")
            
            server.send_message(msg)
            print(f"[+] Test email sent successfully to {recipient}")
            
    except Exception as e:
        print("\n[X] FAILED!")
        print(f"Error: {e}")
        print("\nTroubleshooting:")
        print("1. Double check the App Password.")
        print("2. Ensure 2-Step Verification is ON for the sender account.")
        print("3. Check firewall/internet connection.")

if __name__ == "__main__":
    test_smtp()
