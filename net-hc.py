import sys
import os
import logging
import subprocess
import smtplib
import ssl
import socket
from email.message import EmailMessage
import yaml

# Load config from YAML if it exists
def load_config():
    config_path = os.path.join(os.getcwd(), 'config.yaml')
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    return {}

CONFIG = load_config()
MS = CONFIG.get('mail_settings', {})

# Configuration for Email
SENDER_EMAIL = os.environ.get('SENDER_EMAIL', MS.get('email', 'networksecscanner@gmail.com'))
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD', MS.get('password', 'nrep tddh kksq isnp'))
SMTP_SERVER = os.environ.get('SMTP_SERVER', MS.get('smtp_server', 'smtp.gmail.com'))
SMTP_PORT = int(os.environ.get('SMTP_PORT', MS.get('smtp_port', 587)))

# Mailgun Configuration (Alternative for Render/Cloud)
MAILGUN_API_KEY = os.environ.get('MAILGUN_API_KEY', MS.get('mailgun_api_key'))
MAILGUN_DOMAIN = os.environ.get('MAILGUN_DOMAIN', MS.get('mailgun_domain'))
import requests

LOG_LEVEL = logging.DEBUG
CURRENT_DIR = os.getcwd()
OUTPUT_DIR = f'{CURRENT_DIR}/outputs'
LOG_OUTPUT_PATH = f'{OUTPUT_DIR}/logs.txt'

# Ensure output directory exists
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

logging.basicConfig(filename=LOG_OUTPUT_PATH, level=LOG_LEVEL,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def get_passive_info(ip):
    """
    Gathers info about an IP/Domain without using Nmap.
    Uses public API (ip-api.com) and basic socket checks.
    """
    print(f"[*] Gathering passive info for {ip}...")
    results = {"ip": ip, "passive_data": {}, "dns": {}, "connectivity": {}}
    
    # 1. IP-API lookup (Passive Geolocation & ISP)
    try:
        # If it's a hostname, resolve it first
        resolved_ip = socket.gethostbyname(ip)
        response = requests.get(f"http://ip-api.com/json/{resolved_ip}", timeout=5)
        if response.status_code == 200:
            results["passive_data"] = response.json()
    except Exception as e:
        results["passive_data"] = {"error": str(e)}

    # 2. Basic Socket Connectivity (Check common ports 80, 443, etc.)
    common_ports = [80, 443, 21, 22, 25, 53, 3306, 5000, 8000, 8080]
    open_ports = []
    print(f"[*] Checking common ports (80, 443, etc.) via stealth connection...")
    for port in common_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    results["connectivity"]["open_ports"] = open_ports

    return results

def format_passive_report(ip, data):
    p = data.get("passive_data", {})
    report = f"""
==================================================================
              PASSIVE NETWORK HEALTH REPORT
==================================================================

Target: {ip}
Resolved IP: {p.get('query', 'Unknown')}
Location: {p.get('city', 'Unknown')}, {p.get('regionName', 'Unknown')}, {p.get('country', 'Unknown')}
ISP/Organization: {p.get('isp', 'Unknown')} / {p.get('org', 'Unknown')}

NETWORK ACCESSIBILITY
---------------------
"""
    open_ports = data.get("connectivity", {}).get("open_ports", [])
    if open_ports:
        report += f"[!] Found {len(open_ports)} common port(s) open: {', '.join(map(str, open_ports))}\n"
        report += "    (Note: This was a quick check, more ports might be open but hidden.)\n"
    else:
        report += "[+] No common public ports (Web/SSH/FTP) were found open.\n"
        report += "    This device appears to be well-hidden or heavily firewalled.\n"

    report += """
SECURITY SUMMARY
----------------
• This is a 'Passive' report because standard active scanning was blocked.
• The device is hosted/connected via {isp}.
• Recommendation: Ensure any cloud-based services have strict security groups.

==================================================================
""".format(isp=p.get('isp', 'your provider'))
    return report

def get_user_input():
    print("\n=== Network Vulnerability Scanner ===")
    ip = input("1. Enter IP address to scan: ").strip()
    email = input("2. Enter your email to receive results: ").strip()
    return ip, email

def run_nmap_scan(ip):
    print(f"\n[*] Starting vulnerability scan for target: {ip}")
    print("    This process may take several minutes. Please wait...")
    logging.info(f"Starting nmap scan for {ip}")
    
    # Command explanation:
    # -sV: Probe open ports to determine service/version info
    # --script=vuln: Run standard vulnerability detection scripts
    command = ["nmap", "-sV", "--script=vuln", ip]
    
    try:
        # 15 minute timeout to prevent hanging indefinitely
        result = subprocess.run(command, capture_output=True, text=True, timeout=900)
        
        if result.returncode != 0:
            # If Nmap fails, try Passive Scan as fallback
            print("[!] Nmap scan failed. Falling back to Passive Discovery...")
            passive_data = get_passive_info(ip)
            return format_passive_report(ip, passive_data)
        
        logging.info(f"Scan completed for {ip}")
        return result.stdout

    except subprocess.TimeoutExpired:
        msg = "Scan timed out after 15 minutes."
        logging.error(msg)
        return msg
    except FileNotFoundError:
        msg = "Error: 'nmap' command not found. Please ensure nmap is installed and in your PATH."
        logging.error(msg)
        return msg
    except Exception as e:
        msg = f"An unexpected error occurred: {str(e)}"
        logging.error(msg)
        return msg

def generate_simplified_report(ip, nmap_output):
    """
    Parses Nmap output to create a non-technical summary.
    """
    lines = nmap_output.splitlines()
    open_ports = []
    vulnerabilities = []
    
    # Basic parsing logic
    is_capturing_ports = False
    for line in lines:
        # Check for port table header
        if "PORT" in line and "STATE" in line and "SERVICE" in line:
            is_capturing_ports = True
            continue
        
        # Stop capturing if we hit a blank line or a different section
        if is_capturing_ports and (not line.strip() or line.startswith("|") or line.startswith("SF:")):
            # Check for vulnerability text in the detail lines
            if "VULNERABLE" in line or "CVE-" in line:
                vulnerabilities.append(line.strip())
            continue
            
        # Capture standard port lines (digits followed by /protocol)
        if is_capturing_ports and "/tcp" in line and "open" in line:
            parts = line.split()
            if len(parts) >= 3:
                port = parts[0]
                service = parts[2]
                version = " ".join(parts[3:]) if len(parts) > 3 else "Unknown"
                open_ports.append({'port': port, 'service': service, 'version': version})
        elif "VULNERABLE:" in line: # Catch explicit vuln script headers outside the loop logic above
             vulnerabilities.append(line.strip())

    # Generate the human-readable text
    report = f"""
==================================================================
              SIMPLE NETWORK HEALTH REPORT
==================================================================

Target: {ip}
Scan Date: {os.popen('date').read().strip()}

SUMMARY
-------
We analyzed your network device at {ip}.
"""

    if not open_ports:
        report += "\n[+] GOOD NEWS: We found no 'open doors' (ports) on this device.\n    It appears to be secure from external network connections.\n"
    else:
        report += f"\n[!] ATTENTION: We found {len(open_ports)} accessible service(s) on this device.\n"
        report += "    Think of these as unlocked doors that outsiders could potentially knock on.\n"
        
        report += "\nWHAT WE FOUND\n-------------\n"
        for item in open_ports:
            report += f"• Port {item['port']} is OPEN running '{item['service']}'.\n"
            # Add simple explanations for common ports
            if "http" in item['service']:
                report += "  -> This usually means a website or web interface is hosted here.\n"
            elif "rtsp" in item['service']:
                report += "  -> This is often used for streaming media (like AirPlay or security cameras).\n"
            elif "ssh" in item['service']:
                report += "  -> This is for remote administrative access.\n"
            elif "ftp" in item['service']:
                report += "  -> This is for file transfers.\n"
    
    if vulnerabilities:
        report += "\n\nPOTENTIAL RISKS DETECTED\n------------------------\n"
        report += "[!!!] Our advanced scan flagged some potential security issues:\n"
        for v in vulnerabilities:
            report += f"  - {v}\n"
    else:
        report += "\n\nSECURITY RISKS\n--------------\n"
        report += "[+] Our automated check did not detect any obvious specific vulnerabilities.\n"
        report += "    (However, always keep your software up to date!)\n"

    report += """
------------------------------------------------------------------
Next Steps:
1. If you recognize these services (e.g., a web server you set up), ensure they are password protected.
2. If you do not need a service, consider turning it off or blocking the port.
3. Keep the device's software updated to prevent hackers from using old bugs.
------------------------------------------------------------------
    (Technical details are attached below for your IT support)
==================================================================
    """
    
    return report

def send_email_report(recipient_email, ip, scan_results):
    print(f"[*] Preparing to send email report to {recipient_email}...")
    
    # Generate the simple version
    simple_report = generate_simplified_report(ip, scan_results)
    
    # Combined Body
    full_email_body = f"{simple_report}\n\n\n=== TECHNICAL RAW OUTPUT ===\n{scan_results}"
    
    # METHOD 0: Try Mailgun API (Best for Cloud/Render)
    if MAILGUN_API_KEY and MAILGUN_DOMAIN:
        print("[*] Attempting to send via Mailgun API...")
        try:
            # IMPORTANT: On sandbox domains, Mailgun usually requires the 'from' 
            # address to be postmaster@domain or something @domain.
            mailgun_sender = f"Network Scanner <postmaster@{MAILGUN_DOMAIN}>" if "sandbox" in MAILGUN_DOMAIN else f"Network Scanner <{SENDER_EMAIL}>"
            
            response = requests.post(
                f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages",
                auth=("api", MAILGUN_API_KEY),
                data={"from": mailgun_sender,
                      "to": [recipient_email],
                      "subject": f"Simple Health Report: {ip}",
                      "text": full_email_body})
            
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

    # METHOD 1: Try using macOS Mail App (No password input required if configured)
    if sys.platform == 'darwin':
        print("[*] Detected macOS. Attempting to send via Apple Mail app...")
        print("    (Note: This uses the default account in your Mail app, ignoring 'SENDER_EMAIL' settings)")
        try:
            # Prepare the body for AppleScript (escape quotes and handle newlines)
            # Use the simplified report for the main view
            safe_body = full_email_body.replace('\\', '\\\\').replace('"', '\\"')
            safe_subject = f"Simple Health Report for {ip}"
            
            # AppleScript to create and send the email
            # We explicitly set the 'sender' property to request a specific account
            script = f'''
            tell application "Mail"
                set theMessage to make new outgoing message with properties {{subject:"{safe_subject}", content:"{safe_body}", visible:true, sender:"{SENDER_EMAIL}"}}
                tell theMessage
                    make new to recipient at end of to recipients with properties {{address:"{recipient_email}"}}
                end tell
                send theMessage
            end tell
            '''
            
            result = subprocess.run(['osascript', '-e', script], capture_output=True, text=True)
            
            if result.returncode == 0:
                print("[+] Email sent successfully via Apple Mail!")
                logging.info(f"Email sent via Apple Mail to {recipient_email}")
                return True, "Email sent via Apple Mail!"
            else:
                print(f"[-] Apple Mail automation failed: {result.stderr}")
                print("    (You may need to grant Terminal permission to control Mail in System Settings)")
        except Exception as e:
            print(f"[-] Error trying to use Apple Mail: {e}")

    # METHOD 2: Fallback to SMTP (Requires Password)
    print("\n[*] Falling back to standard SMTP (Gmail).")
    
    sender_email = SENDER_EMAIL
    sender_password = SENDER_PASSWORD.replace(' ', '')
    
    if sender_email == 'your_email@gmail.com' or sender_password == 'your_app_password':
        print("[!] Email configuration missing or default.")
        logging.error("Sender credentials are not configured in environment variables. Cannot send email.")
        return False, "SMTP credentials not configured."

    msg = EmailMessage()
    msg.set_content(full_email_body)
    msg['Subject'] = f"Simple Health Report: {ip}"
    msg['From'] = sender_email
    msg['To'] = recipient_email

    context = ssl.create_default_context()

    # HELPER: Force IPv4 Patch
    original_getaddrinfo = socket.getaddrinfo
    def ipv4_getaddrinfo(*args, **kwargs):
        responses = original_getaddrinfo(*args, **kwargs)
        # Filter for IPv4 (AF_INET)
        return [r for r in responses if r[0] == socket.AF_INET]
    
    # Enable Patch
    socket.getaddrinfo = ipv4_getaddrinfo

    try:
        # DEBUG: Check Connectivity and Resolution
        print("--- DEBUG: Network Diagnostics ---")
        try:
            # 1. Resolve Gmail
            resolved_ips = ipv4_getaddrinfo(SMTP_SERVER, 465, socket.AF_INET, socket.SOCK_STREAM)
            target_ip = resolved_ips[0][4][0]
            print(f"[*] Resolved {SMTP_SERVER} to IPv4: {target_ip}")
            
            # 2. Check basic Internet (Google HTTP)
            print("[*] Checking basic internet access (google.com:80)...")
            socket.create_connection(("google.com", 80), timeout=5).close()
            print("[+] Internet is reachable.")
        except Exception as diag_err:
            print(f"[!] Diagnostics Failed: {diag_err}")
        print("----------------------------------")

        # Attempt 1: Try Port 465 (SSL)
        try:
            print(f"[*] Attempting connection to {SMTP_SERVER}:465 (SSL)...")
            server = smtplib.SMTP_SSL(SMTP_SERVER, 465, context=context, timeout=8)
            server.login(sender_email, sender_password)
            server.send_message(msg)
            server.quit()
            
            print("[+] Email sent via Port 465.")
            logging.info(f"Email successfully sent to {recipient_email} via Port 465")
            socket.getaddrinfo = original_getaddrinfo
            return True, "Email sent successfully via Port 465!"
        except Exception as e1:
            print(f"[-] Port 465 failed: {e1}")
            
            # Attempt 2: Try Port 587 (STARTTLS)
            try:
                print(f"[*] Attempting connection to {SMTP_SERVER}:587 (STARTTLS)...")
                server = smtplib.SMTP(SMTP_SERVER, 587, timeout=8)
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(sender_email, sender_password)
                server.send_message(msg)
                server.quit()
                print("[+] Email sent via Port 587.")
                logging.info(f"Email successfully sent to {recipient_email} via Port 587")
                socket.getaddrinfo = original_getaddrinfo
                return True, "Email sent successfully via Port 587!"
            except Exception as e2:
                print(f"[-] Port 587 failed: {e2}")

                # Attempt 3: Try Port 2525 (STARTTLS) - The "Hail Mary"
                try:
                    print(f"[*] Attempting connection to {SMTP_SERVER}:2525 (STARTTLS)...")
                    server = smtplib.SMTP(SMTP_SERVER, 2525, timeout=8)
                    server.ehlo()
                    server.starttls(context=context)
                    server.ehlo()
                    server.login(sender_email, sender_password)
                    server.send_message(msg)
                    server.quit()
                    print("[+] Email sent via Port 2525.")
                    logging.info(f"Email successfully sent to {recipient_email} via Port 2525")
                    socket.getaddrinfo = original_getaddrinfo
                    return True, "Email sent successfully via Port 2525!"
                except Exception as e3:
                     # All failed
                    raise e3

    except Exception as e:
        # Restore patch in case of failure
        socket.getaddrinfo = original_getaddrinfo
        
        error_msg = f"Network Error. Diagnosed: {e}"
        print(f"[-] {error_msg}")
        logging.error(error_msg)
        return False, error_msg

def main():
    try:
        target_ip, user_email = get_user_input()
        
        if not target_ip:
            print("Error: IP address is required.")
            return

        scan_output = run_nmap_scan(target_ip)
        
        # Generate simple report for preview
        simple_preview = generate_simplified_report(target_ip, scan_output)

        # Display a summary or the full output to the console
        print("\n--- Scan output preview ---")
        print(simple_preview)
        print("---------------------------\n")

        # Save to file (Raw output)
        output_file = f"{OUTPUT_DIR}/{target_ip}_vuln_report.txt"
        with open(output_file, "w") as f:
            f.write(scan_output) # Save raw for technical reference
            f.write("\n\n" + simple_preview) # Append simple version
            
        print(f"[*] Full report saved locally to: {output_file}")
        
        if user_email:
            send_email_report(user_email, target_ip, scan_output)
        else:
            print("[*] No email provided, skipping email report.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()