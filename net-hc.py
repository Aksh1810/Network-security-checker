import sys
import os
import logging
import subprocess
import smtplib
import ssl
import socket
from email.message import EmailMessage
import yaml

def load_config():
    config_path = os.path.join(os.getcwd(), 'config.yaml')
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    return {}

CONFIG = load_config()
MS = CONFIG.get('mail_settings', {})

SENDER_EMAIL = os.environ.get('SENDER_EMAIL', MS.get('email', 'networksecscanner@gmail.com'))
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD', MS.get('password', 'nrep tddh kksq isnp'))
SMTP_SERVER = os.environ.get('SMTP_SERVER', MS.get('smtp_server', 'smtp.gmail.com'))
SMTP_PORT = int(os.environ.get('SMTP_PORT', MS.get('smtp_port', 587)))
MAILGUN_API_KEY = os.environ.get('MAILGUN_API_KEY', MS.get('mailgun_api_key'))
MAILGUN_DOMAIN = os.environ.get('MAILGUN_DOMAIN', MS.get('mailgun_domain'))
import requests

LOG_LEVEL = logging.DEBUG
CURRENT_DIR = os.getcwd()
OUTPUT_DIR = f'{CURRENT_DIR}/outputs'
LOG_OUTPUT_PATH = f'{OUTPUT_DIR}/logs.txt'

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

logging.basicConfig(filename=LOG_OUTPUT_PATH, level=LOG_LEVEL,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def get_passive_info(ip):
    print(f"[*] Gathering passive info for {ip}...")
    results = {"ip": ip, "passive_data": {}, "dns": {}, "connectivity": {}}
    
    try:
        resolved_ip = socket.gethostbyname(ip)
        response = requests.get(f"http://ip-api.com/json/{resolved_ip}", timeout=5)
        if response.status_code == 200:
            results["passive_data"] = response.json()
    except Exception as e:
        results["passive_data"] = {"error": str(e)}

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
    
    command = ["nmap", "-sV", "--script=vuln", ip]
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=900)
        
        if result.returncode != 0:
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
    
    is_capturing_ports = False
    for line in lines:
        if "PORT" in line and "STATE" in line and "SERVICE" in line:
            is_capturing_ports = True
            continue
        
        if is_capturing_ports and (not line.strip() or line.startswith("|") or line.startswith("SF:")):
            if "VULNERABLE" in line or "CVE-" in line:
                vulnerabilities.append(line.strip())
            continue
            
        if is_capturing_ports and "/tcp" in line and "open" in line:
            parts = line.split()
            if len(parts) >= 3:
                port = parts[0]
                service = parts[2]
                version = " ".join(parts[3:]) if len(parts) > 3 else "Unknown"
                open_ports.append({'port': port, 'service': service, 'version': version})
        elif "VULNERABLE:" in line: 
             vulnerabilities.append(line.strip())

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

def generate_html_report(ip, nmap_output):
    """
    Generates a beautiful HTML email report for non-technical users.
    """
    lines = nmap_output.splitlines()
    open_ports = []
    vulnerabilities = []
    
    is_capturing_ports = False
    for line in lines:
        if "PORT" in line and "STATE" in line and "SERVICE" in line:
            is_capturing_ports = True
            continue
        if is_capturing_ports and (not line.strip() or line.startswith("|") or line.startswith("SF:")):
            if "VULNERABLE" in line or "CVE-" in line:
                vulnerabilities.append(line.strip())
            continue
        if is_capturing_ports and "/tcp" in line and "open" in line:
            parts = line.split()
            if len(parts) >= 3:
                port_data = {
                    'port': parts[0],
                    'service': parts[2],
                    'desc': "Unknown Service"
                }
                svc = parts[2].lower()
                if "http" in svc: port_data['desc'] = "Web Website/Interface"
                elif "ssh" in svc: port_data['desc'] = "Remote Admin Access"
                elif "ftp" in svc: port_data['desc'] = "File Transfer"
                elif "rtsp" in svc: port_data['desc'] = "Media Stream / Camera"
                elif "telnet" in svc: port_data['desc'] = "Unsecure Remote Access"
                elif "smtp" in svc: port_data['desc'] = "Email Server"
                elif "domain" in svc: port_data['desc'] = "DNS Server"
                
                open_ports.append(port_data)
        elif "VULNERABLE:" in line:
             vulnerabilities.append(line.strip())
    
    scan_date = os.popen('date').read().strip()
    
    if not open_ports:
        status_color = "#28a745"
        status_title = "Safe & Secure"
        status_message = "Great news! We didn't find any open doors on this device."
    else:
        status_color = "#dc3545"
        status_title = "Action Required"
        status_message = f"We found {len(open_ports)} accessible services on this device."

    ports_html = ""
    if open_ports:
        for p in open_ports:
            ports_html += f"""
            <tr style="border-bottom: 1px solid #eee;">
                <td style="padding: 10px; font-weight: bold;">{p['port']}</td>
                <td style="padding: 10px;">{p['service']}</td>
                <td style="padding: 10px; color: #666;">{p['desc']}</td>
            </tr>
            """
    else:
        ports_html = "<tr><td colspan='3' style='padding:15px; text-align:center;'>No open ports found. This is good!</td></tr>"

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }}
            .container {{ max-width: 600px; margin: 20px auto; background: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
            .header {{ background-color: #004de6; color: #ffffff; padding: 20px; text-align: center; }}
            .header h1 {{ margin: 0; font-size: 24px; }}
            .status-card {{ background-color: {status_color}; color: white; padding: 15px; text-align: center; margin: 20px; border-radius: 4px; }}
            .content {{ padding: 20px; color: #333; line-height: 1.6; }}
            .table-box {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            .footer {{ background-color: #eee; text-align: center; padding: 10px; font-size: 12px; color: #888; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Network Health Report</h1>
            </div>
            
            <div class="status-card">
                <h2 style="margin:0;">{status_title}</h2>
                <p style="margin:5px 0 0 0;">{status_message}</p>
            </div>
            
            <div class="content">
                <p><strong>Target IP:</strong> {ip}</p>
                <p><strong>Scan Date:</strong> {scan_date}</p>
                
                <h3>🔍 What We Found</h3>
                <table class="table-box">
                    <tr style="background:#f8f9fa; text-align:left;">
                        <th style="padding:10px;">Port</th>
                        <th style="padding:10px;">Service</th>
                        <th style="padding:10px;">Description</th>
                    </tr>
                    {ports_html}
                </table>
                <br>
                
                <div style="background-color: #fff3cd; border: 1px solid #ffeeba; padding: 15px; border-radius: 4px; color: #856404;">
                    <strong>💡 Next Steps:</strong>
                    <ul style="margin-top: 5px; padding-left: 20px;">
                        <li>If you don't recognize a service above, turn it off.</li>
                        <li>Ensure all open services are password protected.</li>
                        <li>Keep your device software updated.</li>
                    </ul>
                </div>
                
                <p style="font-size: 12px; color: #999; margin-top: 20px;">
                    *Technical Note: Raw scan data is attached below only if viewed in plain text mode.
                </p>
            </div>
            
            <div class="footer">
                Securing your network, one scan at a time.<br>
                Generated by Network Health Checker
            </div>
        </div>
    </body>
    </html>
    """
    return html

def send_email_report(recipient_email, ip, scan_results):
    print(f"[*] Preparing to send email report to {recipient_email}...")
    
    simple_report = generate_simplified_report(ip, scan_results)
    
    html_report = generate_html_report(ip, scan_results)
    
    full_email_body = f"{simple_report}\n\n\n=== TECHNICAL RAW OUTPUT ===\n{scan_results}"
    
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
                html_content=html_report)
            
            sg = SendGridAPIClient(SENDGRID_API_KEY)
            response = sg.send(message)
            
            if response.status_code >= 200 and response.status_code < 300:
                print(f"[+] Email sent successfully via SendGrid! (Status: {response.status_code})")
                logging.info(f"Email sent via SendGrid to {recipient_email}")
                return True, "Email sent successfully via SendGrid API!"
            else:
                print(f"[-] SendGrid failed (Status {response.status_code})")
        except Exception as e:
            print(f"[-] Error trying to use SendGrid: {e}")
            logging.error(f"SendGrid exception: {e}")

    if MAILGUN_API_KEY and MAILGUN_DOMAIN:
        print("[*] Attempting to send via Mailgun API...")
        try:
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

    original_getaddrinfo = socket.getaddrinfo
    def ipv4_getaddrinfo(*args, **kwargs):
        responses = original_getaddrinfo(*args, **kwargs)
        return [r for r in responses if r[0] == socket.AF_INET]
    
    socket.getaddrinfo = ipv4_getaddrinfo

    try:
        print("--- DEBUG: Network Diagnostics ---")
        try:
            resolved_ips = ipv4_getaddrinfo(SMTP_SERVER, 465, socket.AF_INET, socket.SOCK_STREAM)
            target_ip = resolved_ips[0][4][0]
            print(f"[*] Resolved {SMTP_SERVER} to IPv4: {target_ip}")
            
            print("[*] Checking basic internet access (google.com:80)...")
            socket.create_connection(("google.com", 80), timeout=5).close()
            print("[+] Internet is reachable.")
        except Exception as diag_err:
            print(f"[!] Diagnostics Failed: {diag_err}")
        print("----------------------------------")

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
                    raise e3

    except Exception as e:
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
        
        simple_preview = generate_simplified_report(target_ip, scan_output)

        print("\n--- Scan output preview ---")
        print(simple_preview)
        print("---------------------------\n")

        output_file = f"{OUTPUT_DIR}/{target_ip}_vuln_report.txt"
        with open(output_file, "w") as f:
            f.write(scan_output)
            f.write("\n\n" + simple_preview)
            
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
