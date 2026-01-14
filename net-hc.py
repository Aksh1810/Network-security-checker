import sys
import os
import logging
import subprocess
import smtplib
import ssl
from email.message import EmailMessage

# Configuration for Email
# NOTE: You must configure these variables or set them in your environment for email to work.
SENDER_EMAIL = os.environ.get('SENDER_EMAIL', 'networksecscanner@gmail.com')
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD', 'nrep tddh kksq isnp')
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587

LOG_LEVEL = logging.DEBUG
CURRENT_DIR = os.getcwd()
OUTPUT_DIR = f'{CURRENT_DIR}/outputs'
LOG_OUTPUT_PATH = f'{OUTPUT_DIR}/logs.txt'

# Ensure output directory exists
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

logging.basicConfig(filename=LOG_OUTPUT_PATH, level=LOG_LEVEL,
                    format='%(asctime)s - %(levelname)s - %(message)s')

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
            error_msg = f"Nmap scan failed or was interrupted.\nStderr: {result.stderr}"
            logging.error(f"Nmap error: {result.stderr}")
            if not result.stdout:
                return error_msg
            # If we have some stdout, we might want to return it even if returncode != 0
            return result.stdout + "\n" + error_msg
        
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
                return
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
        return

    msg = EmailMessage()
    msg.set_content(full_email_body)
    msg['Subject'] = f"Simple Health Report: {ip}"
    msg['From'] = sender_email
    msg['To'] = recipient_email

    context = ssl.create_default_context()

    try:
        # Force IPv4 connection to avoid [Errno 101] Network is unreachable on some cloud providers
        # Create a custom connection to port 587
        import socket
        
        try:
            # Resolve IPv4 specifically
            addr_info = socket.getaddrinfo(SMTP_SERVER, SMTP_PORT, socket.AF_INET, socket.SOCK_STREAM)
            family, socktype, proto, canonname, sockaddr = addr_info[0]
            
            # Manually connect
            s = socket.socket(family, socktype, proto)
            s.connect(sockaddr)
            
            # Pass this socket to smtplib
            server = smtplib.SMTP(host=SMTP_SERVER, port=SMTP_PORT)
            server.sock = s
            server.file = s.makefile('rb')
            server.get_reply() # Read initial greeting from server
            server.ehlo()
        except Exception as socket_err:
            print(f"[-] Custom IPv4 socket failed: {socket_err}. Falling back to default.")
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)

        # Proceed with TLS and Login
        with server:
            server.starttls(context=context)
            server.login(sender_email, sender_password)
            server.send_message(msg)
        print("[+] Email sent via SMTP.")
    except Exception as e:
        print(f"[-] SMTP Failed: {e}")

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