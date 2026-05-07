import subprocess
import logging

from .passive import get_passive_info, format_passive_report


def run_nmap_scan(ip, scan_type='network'):
    print(f"\n[*] Starting {scan_type} scan for target: {ip}")
    print("    This process may take several minutes. Please wait...")
    logging.info(f"Starting {scan_type} scan for {ip}")

    if scan_type == 'web':
        command = ["nmap", "-p", "80,443,8080", "-sV",
                   "--script=http-vuln*,http-headers,http-title,ssl-cert", ip]
    elif scan_type == 'specialty':
        command = ["nmap", "-F", "-sV", "--version-light", ip]
    else:
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
