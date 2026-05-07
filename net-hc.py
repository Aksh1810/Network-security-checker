import os
import sys

from scanner.config import OUTPUT_DIR
from scanner.nmap import run_nmap_scan
from scanner.reports import generate_simplified_report, generate_html_report


def get_user_input():
    print("\n=== Network Vulnerability Scanner ===")
    ip = input("1. Enter IP address to scan: ").strip()
    return ip


def main():
    try:
        target_ip = get_user_input()

        if not target_ip:
            print("Error: IP address is required.")
            return

        scan_output    = run_nmap_scan(target_ip)
        simple_preview = generate_simplified_report(target_ip, scan_output)

        print("\n--- Scan output preview ---")
        print(simple_preview)
        print("---------------------------\n")

        txt_file = os.path.join(OUTPUT_DIR, f"{target_ip}_vuln_report.txt")
        with open(txt_file, "w") as f:
            f.write(scan_output)
            f.write("\n\n" + simple_preview)
        print(f"[*] Text report saved to: {txt_file}")

        html_report = generate_html_report(target_ip, scan_output)
        html_file   = os.path.join(OUTPUT_DIR, f"{target_ip}_report.html")
        with open(html_file, "w") as f:
            f.write(html_report)
        print(f"[*] HTML report saved to: {html_file}")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
