import sys
from scanner.config import OUTPUT_DIR
from scanner.nmap import run_nmap_scan
from scanner.reports import generate_simplified_report
from scanner.email import send_email_report


def get_user_input():
    print("\n=== Network Vulnerability Scanner ===")
    ip    = input("1. Enter IP address to scan: ").strip()
    email = input("2. Enter your email to receive results: ").strip()
    return ip, email


def main():
    try:
        target_ip, user_email = get_user_input()

        if not target_ip:
            print("Error: IP address is required.")
            return

        scan_output  = run_nmap_scan(target_ip)
        simple_preview = generate_simplified_report(target_ip, scan_output)

        print("\n--- Scan output preview ---")
        print(simple_preview)
        print("---------------------------\n")

        import os
        output_file = os.path.join(OUTPUT_DIR, f"{target_ip}_vuln_report.txt")
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
