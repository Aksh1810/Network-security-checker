import socket
import requests


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
    print("[*] Checking common ports (80, 443, etc.) via stealth connection...")
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
\u2022 This is a 'Passive' report because standard active scanning was blocked.
\u2022 The device is hosted/connected via {isp}.
\u2022 Recommendation: Ensure any cloud-based services have strict security groups.

==================================================================
""".format(isp=p.get('isp', 'your provider'))
    return report
