import datetime
import html


def parse_nmap_output(nmap_output):
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
                open_ports.append({
                    'port': parts[0],
                    'service': parts[2],
                    'version': " ".join(parts[3:]) if len(parts) > 3 else "Unknown",
                })
        elif "VULNERABLE:" in line:
            vulnerabilities.append(line.strip())

    return {'open_ports': open_ports, 'vulnerabilities': vulnerabilities}


def generate_simplified_report(ip, nmap_output):
    parsed = parse_nmap_output(nmap_output)
    open_ports = parsed['open_ports']
    vulnerabilities = parsed['vulnerabilities']
    scan_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    report = f"""
==================================================================
              SIMPLE NETWORK HEALTH REPORT
==================================================================

Target: {ip}
Scan Date: {scan_date}

SUMMARY
-------
We analyzed your network device at {ip}.
"""
    if not open_ports:
        report += "\n[+] GOOD NEWS: We found no 'open doors' (ports) on this device.\n"
        report += "    It appears to be secure from external network connections.\n"
    else:
        report += f"\n[!] ATTENTION: We found {len(open_ports)} accessible service(s) on this device.\n"
        report += "    Think of these as unlocked doors that outsiders could potentially knock on.\n"
        report += "\nWHAT WE FOUND\n-------------\n"
        for item in open_ports:
            report += f"\u2022 Port {item['port']} is OPEN running '{item['service']}'.\n"
            svc = item['service'].lower()
            if "http" in svc:
                report += "  -> This usually means a website or web interface is hosted here.\n"
            elif "rtsp" in svc:
                report += "  -> This is often used for streaming media (like AirPlay or security cameras).\n"
            elif "ssh" in svc:
                report += "  -> This is for remote administrative access.\n"
            elif "ftp" in svc:
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
1. If you recognize these services, ensure they are password protected.
2. If you do not need a service, consider turning it off or blocking the port.
3. Keep the device's software updated to prevent hackers from using old bugs.
------------------------------------------------------------------
    (Technical details are attached below for your IT support)
==================================================================
    """
    return report


def generate_html_report(ip, nmap_output):
    # Everything interpolated below is untrusted: the service banner comes from the
    # scanned host, and `ip` arrives from a form POST. Escape it all.
    parsed = parse_nmap_output(nmap_output)
    scan_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    safe_ip = html.escape(str(ip))

    open_ports = []
    for item in parsed['open_ports']:
        svc = item['service'].lower()
        if "http" in svc:      desc = "Web Website/Interface"
        elif "ssh" in svc:     desc = "Remote Admin Access"
        elif "ftp" in svc:     desc = "File Transfer"
        elif "rtsp" in svc:    desc = "Media Stream / Camera"
        elif "telnet" in svc:  desc = "Unsecure Remote Access"
        elif "smtp" in svc:    desc = "Email Server"
        elif "domain" in svc:  desc = "DNS Server"
        else:                  desc = "Unknown Service"
        open_ports.append({
            'port': html.escape(item['port']),
            'service': html.escape(item['service']),
            'desc': desc,
        })

    if not open_ports:
        status_color   = "#28a745"
        status_title   = "Safe & Secure"
        status_message = "Great news! We didn't find any open doors on this device."
    else:
        status_color   = "#dc3545"
        status_title   = "Action Required"
        status_message = f"We found {len(open_ports)} accessible services on this device."

    if open_ports:
        ports_html = "".join(
            f"<tr style='border-bottom:1px solid #eee;'>"
            f"<td style='padding:10px;font-weight:bold;'>{p['port']}</td>"
            f"<td style='padding:10px;'>{p['service']}</td>"
            f"<td style='padding:10px;color:#666;'>{p['desc']}</td></tr>"
            for p in open_ports
        )
    else:
        ports_html = "<tr><td colspan='3' style='padding:15px;text-align:center;'>No open ports found. This is good!</td></tr>"

    return f"""<!DOCTYPE html>
<html>
<head>
<style>
  body {{font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;background:#f4f4f4;margin:0;padding:0;}}
  .container {{max-width:600px;margin:20px auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1);}}
  .header {{background:#004de6;color:#fff;padding:20px;text-align:center;}}
  .header h1 {{margin:0;font-size:24px;}}
  .status-card {{background:{status_color};color:white;padding:15px;text-align:center;margin:20px;border-radius:4px;}}
  .content {{padding:20px;color:#333;line-height:1.6;}}
  .table-box {{width:100%;border-collapse:collapse;margin-top:10px;}}
  .footer {{background:#eee;text-align:center;padding:10px;font-size:12px;color:#888;}}
</style>
</head>
<body>
<div class="container">
  <div class="header"><h1>Network Health Report</h1></div>
  <div class="status-card">
    <h2 style="margin:0;">{status_title}</h2>
    <p style="margin:5px 0 0 0;">{status_message}</p>
  </div>
  <div class="content">
    <p><strong>Target IP:</strong> {safe_ip}</p>
    <p><strong>Scan Date:</strong> {scan_date}</p>
    <h3>\U0001f50d What We Found</h3>
    <table class="table-box">
      <tr style="background:#f8f9fa;text-align:left;">
        <th style="padding:10px;">Port</th>
        <th style="padding:10px;">Service</th>
        <th style="padding:10px;">Description</th>
      </tr>
      {ports_html}
    </table><br>
    <div style="background:#fff3cd;border:1px solid #ffeeba;padding:15px;border-radius:4px;color:#856404;">
      <strong>\U0001f4a1 Next Steps:</strong>
      <ul style="margin-top:5px;padding-left:20px;">
        <li>If you don't recognize a service above, turn it off.</li>
        <li>Ensure all open services are password protected.</li>
        <li>Keep your device software updated.</li>
      </ul>
    </div>
  </div>
  <div class="footer">Securing your network, one scan at a time.<br>Generated by Network Health Checker</div>
</div>
</body>
</html>"""
