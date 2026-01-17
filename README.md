# Network Vulnerability Scanner

This is a personal network security tool designed to simplify the process of vulnerability scanning. It acts as a bridge between complex technical tools and user-friendly reporting, changing raw data into easy-to-understand health reports.

## 🎯 Project Goal

The primary goal of this project is to make network security monitoring accessible and understandable. Traditional security tools produce dense, technical output that can be overwhelming. This application automates the scanning process using industry-standard engines and translates the results into plain English, highlighting potential risks without the jargon.

## ✨ Key Features

-   **Three Powerful Scan Modes:**
    -   🛡️ **Network Device Scan:** Deep vulnerability scan for servers, routers, and IoT devices (`nmap -sV --script=vuln`).
    -   🌐 **Website & App Scan:** Targeted scan for web headers, SSL issues, and web vulnerabilities.
    -   ⚡ **Quick Security Check:** Fast audit of the top 100 most common ports.
-   **Live Progress Tracking:** Real-time loading screen that updates as the scan progresses.
-   **Instant Web Reports:** View technical results directly in your browser immediately after the scan completes.
-   **On-Demand Email Reports:** Option to send a beautiful, non-technical HTML summary to your inbox after reviewing the results.
-   **Human-Readable Analysis:** Automatically parses technical port data into friendly descriptions (e.g., "Open Port 80" -> "Web Website").

## 📖 How to Use

Using the scanner is simple and intuitive:

1.  **Enter Target:** Input the IP address or domain name you wish to scan.
2.  **Select Mode:** Choose the scan type that matches your target (Network, Web, or Quick Check).
3.  **Run Scan:** The system will process the scan in the background (typically 2-5 minutes).
4.  **View Results:** See the raw technical output instantly on the results page.
5.  **Get Report:** (Optional) Enter your email to receive a polished, easy-to-read HTML report for your records.

> **⚠️ Note:** If you request an email report, please check your **Spam or Junk folder** as automated security reports are sometimes filtered by providers.

## 🛠️ Technology Stack

-   **Backend:** Python 3, Flask
-   **Scanning Engine:** Nmap (Active Scanning)
-   **Email Engine:** SendGrid API
-   **Frontend:** HTML5, CSS3, JavaScript (Polling)

## 📊 Example Output

The email report transforms complex data into a clear summary:

> **Status:** Action Required (Red Status Card)
>
> **What We Found:**
> - **Port 80 (HTTP):** Web Website/Interface
> - **Port 22 (SSH):** Remote Admin Access
>
> **Advice:** Ensure these services are password protected if you intend to keep them open.

---
*This is a personal project for educational and monitoring purposes.*
