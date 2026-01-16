# Network Vulnerability Scanner

This is a personal network security tool designed to simplify the process of vulnerability scanning. It acts as a bridge between complex technical tools and user-friendly reporting, changing raw data into easy-to-understand health reports.

## 🎯 Project Goal

The primary goal of this project is to make network security monitoring accessible and understandable. Traditional security tools produce dense, technical output that can be overwhelming. This application automates the scanning process using industry-standard engines and translates the results into plain English, highlighting potential risks without the jargon.

## ✨ Key Features

-   **Interactive Web Interface:** A clean, responsive web UI for easy interaction.
-   **Automated Scanning:** Powered by the `nmap` engine to perform deep analysis of network devices.
-   **Smart Reporting:** Automatically parses technical port data into friendly descriptions (e.g., explaining that "Port 80" means a web server).
-   **Email Alerts:** Delivers beautiful, color-coded HTML health reports directly to your inbox.
-   **Cloud Ready:** Deployed and running on the cloud for anytime access.

## 📖 How to Use

Using the scanner is simple designed to be intuitive:

1.  **Access the Interface:** Open the web application in your browser.
2.  **Enter Target:** Input the **IP Address** or **Domain Name** of the device you want to scan.
3.  **Enter Email:** Provide the email address where you want to receive the final report.
4.  **Start Scan:** Click the submit button. The system will start a background scan (this typically takes 2-5 minutes depending on the target's security).
5.  **Check Your Email:** Once finished, you will receive a detailed report.

> **⚠️ Important Check:** Since this is an automated security tool, email providers often filter these reports. **Please check your Spam or Junk folder** if you do not see the email in your main inbox.

## 🛠️ Technology Stack

-   **Backend:** Python 3, Flask
-   **Scanning Engine:** Nmap (Active Scanning)
-   **Email Engine:** SendGrid API
-   **Frontend:** HTML5, CSS3

## 📊 Example Output

The user receives a report that looks like this:

> **Status:** Action Required (Red)
>
> **What We Found:**
> - **Port 80 (HTTP):** Web Website/Interface
> - **Port 22 (SSH):** Remote Admin Access
>
> **Advice:** Ensure these services are password protected if you intend to keep them open.

---
*This is a personal project for educational and monitoring purposes.*
