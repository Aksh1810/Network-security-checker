# Network Vulnerability Scanner

This project is a **user-friendly network security tool** designed to connect the gap between complex technical scanning and everyday users. It transforms a standard Nmap vulnerability scan into a simple, easy-to-understand health report delivered directly to your email.

## 🎯 Project Goal

The primary goal is to make network security accessible. Traditional tools like Nmap produce dense, technical output that is confusing for non-technical users. This application parses those results and explains them in plain English, highlighting risks without the jargon.

## ✨ Key Features

-   **Interactive Web Interface:** A modern, clean web UI (built with Flask) allows users to easily input their targets.
-   **Automated Vulnerability Scanning:** Powered by the industry-standard `nmap` engine, performing in-depth analysis (`-sV --script=vuln`) of network devices.
-   **Smart Report Generation:** A custom parsing engine that translates "Open Port 80" into "There is a website hosted here."
-   **Email Alerts:** Automatically delivers the full health report to the user's inbox.
-   **Cross-Platform Architecture:**
    -   **Web/Cloud:** Dockerized for easy deployment (e.g., Render/AWS).
    -   **Local (macOS):** Features native integration with the Apple Mail app for seamless local usage.

## 🛠️ Technology Stack

-   **Backend:** Python 3, Flask
-   **Scanning Engine:** Nmap (Active) & Socket/IP-API (Passive Fallback)
-   **Email Engine:** Mailgun HTTP API (Primary for Cloud) & SMTP (Fallback)
-   **Deployment:** Docker, Gunicorn
-   **Frontend:** HTML5, CSS3

## 📊 Example Output

Instead of confusing code, the user receives a report like this:

> **Summary:** We found 1 accessible service on this device.
>
> **Detail:** Port 80 is OPEN.
> **What this means:** This usually means a website or web interface is hosted here.
>
> **Action:** If you didn't set this up, you should check your router settings.

## 🚀 Cloud Setup (Render/Heroku)

To ensure email works on cloud platforms, this app uses the **Mailgun API** to bypass SMTP port blocking.

1.  Create a free account at [Mailgun](https://www.mailgun.com/).
2.  Add your **Mailgun Domain** and **Private API Key** to your environment variables:
    -   `MAILGUN_API_KEY`: Your "key-..." or "api-..." value.
    -   `MAILGUN_DOMAIN`: Your sandbox or custom domain.

## ⚠️ Current Status & Limitations

-   **Passive Fallback:** If the hosting provider (like Render) blocks Nmap's active scanning, the app automatically switches to **Passive Mode**. This uses metadata and metadata-lookups to give you security insights without triggering network blocks.
-   **Performance:** Active scans typically take 2-5 minutes; Passive scans take seconds.
