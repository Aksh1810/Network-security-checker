# Network Vulnerability Scanner

This project is a **user-friendly network security tool** designed to bridge the gap between complex technical scanning and everyday users. It transforms standard Nmap vulnerability scans into beautiful, easy-to-understand HTML health reports delivered directly to your email.

## 🎯 Project Goal

The primary goal is to make network security accessible. Traditional tools like Nmap produce dense, technical output. This application parses those results and explains them in plain English, highlighting risks without the jargon.

## ✨ Key Features

-   **Interactive Web Interface:** A modern, clean web UI built with Flask.
-   **Automated Scanning:** Powered by `nmap` (`-sV --script=vuln`) for in-depth analysis.
-   **Smart Reports:** Translates technical data into friendly descriptions (e.g., "Open Port 80" -> "Web Website").
-   **Beautiful Email Alerts:** Sends color-coded, styled HTML reports via **SendGrid**.
-   **Cross-Platform:** Works locally and on cloud platforms like Render.

## 🛠️ Technology Stack

-   **Backend:** Python 3, Flask
-   **Scanning Engine:** Nmap (Active) & Socket/IP-API (Passive Fallback)
-   **Email Engine:** SendGrid API (Primary)
-   **Deployment:** Docker, Gunicorn

## 🚀 Setup

To run this on cloud providers (like Render), simply add your **SendGrid API Key** to the environment variables:

-   `SENDGRID_API_KEY`: Your SendGrid API Key starting with `SG...`

*No complex SMTP configuration required.*
