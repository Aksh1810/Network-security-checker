# Network Vulnerability Scanner

A Python script designed to make network security accessible to everyone. It performs vulnerability scanning using `nmap`, translates the technical results into a **simple, non-technical report**, and emails it to the user.

## Features

- **Interactive & Easy:** Simply run the script and enter the Target IP and your Email.
- **Smart Reporting:** Automatically translates complex technical data into a human-readable summary (e.g., explaining what "Port 80" means).
- **Vulnerability Scanning:** Uses Nmap (`-sV --script=vuln`) to detect running services and potential security risks.
- **Seamless Email (macOS):** On macOS, it uses the native **Mail app** to send reports without requiring you to enter a password in the script.
- **Cross-Platform:** Works on Linux/Windows as well (requires SMTP configuration).

## Requirements

1. **Python 3.x**
2. **Nmap** installed:
   - MacOS: `brew install nmap`
   - Linux: `sudo apt install nmap`
3. **Email Configuration:**
   - **MacOS:** Uses your local Mail app accounts automatically (Default sender request: `networksecscanner@gmail.com`).
   - **Linux/Windows:** Requires a Gmail account and App Password.

## Usage

1.  **Run the script:**
    ```bash
    python3 net-hc.py
    ```

2.  **Follow the prompts:**
    - Enter the **IP Address** you want to scan.
    - Enter the **Email Address** where you want to receive the report.

3.  **Get your Report:**
    - The script will scan the target (this may take a few minutes).
    - It will generate a **Simple Network Health Report**.
    - The report is saved locally in `outputs/` and emailed to you.

## Configuration (Optional for macOS)

**If you are on Linux/Windows** or want to force a specific Gmail account via SMTP, you must configure the credentials:

1.  Open `net-hc.py`.
2.  Edit the variables or set environment variables:
    ```python
    SENDER_EMAIL = 'your_account@gmail.com'
    SENDER_PASSWORD = 'your_app_password' # Generate this in Google Account > Security
    ```

## Output Example

The email report includes a friendly summary like this:

> **GOOD NEWS:** We found no 'open doors' (ports) on this device.

Or:

> **ATTENTION:** Port 80 is OPEN. This usually means a website is hosted here.

## 🌐 Web Application

You can also run this tool as a web interface:
1. Install dependencies: `pip install -r requirements.txt`
2. Run the server: `python3 app.py`
3. Open `http://localhost:5000`

## 🚀 Deployment (Render)

This project is ready for Docker-based deployment (e.g., on Render):

1. **New Web Service:** Connect this repo on Render.
2. **Environment Variables:**
   - `SENDER_EMAIL`: `networksecscanner@gmail.com`
   - `SENDER_PASSWORD`: *(Your Google App Password)*
3. **Deploy:** Render will automatically build the `Dockerfile` and launch the app.

