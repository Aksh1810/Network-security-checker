from flask import Flask, render_template, request, flash, redirect, url_for
import threading
import os


app = Flask(__name__)
app.secret_key = os.urandom(24)

# Import functions from the existing script
# Note: Since the filename is net-hc.py with a hyphen, we might need a workaround to import it,
# but usually it's better to rename it. For now, I'll assume we can rename it or use importlib.
# Actually, let's just use importlib to be safe given the hyphen.
import importlib.util
spec = importlib.util.spec_from_file_location("net_hc", "net-hc.py")
net_hc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(net_hc)

@app.route('/', methods=['GET', 'POST'])
def index():
    # Detect User IP (Handles proxies like Render/Heroku)
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    # If multiple IPs are present in X-Forwarded-For, take the first one
    if user_ip and ',' in user_ip:
        user_ip = user_ip.split(',')[0].strip()

    if request.method == 'POST':
        ip = request.form.get('ip')
        email = request.form.get('email')
        
        if not ip or not email:
            flash('Please provide both IP and Email.')
            return redirect(url_for('index'))
        
        # Start scanning in a background thread to avoid timeout
        thread = threading.Thread(target=run_async_scan, args=(ip, email))
        thread.start()
        
        flash(f'Scan started for {ip}! Results will be sent to {email}.')
        return redirect(url_for('index'))
        
    return render_template('index.html', user_ip=user_ip)

def run_async_scan(ip, email):
    """
    Runs the scan and sends email in the background.
    """
    print(f"Background task: Scanning {ip} for {email}")
    try:
        # Run the Nmap Scan
        scan_output = net_hc.run_nmap_scan(ip)
        
        # Checking if the function signature matches what we have in net-hc.py
        # net-hc.py: send_email_report(recipient_email, ip, scan_results)
        net_hc.send_email_report(email, ip, scan_output)
        print("Background task: Finished and emailed.")
        
    except Exception as e:
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Error in background task: {e}")

@app.route('/test-email', methods=['POST'])
def test_email():
    email = request.form.get('email')
    if email:
        print(f"Sending test email to {email}...")
        try:
            # Send a dummy report to verify connectivity
            success, msg = net_hc.send_email_report(email, "TEST_CONNECTION", "This is a quick test from the Render Web App.")
            if success:
                flash(f"SUCCESS: {msg}")
            else:
                flash(f"ERROR: {msg}")
        except Exception as e:
            flash(f"Test crashed: {e}")
            print(f"Test failed: {e}")
    else:
        flash("Please enter an email address first.")
    return redirect(url_for('index'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
