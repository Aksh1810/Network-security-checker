from flask import Flask, render_template, request, flash, redirect, url_for
import threading
import os


app = Flask(__name__)
app.secret_key = os.urandom(24)

# Need to import the scanner script. Since it has a hyphen, we use this trick.
import importlib.util
spec = importlib.util.spec_from_file_location("net_hc", "net-hc.py")
net_hc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(net_hc)

@app.route('/', methods=['GET', 'POST'])
def index():
    # Figure out the user's IP. Needed for cloud hosting like Render.
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    # Sometimes we get a list of IPs, just grab the first one.
    if user_ip and ',' in user_ip:
        user_ip = user_ip.split(',')[0].strip()

    if request.method == 'POST':
        ip = request.form.get('ip')
        email = request.form.get('email')
        
        if not ip or not email:
            flash('Please provide both IP and Email.')
            return redirect(url_for('index'))
        
        # Run the scan in the background so the page doesn't freeze.
        thread = threading.Thread(target=run_async_scan, args=(ip, email))
        thread.start()
        
        flash(f'Scan started for {ip}! Results will be sent to {email}.')
        return redirect(url_for('index'))
        
    return render_template('index.html', user_ip=user_ip)

def run_async_scan(ip, email):
    # This runs quietly in the background.
    print(f"Background task: Scanning {ip} for {email}")
    try:
        # Kick off the Nmap scan
        scan_output = net_hc.run_nmap_scan(ip)
        
        # Send the results via email using the function in net-hc.py
        net_hc.send_email_report(email, ip, scan_output)
        print("Background task: Finished and emailed.")
        
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
            # Just sending a quick test message to make sure email works.
            result = net_hc.send_email_report(email, "TEST_CONNECTION", "This is a quick test from the Network Health Checker.")
            
            # Handle the result, whether it's a tuple or just a boolean.
            if isinstance(result, tuple):
                success, msg = result
            else:
                success, msg = result, "Email operation finished."

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

