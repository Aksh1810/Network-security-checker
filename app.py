from flask import Flask, render_template, request, flash, redirect, url_for
import threading
import os
import uuid
import json
import time

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Need to import the scanner script. Since it has a hyphen, we use this trick.
import importlib.util
spec = importlib.util.spec_from_file_location("net_hc", "net-hc.py")
net_hc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(net_hc)

# Define where we store temporary scan results
SCAN_DIR = os.path.join(os.getcwd(), 'outputs', 'scans')
if not os.path.exists(SCAN_DIR):
    os.makedirs(SCAN_DIR)

@app.route('/', methods=['GET', 'POST'])
def index():
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if user_ip and ',' in user_ip:
        user_ip = user_ip.split(',')[0].strip()

    if request.method == 'POST':
        ip = request.form.get('ip')
        scan_type = request.form.get('scan_type', 'network')
        
        if not ip:
            flash('Please provide a target IP.')
            return redirect(url_for('index'))
        
        # Create a unique ID for this scan
        scan_id = str(uuid.uuid4())
        
        # Start the background scan
        thread = threading.Thread(target=run_background_scan, args=(scan_id, ip, scan_type))
        thread.start()
        
        # Redirect to the results page (which will show loading state initially)
        return redirect(url_for('view_scan', scan_id=scan_id))
        
    return render_template('index.html', user_ip=user_ip)

@app.route('/scan/<scan_id>')
def view_scan(scan_id):
    scan_file = os.path.join(SCAN_DIR, f"{scan_id}.json")
    
    if os.path.exists(scan_file):
        # Load the results
        with open(scan_file, 'r') as f:
            data = json.load(f)
        
        if data['status'] == 'completed':
            return render_template('result.html', 
                                   scan_output=data['output'], 
                                   ip=data['ip'], 
                                   scan_type=data['scan_type'],
                                   scan_id=scan_id)
        else:
            # Still running
            return render_template('loading.html', ip=data['ip'], scan_type=data['scan_type'])
    else:
        # File doesn't exist yet (race condition) or invalid ID
        time.sleep(0.5) 
        if os.path.exists(scan_file):
             return redirect(url_for('view_scan', scan_id=scan_id))
        return "Scan not found or expired.", 404

@app.route('/scan/<scan_id>/email', methods=['POST'])
def send_report_email(scan_id):
    email = request.form.get('email')
    scan_file = os.path.join(SCAN_DIR, f"{scan_id}.json")
    
    if os.path.exists(scan_file):
        with open(scan_file, 'r') as f:
            data = json.load(f)
            
        if data['status'] == 'completed':
            try:
                success, msg = net_hc.send_email_report(email, data['ip'], data['output'])
                if success:
                    flash(f"SUCCESS: {msg}")
                else:
                    flash(f"ERROR: {msg}")
            except Exception as e:
                flash(f"Error sending email: {e}")
                
            return redirect(url_for('view_scan', scan_id=scan_id))
            
    return "Scan data not found.", 404

def run_background_scan(scan_id, ip, scan_type):
    scan_file = os.path.join(SCAN_DIR, f"{scan_id}.json")
    
    # Save initial state
    with open(scan_file, 'w') as f:
        json.dump({'status': 'running', 'ip': ip, 'scan_type': scan_type, 'output': None}, f)
        
    try:
        # Run scan using the net-hc module
        scan_output = net_hc.run_nmap_scan(ip, scan_type=scan_type)
        
        # Update file with completion
        with open(scan_file, 'w') as f:
            json.dump({'status': 'completed', 'ip': ip, 'scan_type': scan_type, 'output': scan_output}, f)
            
    except Exception as e:
        # Log error in file
        with open(scan_file, 'w') as f:
             json.dump({'status': 'completed', 'ip': ip, 'scan_type': scan_type, 'output': f"Scan failed: {e}"}, f)


@app.route('/test-email', methods=['POST'])
def test_email():
    email = request.form.get('email')
    if email:
        try:
            result = net_hc.send_email_report(email, "TEST_CONNECTION", "This is a quick test from the Network Health Checker.")
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
    else:
        flash("Please enter an email address first.")
    return redirect(url_for('index'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
