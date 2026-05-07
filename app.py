import datetime
import ipaddress
import re
import threading
import uuid

from flask import Flask, jsonify, redirect, render_template, request, flash, url_for

from scanner.nmap import run_nmap_scan
from scanner.email import send_email_report
from scanner.reports import parse_nmap_output

app = Flask(__name__)
app.secret_key = __import__('os').urandom(24)

# In-memory scan state: {scan_id: {status, ip, scan_type, output, started_at, _proc_store}}
scans = {}

_HOSTNAME_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

def is_valid_target(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(target))


@app.route('/', methods=['GET', 'POST'])
def index():
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if user_ip and ',' in user_ip:
        user_ip = user_ip.split(',')[0].strip()

    if request.method == 'POST':
        ip        = (request.form.get('ip') or '').strip()
        scan_type = request.form.get('scan_type', 'network')

        if not ip:
            flash('Please provide a target IP or hostname.')
            return redirect(url_for('index'))

        if not is_valid_target(ip):
            flash('Invalid target. Please enter a valid IP address or hostname.')
            return redirect(url_for('index'))

        scan_id = str(uuid.uuid4())

        scans[scan_id] = {
            'status': 'running',
            'ip': ip,
            'scan_type': scan_type,
            'output': None,
            'started_at': datetime.datetime.now().isoformat(timespec='seconds'),
            '_proc_store': [],
        }

        thread = threading.Thread(target=_run_background_scan, args=(scan_id, ip, scan_type), daemon=True)
        thread.start()

        return redirect(url_for('view_scan', scan_id=scan_id))

    return render_template('index.html', user_ip=user_ip)


@app.route('/scan/<scan_id>')
def view_scan(scan_id):
    data = scans.get(scan_id)
    if not data:
        return "Scan not found or expired.", 404

    if data['status'] == 'running':
        return render_template('loading.html', ip=data['ip'], scan_type=data['scan_type'], scan_id=scan_id)

    is_error = (data['status'] == 'error')
    parsed   = parse_nmap_output(data['output']) if not is_error and data['output'] else None

    return render_template(
        'result.html',
        scan_output=data['output'],
        parsed=parsed,
        ip=data['ip'],
        scan_type=data['scan_type'],
        scan_id=scan_id,
        is_error=is_error,
    )


@app.route('/scan/<scan_id>/status')
def scan_status(scan_id):
    data = scans.get(scan_id)
    if not data:
        return jsonify({'status': 'not_found'}), 404
    return jsonify({'status': data['status']})


@app.route('/scan/<scan_id>/cancel', methods=['POST'])
def cancel_scan(scan_id):
    data = scans.get(scan_id)
    if not data or data['status'] != 'running':
        return jsonify({'ok': False, 'reason': 'not running'}), 400
    for proc in data.get('_proc_store', []):
        proc.kill()
    scans[scan_id].update({'status': 'error', 'output': 'Scan cancelled by user.'})
    return jsonify({'ok': True})


@app.route('/scan/<scan_id>/email', methods=['POST'])
def send_report_email(scan_id):
    email = request.form.get('email')
    data  = scans.get(scan_id)

    if not data or data['status'] != 'completed':
        return "Scan data not found or not yet complete.", 404

    try:
        success, msg = send_email_report(email, data['ip'], data['output'])
        flash(f"{'SUCCESS' if success else 'ERROR'}: {msg}")
    except Exception as e:
        flash(f"ERROR: Error sending email: {e}")

    return redirect(url_for('view_scan', scan_id=scan_id))


@app.route('/history')
def history():
    history_list = sorted(
        scans.items(),
        key=lambda x: x[1].get('started_at', ''),
        reverse=True,
    )
    return render_template('history.html', scans=history_list)


@app.route('/test-email', methods=['POST'])
def test_email():
    email = request.form.get('email')
    if email:
        try:
            success, msg = send_email_report(email, "TEST_CONNECTION",
                                             "This is a quick test from the Network Health Checker.")
            flash(f"{'SUCCESS' if success else 'ERROR'}: {msg}")
        except Exception as e:
            flash(f"ERROR: Test crashed: {e}")
    else:
        flash('Please enter an email address first.')
    return redirect(url_for('index'))


def _run_background_scan(scan_id, ip, scan_type):
    proc_store = scans[scan_id]['_proc_store']
    try:
        output = run_nmap_scan(ip, scan_type=scan_type, proc_store=proc_store)
        if scans[scan_id]['status'] == 'running':
            scans[scan_id].update({'status': 'completed', 'output': output})
    except Exception as e:
        if scans[scan_id]['status'] == 'running':
            scans[scan_id].update({'status': 'error', 'output': str(e)})


if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port)
