import datetime
import ipaddress
import re
import shutil
import threading
import uuid

from flask import Flask, Response, jsonify, redirect, render_template, request, flash, url_for

from scanner.nmap import run_nmap_scan
from scanner.reports import parse_nmap_output, generate_html_report

app = Flask(__name__)
app.secret_key = __import__('os').urandom(24)

# In-memory scan state: {scan_id: {status, ip, scan_type, output, started_at, _proc_store}}
scans = {}

NMAP_AVAILABLE = bool(shutil.which('nmap'))

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

        if NMAP_AVAILABLE:
            scans[scan_id] = {
                'status': 'running',
                'ip': ip,
                'scan_type': scan_type,
                'output': None,
                'started_at': datetime.datetime.now().isoformat(timespec='seconds'),
                '_proc_store': [],
            }
            thread = threading.Thread(
                target=_run_background_scan, args=(scan_id, ip, scan_type), daemon=True
            )
            thread.start()
            return redirect(url_for('view_scan', scan_id=scan_id))

        # Vercel / no-nmap path: run synchronously, render result inline
        from scanner.socket_scanner import run_socket_scan
        try:
            output   = run_socket_scan(ip, scan_type)
            is_error = False
        except Exception as e:
            output   = str(e)
            is_error = True
        parsed = parse_nmap_output(output) if not is_error else None
        return render_template(
            'result.html',
            scan_output=output,
            parsed=parsed,
            ip=ip,
            scan_type=scan_type,
            scan_id=scan_id,
            is_error=is_error,
        )

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


@app.route('/scan/<scan_id>/report')
def download_report(scan_id):
    data = scans.get(scan_id)
    if not data or data['status'] != 'completed':
        return "Report not available.", 404
    html     = generate_html_report(data['ip'], data['output'])
    filename = f"nhc-report-{data['ip'].replace('.', '-')}.html"
    return Response(
        html,
        mimetype='text/html',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


@app.route('/download-report', methods=['POST'])
def download_report_post():
    """Stateless download — works on Vercel where scan state doesn't persist."""
    ip     = request.form.get('ip', 'unknown')
    output = request.form.get('scan_output', '')
    html   = generate_html_report(ip, output)
    fname  = f"nhc-report-{ip.replace('.', '-')}.html"
    return Response(
        html,
        mimetype='text/html',
        headers={'Content-Disposition': f'attachment; filename="{fname}"'},
    )


@app.route('/history')
def history():
    history_list = sorted(
        scans.items(),
        key=lambda x: x[1].get('started_at', ''),
        reverse=True,
    )
    return render_template('history.html', scans=history_list)


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
    app.run(host='0.0.0.0', port=port, debug=True)
