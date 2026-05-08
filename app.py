import datetime
import ipaddress
import os
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

ON_VERCEL     = bool(os.environ.get('VERCEL'))
NMAP_AVAILABLE = not ON_VERCEL and bool(shutil.which('nmap'))

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
    user_ip = (
        request.headers.get('X-Real-IP')
        or request.headers.get('X-Vercel-Forwarded-For')
        or request.headers.get('X-Forwarded-For')
        or request.remote_addr
    )
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
        ports_scanned = 0
        try:
            output, ports_scanned = run_socket_scan(ip, scan_type)
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
            ports_scanned=ports_scanned,
        )

    return render_template('index.html', user_ip=user_ip, nmap_available=NMAP_AVAILABLE)


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


@app.route('/_debug/connect/<host>/<int:port>')
def debug_connect(host, port):
    """Temporary: confirms whether the Vercel function can open a TCP socket.
    Remove once the scanner is verified end-to-end."""
    import socket
    import time
    t0 = time.time()
    try:
        s = socket.create_connection((host, port), timeout=3.0)
        s.close()
        return jsonify({
            'ok': True, 'host': host, 'port': port,
            'elapsed_ms': int((time.time() - t0) * 1000),
        })
    except Exception as e:
        return jsonify({
            'ok': False, 'host': host, 'port': port,
            'error_type': type(e).__name__,
            'error': str(e),
            'elapsed_ms': int((time.time() - t0) * 1000),
        })


@app.route('/_debug/headers')
def debug_headers():
    """Temporary: shows what proxy headers Vercel passes to the function,
    so we can verify which header carries the real client IP."""
    interesting = [
        'X-Real-IP', 'X-Forwarded-For', 'X-Vercel-Forwarded-For',
        'X-Vercel-IP-Country', 'X-Vercel-IP-City', 'X-Vercel-IP-Region',
        'CF-Connecting-IP', 'True-Client-IP',
    ]
    return jsonify({
        'remote_addr': request.remote_addr,
        'headers': {h: request.headers.get(h) for h in interesting if request.headers.get(h)},
    })


@app.route('/history')
def history():
    return render_template('history.html')


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
