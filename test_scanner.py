"""Self-check for target validation, scan pruning, and report escaping.

Run: python test_scanner.py   (no test framework needed)
"""
import datetime

import app
from scanner.reports import generate_html_report, parse_nmap_output


def test_valid_targets():
    for good in ['127.0.0.1', '8.8.8.8', '::1', 'localhost', 'example.com',
                 'a.sub.domain.co.uk', 'my-host', 'xn--80ak6aa92e.com']:
        assert app.is_valid_target(good), f'should accept {good!r}'


def test_rejected_targets():
    for bad in ['', 'not a host!!', '127.0.0.1; ls', '$(id)', '`id`',
                '127.0.0.1 -oN /tmp/pwn', '-sS 127.0.0.1', '../../etc/passwd',
                '999.999.999.999', '1.2.3.4.5', '<script>alert(1)</script>',
                'a' * 300 + '.com', 'host_with_underscore', '-leading-dash',
                'trailing-dash-', 'has..empty.label']:
        assert not app.is_valid_target(bad), f'should reject {bad!r}'


def test_prune_drops_only_stale_finished_scans():
    now = datetime.datetime.now()
    old = (now - datetime.timedelta(hours=3)).isoformat(timespec='seconds')
    new = now.isoformat(timespec='seconds')
    app.scans.clear()
    app.scans.update({
        'stale-done':    {'status': 'completed', 'started_at': old},
        'stale-running': {'status': 'running',   'started_at': old},
        'fresh-done':    {'status': 'completed', 'started_at': new},
    })
    app._prune_scans()
    assert set(app.scans) == {'stale-running', 'fresh-done'}, app.scans
    app.scans.clear()


def test_report_escapes_untrusted_text():
    # The service column is chosen by the host being scanned; ip comes from a form post.
    scan = 'PORT      STATE  SERVICE\n80/tcp    open   <img/src=x/onerror=alert(1)>'
    out = generate_html_report("<script>alert('ip')</script>", scan)
    assert '<img/src=x/onerror=alert(1)>' not in out
    assert "<script>alert('ip')</script>" not in out
    assert '&lt;img/src=x/onerror=alert(1)&gt;' in out


def test_socket_output_stays_parseable():
    # scanner.socket_scanner fakes nmap-shaped stdout so this parser works unchanged.
    from scanner.socket_scanner import run_socket_scan
    text, count = run_socket_scan('127.0.0.1', 'web')
    assert count > 0
    parsed = parse_nmap_output(text)
    assert isinstance(parsed['open_ports'], list)


if __name__ == '__main__':
    for name, fn in sorted(globals().items()):
        if name.startswith('test_'):
            fn()
            print(f'ok  {name}')
    print('all passed')
