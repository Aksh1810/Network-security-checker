import socket
import concurrent.futures

PORT_SERVICES = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain',
    80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc', 139: 'netbios-ssn',
    143: 'imap', 443: 'https', 445: 'microsoft-ds', 465: 'smtps', 587: 'submission',
    993: 'imaps', 995: 'pop3s', 1433: 'ms-sql-s', 1521: 'oracle',
    2181: 'zookeeper', 2375: 'docker', 2376: 'docker-ssl', 3000: 'ppp',
    3306: 'mysql', 3389: 'ms-wbt-server', 4369: 'epmd', 5000: 'upnp',
    5432: 'postgresql', 5672: 'amqp', 5900: 'vnc', 6379: 'redis',
    6443: 'sun-sr-https', 7001: 'afs3-callback', 8000: 'http-alt',
    8080: 'http-proxy', 8081: 'blackice-icecap', 8443: 'https-alt',
    8888: 'sun-answerbook', 9000: 'cslistener', 9090: 'zeus-admin',
    9200: 'wap-wsp', 9300: 'vrace', 11211: 'memcache', 15672: 'unknown',
    27017: 'mongod', 27018: 'mongod', 28017: 'mongod',
}

_TOP_200 = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1080, 1433, 1521, 2181, 2375, 2376, 3000, 3306, 3389, 4369,
    5000, 5432, 5672, 5900, 6379, 6443, 7001, 8000, 8080, 8081, 8443,
    8888, 9000, 9090, 9200, 9300, 11211, 15672, 27017, 27018, 28017,
    # extend with additional common ports
    20, 24, 26, 69, 79, 88, 106, 113, 119, 137, 138, 179, 199, 389, 427,
    444, 458, 464, 481, 497, 500, 512, 513, 514, 515, 543, 544, 548, 554,
    587, 631, 646, 873, 990, 1025, 1026, 1027, 1028, 1029, 1110, 1720,
    1723, 1755, 1900, 2000, 2049, 2121, 2717, 3128, 3306, 3986, 4899,
    5009, 5051, 5060, 5101, 5190, 5357, 5631, 6000, 6001, 6646, 7070,
    8008, 8009, 8031, 8085, 8090, 8181, 8192, 8200, 8222, 8300, 8500,
    8800, 8899, 9001, 9100, 9999, 10000, 10001, 32768, 49152,
]

_WEB_PORTS   = [80, 443, 8080, 8443, 8000, 8888, 3000]
_FAST_PORTS  = _TOP_200[:100]


def _check_port(ip, port, timeout=1.0):
    try:
        socket.create_connection((ip, port), timeout=timeout).close()
        return port
    except OSError:
        return None


def run_socket_scan(ip, scan_type='network'):
    if scan_type == 'web':
        ports = _WEB_PORTS
    elif scan_type == 'specialty':
        ports = _FAST_PORTS
    else:
        ports = _TOP_200

    ports = list(dict.fromkeys(ports))  # deduplicate, preserve order

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=150) as ex:
        futures = {ex.submit(_check_port, ip, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            result = fut.result()
            if result is not None:
                open_ports.append(result)

    open_ports.sort()

    lines = [
        f"Starting NHC socket scan on {ip}",
        "",
        "PORT      STATE  SERVICE",
    ]
    for p in open_ports:
        svc = PORT_SERVICES.get(p, 'unknown')
        lines.append(f"{p}/tcp    open   {svc}")

    lines += [
        "",
        f"NHC socket scan completed. {len(ports)} ports scanned.",
    ]
    return "\n".join(lines)
