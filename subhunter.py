#!/usr/bin/env python3
"""Subdomain enumerator + port scanner + app fingerprint -> CSV

Usage:
  python subhunter.py --domain example.com --wordlist subdomains.txt --output results.csv
"""
import argparse
import csv
import socket
import concurrent.futures
import os
import time
from pathlib import Path
import requests
from requests.exceptions import RequestException
import sys


PORTS_FILE = Path(__file__).parent / 'ports.txt'
APPS_FILE = Path(__file__).parent / 'apps_signatures.txt'
WAF_FILE = Path(__file__).parent / 'waf_signatures.txt'


def load_ports_file(path: Path) -> list:
    """Load ports from a file, one port per line. Returns sorted unique ints.

    Raises FileNotFoundError if file missing.
    """
    ports = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith('#'):
                continue
            try:
                ports.append(int(s))
            except ValueError:
                continue
    return sorted(set(ports))

def load_signatures(path: Path) -> list:
    """Load signature files like apps or wafs. Format: Name:pattern1,pattern2"""
    sigs = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if ':' in line:
                    name, pats = line.split(':', 1)
                    patterns = [p.strip().lower() for p in pats.split(',') if p.strip()]
                    sigs.append((name.strip(), patterns))
    except FileNotFoundError:
        return []
    return sigs

def resolve_host(host):
    try:
        # run getaddrinfo with a timeout to avoid blocking the caller
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(socket.getaddrinfo, host, None)
            try:
                infos = fut.result(timeout=2.0)
            except concurrent.futures.TimeoutError:
                return []
        ips = sorted({info[4][0] for info in infos})
        return ips
    except socket.gaierror:
        return []
    except Exception:
        # catch other errors (e.g. IDNA encoding issues) and treat as unresolved
        return []

def scan_port(ip, port, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.close()
        return True
    except Exception:
        return False

def probe_http(host, ip):
    results = {
        'url': None,
        'status': None,
        'server': None,
        'x_powered_by': None,
        'title': None,
        'body_snippet': None,
    }
    schemes = ['https://', 'http://']
    max_response_time = 5.0
    for scheme in schemes:
        url = scheme + host
        try:
            start = time.monotonic()
            r = requests.get(url, timeout=5, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'})
            elapsed = time.monotonic() - start
            if elapsed > max_response_time:
                # ignore slow responses
                continue
            results['url'] = r.url
            results['status'] = r.status_code
            results['server'] = r.headers.get('Server')
            results['x_powered_by'] = r.headers.get('X-Powered-By')
            text = r.text
            results['body_snippet'] = text[:200].replace('\n',' ')
            start = text.find('<title>')
            end = text.find('</title>')
            if start != -1 and end != -1 and end > start:
                results['title'] = text[start+7:end].strip()
            return results
        except RequestException:
            continue
    return results


def probe_waf(probe):
    # Simple heuristic-based WAF identification from headers/body
    headers_concat = ' '.join([str(probe.get('server') or ''), str(probe.get('x_powered_by') or '')]).lower()
    body = (probe.get('body_snippet') or '').lower()
    status = probe.get('status') or 0

    if 'cloudflare' in headers_concat or 'cf-ray' in (probe.get('server') or '').lower() or 'cf-cache-status' in (probe.get('server') or '').lower():
        return 'Cloudflare'
    if 'akamai' in headers_concat or 'akamai' in body or 'AkamaiGHost'.lower() in (probe.get('server') or '').lower():
        return 'Akamai'
    if 'incapsula' in headers_concat or 'visid_incap' in body or 'incap_ses_' in body:
        return 'Imperva Incapsula'
    if 'sucuri' in headers_concat or 'sucuri' in body:
        return 'Sucuri'
    if 'bigip' in headers_concat or 'f5' in headers_concat or 'x-waf' in headers_concat:
        return 'F5 / BIG-IP'
    if 'mod_security' in headers_concat or 'mod_security' in body or 'mod_security' in (probe.get('server') or '').lower() or 'mod_security' in (probe.get('x_powered_by') or '').lower():
        return 'ModSecurity'
    if 'aws' in headers_concat or 'amazon' in headers_concat or status == 403 and 'waf' in body:
        return 'AWS WAF'
    if 'distil' in headers_concat or 'distil' in body:
        return 'Distil Networks'

    # Fallback checks in body for common WAF phrases
    if 'access denied' in body or 'forbidden' in body or 'request blocked' in body:
        return 'Generic WAF / Firewall'

    return None
    return None


def detect_signatures(probe, signatures):
    """Return semicolon-joined names from signatures that match the probe data."""
    if not signatures:
        return None
    body = (probe.get('body_snippet') or '').lower()
    server = (probe.get('server') or '').lower()
    xpb = (probe.get('x_powered_by') or '').lower()
    title = (probe.get('title') or '').lower()
    matches = []
    for name, patterns in signatures:
        for p in patterns:
            if p in body or p in server or p in xpb or p in title:
                matches.append(name)
                break
    matches = list(dict.fromkeys(matches))
    return ';'.join(matches) if matches else None

def enumerate_subdomains(domain, prefixes, threads=20):
    found = []
    def check(prefix):
        host = f"{prefix}.{domain}" if prefix else domain
        ips = resolve_host(host)
        if ips:
            return (host, ips)
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(check, p.strip()) for p in prefixes if p.strip()]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                found.append(res)
    return sorted(found, key=lambda x: x[0])

def scan_host(host, ips, ports, app_signatures, waf_signatures, verbose):
    """Scan a single host: ports scan, HTTP probe, app guess and WAF detection.

    Args:
        host (str): hostname (subdomain.domain)
        ips (list): list of resolved IPs for host
        ports (list): list of integer ports to check
        signatures (list): app signature tuples (name, patterns)
        verbose (int): verbosity level (0,1,2)
    Returns:
        dict: scan result suitable for CSV writing
    """
    ip = ips[0]
    if verbose >= 1:
        print(f"Scanning {host} -> {ip} ...", flush=True)

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(scan_port, ip, p): p for p in ports}
        for f in concurrent.futures.as_completed(futures):
            p = futures[f]
            try:
                if f.result():
                    open_ports.append(p)
            except Exception:
                pass

    probe = probe_http(host, ip)
    app = detect_signatures(probe, app_signatures)
    waf = detect_signatures(probe, waf_signatures)

    if verbose >= 2:
        if open_ports:
            for p in sorted(open_ports):
                print(f"Open port {p} on {host}", flush=True)
        else:
            print(f"No open common ports on {host}", flush=True)
        if app:
            print(f"App guess for {host}: {app}", flush=True)

    if verbose >= 1:
        ports_str = ','.join(str(p) for p in sorted(open_ports)) if open_ports else 'none'
        print(f"Result {host}: ip={ip} ports={ports_str} status={probe.get('status')} waf={waf}", flush=True)

    return {
        'host': host,
        'ip': ip,
        'open_ports': sorted(open_ports),
        'http_url': probe.get('url'),
        'http_status': probe.get('status'),
        'server': probe.get('server'),
        'x_powered_by': probe.get('x_powered_by'),
        'title': probe.get('title'),
        'app_guess': app,
        'waf': waf,
    }

def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--domain', '-d', help='Domain to enumerate')
    group.add_argument('--list', '-l', help='File with list of domains, one per line')
    parser.add_argument('--wordlist', '-w', default='subdomains.txt', help='Subdomains wordlist')
    parser.add_argument('--output', '-o', default='results.csv', help='Output CSV file')
    parser.add_argument('--threads', '-t', type=int, default=50, help='Threads for enumeration')
    parser.add_argument('--verbose', '-v', type=int, choices=[0,1,2], default=1, help='Verbosity level: 0=quiet, 1=summary, 2=debug')
    args = parser.parse_args()

    try:
        with open(args.wordlist, 'r', encoding='utf-8') as f:
            # sanitize prefixes: strip whitespace and surrounding dots, skip comments
            prefixes = [p for p in (l.strip().strip('.') for l in f if l.strip() and not l.startswith('#')) if p]
    except FileNotFoundError:
        print('Wordlist not found:', args.wordlist, file=sys.stderr)
        sys.exit(1)

    # load ports and application signatures from files (can be expanded later)
    ports_file = os.path.join(os.path.dirname(__file__), 'ports.txt') if not hasattr(args, 'ports_file') else args.ports_file
    apps_file = os.path.join(os.path.dirname(__file__), 'apps_signatures.txt') if not hasattr(args, 'apps_file') else args.apps_file

    try:
        ports_list = load_ports_file(Path(ports_file))
    except FileNotFoundError:
        print('Ports file not found:', ports_file, file=sys.stderr)
        sys.exit(1)

    if not ports_list:
        print('No ports loaded from', ports_file, file=sys.stderr)
        sys.exit(1)

    signatures = load_signatures(Path(apps_file))
    waf_signatures = load_signatures(Path(WAF_FILE))
    verbose = int(args.verbose)

    domains = []
    if args.list:
        try:
            with open(args.list, 'r', encoding='utf-8') as f:
                domains = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        except FileNotFoundError:
            print('Domains list not found:', args.list, file=sys.stderr)
            sys.exit(1)
    else:
        domains = [args.domain]

    # Process each domain separately and produce a per-domain CSV
    for domain in domains:
        print('Enumerating subdomains for', domain)
        subs = enumerate_subdomains(domain, prefixes, threads=min(args.threads, 100))
        print(f'Found {len(subs)} live hosts for {domain}')

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futures = [ex.submit(scan_host, host, ips, ports_list, signatures, waf_signatures, verbose) for host, ips in subs]
            for f in concurrent.futures.as_completed(futures):
                try:
                    results.append(f.result())
                except Exception as e:
                    print('Error scanning host:', e, file=sys.stderr)

        keys = ['host','ip','open_ports','http_url','http_status','server','x_powered_by','title','app_guess','waf']
        # If user passed a list, create per-domain output files; otherwise use provided output
        if args.list:
            outname = domain.replace('.', '_') + '_results.csv'
        else:
            outname = args.output

        with open(outname, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=keys)
            writer.writeheader()
            for r in results:
                row = r.copy()
                row['open_ports'] = ';'.join(str(p) for p in row.get('open_ports', []))
                writer.writerow(row)

        print('Results saved to', outname)

if __name__ == '__main__':
    main()
