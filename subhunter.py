#!/usr/bin/env python3
"""Subdomain enumerator + port scanner + app fingerprint -> CSV

Usage:
  python subhunter.py --domain example.com --wordlist subdomains.txt --output results.csv
"""
import argparse
import csv
import socket
import concurrent.futures
import requests
from requests.exceptions import RequestException
import sys

COMMON_PORTS = [21,22,23,25,53,80,110,143,443,445,465,587,636,993,995,1433,1521,3306,3389,5900,8080]

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
            import time
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

def guess_application(probe):
    hints = []
    body = (probe.get('body_snippet') or '').lower()
    server = (probe.get('server') or '').lower()
    xpb = (probe.get('x_powered_by') or '').lower()
    title = (probe.get('title') or '').lower()

    if 'wordpress' in body or 'wp-' in body or 'xmlrpc.php' in body:
        hints.append('WordPress')
    if 'joomla' in body or 'administrator/' in body:
        hints.append('Joomla')
    if 'drupal' in body:
        hints.append('Drupal')
    if 'shopify' in body or 'cdn.shopify.com' in body:
        hints.append('Shopify')
    if 'magento' in body:
        hints.append('Magento')
    if 'asp.net' in xpb or 'microsoft-iis' in server:
        hints.append('ASP.NET / IIS')
    if 'nginx' in server:
        hints.append('nginx')
    if 'apache' in server:
        hints.append('Apache')
    if 'gunicorn' in server or 'uwsgi' in server:
        hints.append('Python WSGI')
    if not hints and title:
        if 'express' in title:
            hints.append('Node/Express')

    return ';'.join(hints) if hints else None

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

def scan_host(host, ips, ports=COMMON_PORTS):
    ip = ips[0]
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
    app = guess_application(probe)
    waf = probe_waf(probe)
    # concise result line
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
    args = parser.parse_args()

    try:
        with open(args.wordlist, 'r', encoding='utf-8') as f:
            # sanitize prefixes: strip whitespace and surrounding dots, skip comments
            prefixes = [p for p in (l.strip().strip('.') for l in f if l.strip() and not l.startswith('#')) if p]
    except FileNotFoundError:
        print('Wordlist not found:', args.wordlist, file=sys.stderr)
        sys.exit(1)

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
            futures = [ex.submit(scan_host, host, ips) for host, ips in subs]
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
