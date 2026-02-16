#!/usr/bin/env python3
"""Subdomain enumerator with port scanning and application fingerprinting.

This tool enumerates subdomains, scans ports, probes HTTP services,
and detects applications and WAFs.

Usage:
  python subhunter.py --domain example.com --wordlist subdomains.txt
  python subhunter.py --list domains.txt --wordlist subdomains.txt
"""
import argparse
import csv
import socket
import concurrent.futures
import time
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set

import requests
from requests.exceptions import RequestException
import urllib3

# Suppress SSL warnings for self-signed certificates and testing purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Constants
PORTS_FILE = Path(__file__).parent / 'ports.txt'
APPS_SIGNATURES_FILE = Path(__file__).parent / 'apps_signatures.txt'
WAF_SIGNATURES_FILE = Path(__file__).parent / 'waf_signatures.txt'

# Timeouts in seconds
DNS_RESOLUTION_TIMEOUT = 2.0
SOCKET_TIMEOUT = 1.0
HTTP_REQUEST_TIMEOUT = 5.0
HTTP_MAX_RESPONSE_TIME = 5.0

# HTTP configuration
HTTP_HEADERS = {'User-Agent': 'Mozilla/5.0'}
BODY_SNIPPET_SIZE = 200

# Thread pool sizes
ENUMERATION_THREADS = 20
PORT_SCAN_THREADS = 50
HOST_SCAN_THREADS = 10

# Verbosity levels
VERBOSITY_QUIET = 0
VERBOSITY_SUMMARY = 1
VERBOSITY_DEBUG = 2


class SubdomainEnumerator:
    """Handles subdomain enumeration and host discovery."""

    @staticmethod
    def resolve_host(host: str) -> List[str]:
        """Resolve hostname to list of IP addresses.
        
        Args:
            host: Hostname to resolve
            
        Returns:
            Sorted list of unique IP addresses, or empty list if resolution fails
        """
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(socket.getaddrinfo, host, None)
                try:
                    addresses = future.result(timeout=DNS_RESOLUTION_TIMEOUT)
                except concurrent.futures.TimeoutError:
                    return []
            
            ips = sorted(set(addr[4][0] for addr in addresses))
            return ips
        except (socket.gaierror, Exception):
            return []

    @staticmethod
    def enumerate(domain: str, prefixes: List[str], threads: int = ENUMERATION_THREADS) -> List[Tuple[str, List[str]]]:
        """Enumerate subdomains for a domain.
        
        Args:
            domain: Base domain to enumerate
            prefixes: List of subdomain prefixes to try
            threads: Number of concurrent threads
            
        Returns:
            List of tuples (hostname, ip_list) for resolved subdomains
        """
        found = []

        def check_subdomain(prefix: str) -> Optional[Tuple[str, List[str]]]:
            if not prefix:
                return None
            host = f"{prefix}.{domain}"
            ips = SubdomainEnumerator.resolve_host(host)
            return (host, ips) if ips else None

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [
                executor.submit(check_subdomain, p.strip())
                for p in prefixes if p.strip()
            ]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        return sorted(found, key=lambda x: x[0])


class PortScanner:
    """Handles port scanning functionality."""

    @staticmethod
    def scan_port(ip: str, port: int, timeout: float = SOCKET_TIMEOUT) -> bool:
        """Check if a port is open on an IP address.
        
        Args:
            ip: IP address to scan
            port: Port number to check
            timeout: Connection timeout in seconds
            
        Returns:
            True if port is open, False otherwise
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            sock.close()
            return True
        except Exception:
            return False
        finally:
            sock.close()

    @staticmethod
    def scan_ports(ip: str, ports: List[int], threads: int = PORT_SCAN_THREADS) -> List[int]:
        """Scan multiple ports on an IP address.
        
        Args:
            ip: IP address to scan
            ports: List of port numbers to check
            threads: Number of concurrent scanning threads
            
        Returns:
            Sorted list of open ports
        """
        open_ports = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(PortScanner.scan_port, ip, port): port for port in ports}
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception:
                    pass

        return sorted(open_ports)


class HTTPProber:
    """Handles HTTP probing and response analysis."""

    @staticmethod
    def probe_host(host: str, ip: str) -> Dict[str, Optional[str]]:
        """Probe HTTP/HTTPS services on a host.
        
        Args:
            host: Hostname to probe
            ip: IP address (for fallback)
            
        Returns:
            Dictionary with HTTP response details
        """
        result = {
            'url': None,
            'status': None,
            'server': None,
            'x_powered_by': None,
            'title': None,
            'body_snippet': None,
        }

        schemes = ['https://', 'http://']

        for scheme in schemes:
            url = f"{scheme}{host}"
            try:
                start_time = time.monotonic()
                response = requests.get(
                    url,
                    timeout=HTTP_REQUEST_TIMEOUT,
                    allow_redirects=True,
                    headers=HTTP_HEADERS,
                    verify=False
                )
                elapsed = time.monotonic() - start_time

                if elapsed > HTTP_MAX_RESPONSE_TIME:
                    continue

                result['url'] = response.url
                result['status'] = response.status_code
                result['server'] = response.headers.get('Server')
                result['x_powered_by'] = response.headers.get('X-Powered-By')
                result['body_snippet'] = response.text[:BODY_SNIPPET_SIZE].replace('\n', ' ')
                
                # Extract title from HTML
                title_start = response.text.find('<title>')
                title_end = response.text.find('</title>')
                if title_start != -1 and title_end != -1 and title_end > title_start:
                    result['title'] = response.text[title_start + 7:title_end].strip()

                return result
            except RequestException:
                continue
            except Exception:
                continue

        return result


class SignatureDetector:
    """Detects applications and WAFs based on signatures."""

    @staticmethod
    def load_signatures(path: Path) -> List[Tuple[str, List[str]]]:
        """Load signature file. Format: Name:pattern1,pattern2
        
        Args:
            path: Path to signature file
            
        Returns:
            List of tuples (signature_name, pattern_list)
        """
        signatures = []
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if ':' in line:
                        name, patterns_str = line.split(':', 1)
                        patterns = [
                            p.strip().lower() for p in patterns_str.split(',') if p.strip()
                        ]
                        if patterns:
                            signatures.append((name.strip(), patterns))
        except FileNotFoundError:
            pass
        return signatures

    @staticmethod
    def detect_signatures(probe: Dict[str, Optional[str]], signatures: List[Tuple[str, List[str]]]) -> Optional[str]:
        """Detect matched signatures in HTTP probe data.
        
        Args:
            probe: HTTP probe result dictionary
            signatures: List of signature tuples
            
        Returns:
            Semicolon-separated list of matched signatures, or None
        """
        if not signatures:
            return None

        body = (probe.get('body_snippet') or '').lower()
        server = (probe.get('server') or '').lower()
        x_powered_by = (probe.get('x_powered_by') or '').lower()
        title = (probe.get('title') or '').lower()

        matched = []
        for name, patterns in signatures:
            for pattern in patterns:
                if pattern in body or pattern in server or pattern in x_powered_by or pattern in title:
                    matched.append(name)
                    break

        # Remove duplicates while preserving order
        matched = list(dict.fromkeys(matched))
        return ';'.join(matched) if matched else None

    @staticmethod
    def detect_waf(probe: Dict[str, Optional[str]], waf_signatures: List[Tuple[str, List[str]]]) -> Optional[str]:
        """Detect Web Application Firewall (WAF) using signature patterns.
        
        Args:
            probe: HTTP probe result dictionary
            waf_signatures: List of WAF signature tuples from configuration file
            
        Returns:
            Detected WAF name, or None if no WAF detected
        """
        if not waf_signatures:
            return None
            
        headers_text = ' '.join([
            str(probe.get('server') or ''),
            str(probe.get('x_powered_by') or '')
        ]).lower()
        body = (probe.get('body_snippet') or '').lower()

        for waf_name, patterns in waf_signatures:
            for pattern in patterns:
                if pattern in headers_text or pattern in body:
                    return waf_name

        return None


class PortLoader:
    """Loads port lists from configuration files."""

    @staticmethod
    def load_ports(path: Path) -> List[int]:
        """Load ports from file, one per line.
        
        Args:
            path: Path to ports file
            
        Returns:
            Sorted list of unique ports
            
        Raises:
            FileNotFoundError: If file doesn't exist
        """
        ports: Set[int] = set()
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    ports.add(int(line))
                except ValueError:
                    continue
        return sorted(ports)

    @staticmethod
    def get_ports(ports_file: Optional[Path] = None) -> List[int]:
        """Get ports list from file.
        
        Args:
            ports_file: Path to ports file (defaults to PORTS_FILE)
            
        Returns:
            List of ports to scan
            
        Raises:
            FileNotFoundError: If ports file doesn't exist
        """
        target_file = ports_file or PORTS_FILE
        if not target_file.exists():
            raise FileNotFoundError(f"Ports file not found: {target_file}")
        return PortLoader.load_ports(target_file)


class HostScanner:
    """Scans individual hosts for open ports and services."""

    def __init__(self, app_signatures: List[Tuple[str, List[str]]], waf_signatures: List[Tuple[str, List[str]]], verbose: int = VERBOSITY_SUMMARY):
        """Initialize host scanner.
        
        Args:
            app_signatures: Application signature patterns
            waf_signatures: WAF signature patterns
            verbose: Verbosity level
        """
        self.app_signatures = app_signatures
        self.waf_signatures = waf_signatures
        self.verbose = verbose

    def scan(self, host: str, ips: List[str], ports: List[int]) -> Dict:
        """Scan a single host.
        
        Args:
            host: Hostname to scan
            ips: List of resolved IP addresses
            ports: List of ports to scan
            
        Returns:
            Dictionary with scan results
        """
        ip = ips[0]
        
        if self.verbose >= VERBOSITY_SUMMARY:
            print(f"Scanning {host} -> {ip} ...", flush=True)

        # Scan ports
        open_ports = PortScanner.scan_ports(ip, ports)

        # Probe HTTP
        probe = HTTPProber.probe_host(host, ip)

        # Detect applications and WAF
        app = SignatureDetector.detect_signatures(probe, self.app_signatures)
        waf = SignatureDetector.detect_waf(probe, self.waf_signatures)

        if self.verbose >= VERBOSITY_DEBUG:
            if open_ports:
                for port in open_ports:
                    print(f"  Open port {port}", flush=True)
            if app:
                print(f"  Applications: {app}", flush=True)

        if self.verbose >= VERBOSITY_SUMMARY:
            ports_str = ','.join(str(p) for p in open_ports) if open_ports else 'none'
            status = probe.get('status') or 'N/A'
            print(f"  Result: {host} -> {ip} ({ports_str}) [HTTP {status}] WAF: {waf or 'None'}", flush=True)

        return {
            'host': host,
            'ip': ip,
            'open_ports': open_ports,
            'http_url': probe.get('url'),
            'http_status': probe.get('status'),
            'server': probe.get('server'),
            'x_powered_by': probe.get('x_powered_by'),
            'title': probe.get('title'),
            'app_guess': app,
            'waf': waf,
        }


def load_wordlist(path: str) -> List[str]:
    """Load subdomain prefixes from wordlist file.
    
    Args:
        path: Path to wordlist file
        
    Returns:
        List of cleaned subdomain prefixes
        
    Raises:
        FileNotFoundError: If file doesn't exist
    """
    prefixes = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            prefix = line.strip().strip('.')
            if prefix and not prefix.startswith('#'):
                prefixes.append(prefix)
    return prefixes


def load_domains(path: str) -> List[str]:
    """Load domain list from file.
    
    Args:
        path: Path to domains file
        
    Returns:
        List of domains
        
    Raises:
        FileNotFoundError: If file doesn't exist
    """
    domains = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            domain = line.strip()
            if domain and not domain.startswith('#'):
                domains.append(domain)
    return domains


def process_domain(
    domain: str,
    prefixes: List[str],
    ports: List[int],
    app_signatures: List[Tuple[str, List[str]]],
    waf_signatures: List[Tuple[str, List[str]]],
    threads: int,
    verbose: int = VERBOSITY_SUMMARY
) -> Tuple[str, List[Dict]]:
    """Process a single domain: enumerate, scan, and detect.
    
    Args:
        domain: Domain to process
        prefixes: Subdomain prefixes
        ports: Ports to scan
        app_signatures: Application signatures
        waf_signatures: WAF signatures
        threads: Number of threads for scanning
        verbose: Verbosity level
        
    Returns:
        Tuple of (output_filename, results_list)
    """
    print(f"\nEnumerating subdomains for {domain}...")
    subdomains = SubdomainEnumerator.enumerate(domain, prefixes, threads=min(threads, 100))
    print(f"Found {len(subdomains)} live hosts for {domain}")

    results = []
    scanner = HostScanner(app_signatures, waf_signatures, verbose)

    with concurrent.futures.ThreadPoolExecutor(max_workers=HOST_SCAN_THREADS) as executor:
        futures = [
            executor.submit(scanner.scan, host, ips, ports)
            for host, ips in subdomains
        ]
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                print(f"Error scanning host: {e}", file=sys.stderr)

    return domain, results


def save_results(domain: str, results: List[Dict], is_batch: bool = False, output_path: str = 'results.csv') -> str:
    """Save scan results to CSV file.
    
    Args:
        domain: Domain name (used for filename if batch mode)
        results: List of scan result dictionaries
        is_batch: Whether this is batch mode (multiple domains)
        output_path: Output file path
        
    Returns:
        Path to output file
    """
    if is_batch:
        output_file = f"{domain.replace('.', '_')}_results.csv"
    else:
        output_file = output_path

    fieldnames = ['host', 'ip', 'open_ports', 'http_url', 'http_status', 
                  'server', 'x_powered_by', 'title', 'app_guess', 'waf']

    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            row_data = row.copy()
            row_data['open_ports'] = ';'.join(str(p) for p in row_data.get('open_ports', []))
            writer.writerow({field: row_data.get(field) for field in fieldnames})

    print(f"Results saved to {output_file}")
    return output_file


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Subdomain enumerator with port scanning and application detection'
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--domain', '-d', help='Single domain to enumerate')
    group.add_argument('--list', '-l', help='File with list of domains (one per line)')
    
    parser.add_argument(
        '--wordlist', '-w',
        default='subdomains.txt',
        help='Subdomain wordlist file (default: subdomains.txt)'
    )
    parser.add_argument(
        '--ports-file', '-p',
        help='Custom ports file (default: ports.txt)'
    )
    parser.add_argument(
        '--output', '-o',
        default='results.csv',
        help='Output CSV file (default: results.csv)'
    )
    parser.add_argument(
        '--threads', '-t',
        type=int,
        default=50,
        help='Thread count for enumeration (default: 50)'
    )
    parser.add_argument(
        '--verbose', '-v',
        type=int,
        choices=[0, 1, 2],
        default=VERBOSITY_SUMMARY,
        help='Verbosity level: 0=quiet, 1=summary, 2=debug (default: 1)'
    )

    args = parser.parse_args()

    # Load wordlist
    try:
        prefixes = load_wordlist(args.wordlist)
        if not prefixes:
            print(f"Error: No valid prefixes in {args.wordlist}", file=sys.stderr)
            return 1
    except FileNotFoundError:
        print(f"Error: Wordlist not found: {args.wordlist}", file=sys.stderr)
        return 1

    # Load ports
    ports_file = Path(args.ports_file) if args.ports_file else PORTS_FILE
    try:
        ports = PortLoader.get_ports(ports_file)
        if not ports:
            print(f"Error: No ports found in {ports_file}", file=sys.stderr)
            return 1
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Load signatures
    app_signatures = SignatureDetector.load_signatures(APPS_SIGNATURES_FILE)
    waf_signatures = SignatureDetector.load_signatures(WAF_SIGNATURES_FILE)

    # Determine domains to process
    domains = []
    if args.list:
        try:
            domains = load_domains(args.list)
            if not domains:
                print(f"Error: No valid domains in {args.list}", file=sys.stderr)
                return 1
        except FileNotFoundError:
            print(f"Error: Domains list not found: {args.list}", file=sys.stderr)
            return 1
    else:
        domains = [args.domain]

    # Process each domain
    for domain in domains:
        try:
            _, results = process_domain(
                domain, prefixes, ports, app_signatures, waf_signatures,
                args.threads, args.verbose
            )
            save_results(domain, results, is_batch=bool(args.list), output_path=args.output)
        except Exception as e:
            print(f"Error processing domain {domain}: {e}", file=sys.stderr)
            return 1

    print("\nDone!")
    return 0


if __name__ == '__main__':
    sys.exit(main())
