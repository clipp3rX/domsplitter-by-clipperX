#!/usr/bin/env python3
"""
Domain Splitter Advanced - A comprehensive domain analysis tool
"""
import socket
import requests
import argparse
import sys
import time
import concurrent.futures
import dns.resolver
import whois
import ssl
import OpenSSL
import json
import os
import re
import random
import ipaddress
import urllib3
import tldextract
import logging
from datetime import datetime
from colorama import init, Fore, Style
from tabulate import tabulate
from tqdm import tqdm
from PIL import Image
from io import BytesIO
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

# Import HTML report generator
try:
    from html_report import HTMLReportGenerator
except ImportError:
    HTMLReportGenerator = None

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

TOOL_NAME = "domain-splitter-advanced"
VERSION = "2.0"
AUTHOR = "SuperNinja"

BANNER = f"""
{Fore.BLUE + Style.BRIGHT}
   ____                        _       ____        _ _ _           
  |  _ \\  ___  _ __ ___   __ _(_)_ __ |  _ \\ _   _(_) | |_ ___ _ __ 
  | | |/ _ \\| '_ ` _ \\ / _` | | '_ \\| | | | | | | | | __/ _ \\ '__|
  | |_| | (_) | | | | | | (_| | | | | |_| | |_| | | | ||  __/ |   
  |____/ \\___/|_| |_| |_|\\__, |_|_| |_|____/ \\__,_|_|_|\\__\\___|_|   
                         |___/                                      
        {domsplitter} v{2.0} - Advanced Domain Analysis Tool
        Author: {clipperX}
{Style.RESET_ALL}
"""

# User agents for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11.5; rv:90.0) Gecko/20100101 Firefox/90.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15",
]

# Common ports to scan
COMMON_PORTS = [21, 22, 25, 53, 80, 443, 8080, 8443]

# DNS record types to check
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]

class DomainAnalyzer:
    """Main class for domain analysis functionality"""
    
    def __init__(self, args):
        """Initialize with command line arguments"""
        self.args = args
        self.results = {}
        self.dns_cache = {}
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})
        self.session.verify = not args.ignore_ssl_errors
        self.session.timeout = args.timeout
        
        # Set up proxy if provided
        if args.proxy:
            self.session.proxies = {
                "http": args.proxy,
                "https": args.proxy
            }
            
        # Set up screenshot capability if enabled
        if args.screenshot:
            self._setup_webdriver()
            
    def _setup_webdriver(self):
        """Set up headless Chrome for screenshots"""
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")
        
        try:
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=options)
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Could not initialize webdriver for screenshots: {e}")
            self.args.screenshot = False
    
    def analyze_domains(self, domains):
        """Analyze a list of domains with concurrent processing"""
        start_time = time.time()
        
        if not self.args.quiet:
            print(f"\n{Fore.GREEN}[+] Scanning {len(domains)} domains...\n")
        
        # Use ThreadPoolExecutor for concurrent processing
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            if self.args.quiet:
                # Run silently for CI/CD integration
                results = list(executor.map(self.analyze_domain, domains))
            else:
                # Show progress bar
                results = list(tqdm(
                    executor.map(self.analyze_domain, domains),
                    total=len(domains),
                    desc="Analyzing domains",
                    unit="domain"
                ))
        
        # Process results
        alive_domains = [r for r in results if r.get("is_alive")]
        dead_domains = [r for r in results if not r.get("is_alive")]
        
        # Calculate scan duration
        scan_duration = time.time() - start_time
        
        # Save results
        self._save_results(results, alive_domains, dead_domains)
        
        # Generate HTML report if requested
        if self.args.html_report:
            self._generate_html_report(results, scan_duration)
        
        # Print summary
        if not self.args.quiet:
            self._print_summary(results, alive_domains, dead_domains, scan_duration)
        
        return results
    
    def analyze_domain(self, domain):
        """Analyze a single domain and return results"""
        result = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "is_subdomain": self._is_subdomain(domain),
            "ip_addresses": {},
            "is_alive": False,
            "response_code": None,
            "response_time": None,
            "dns_records": {},
            "ssl_info": {},
            "ports": {},
            "whois": {},
            "waf_detected": False,
            "screenshot": None
        }
        
        # Resolve IP addresses (both IPv4 and IPv6)
        result["ip_addresses"] = self._resolve_ips(domain)
        
        # Check if domain is alive
        if self.args.check_alive:
            alive_result = self._check_alive(domain)
            result.update(alive_result)
        
        # Get DNS records
        if self.args.dns:
            result["dns_records"] = self._get_dns_records(domain)
        
        # Check SSL certificate
        if self.args.ssl and result["is_alive"]:
            result["ssl_info"] = self._check_ssl(domain)
        
        # Scan ports
        if self.args.ports:
            result["ports"] = self._scan_ports(domain)
        
        # Get WHOIS information
        if self.args.whois:
            result["whois"] = self._get_whois(domain)
        
        # Check for WAF
        if self.args.waf and result["is_alive"]:
            result["waf_detected"] = self._detect_waf(domain)
        
        # Take screenshot
        if self.args.screenshot and result["is_alive"]:
            result["screenshot"] = self._take_screenshot(domain)
        
        return result
    
    def _is_subdomain(self, domain):
        """Check if domain is a subdomain"""
        extracted = tldextract.extract(domain)
        return bool(extracted.subdomain)
    
    def _resolve_ips(self, domain):
        """Resolve both IPv4 and IPv6 addresses"""
        result = {"ipv4": [], "ipv6": []}
        
        # Check if we have this in cache
        if domain in self.dns_cache:
            return self.dns_cache[domain]
        
        # Resolve IPv4
        try:
            ipv4_addresses = socket.getaddrinfo(domain, None, socket.AF_INET)
            result["ipv4"] = list(set(addr[4][0] for addr in ipv4_addresses))
        except socket.gaierror:
            pass
        
        # Resolve IPv6
        try:
            ipv6_addresses = socket.getaddrinfo(domain, None, socket.AF_INET6)
            result["ipv6"] = list(set(addr[4][0] for addr in ipv6_addresses))
        except socket.gaierror:
            pass
        
        # Cache the result
        self.dns_cache[domain] = result
        return result
    
    def _check_alive(self, domain):
        """Check if domain is alive via HTTP/HTTPS"""
        result = {
            "is_alive": False,
            "response_code": None,
            "response_time": None,
            "http_headers": {},
            "redirect_url": None,
            "server": None,
            "content_type": None
        }
        
        # Try HTTPS first, then HTTP if HTTPS fails
        for protocol in ["https", "http"]:
            url = f"{protocol}://{domain}"
            try:
                start_time = time.time()
                response = self.session.get(
                    url, 
                    timeout=self.args.timeout,
                    allow_redirects=self.args.follow_redirects,
                    verify=False if self.args.ignore_ssl_errors else True
                )
                response_time = time.time() - start_time
                
                result["is_alive"] = True
                result["response_code"] = response.status_code
                result["response_time"] = round(response_time, 3)
                result["http_headers"] = dict(response.headers)
                result["server"] = response.headers.get("Server")
                result["content_type"] = response.headers.get("Content-Type")
                
                if response.url != url:
                    result["redirect_url"] = response.url
                
                # We found a working protocol, no need to try the other
                break
            except requests.RequestException:
                continue
        
        return result
    
    def _get_dns_records(self, domain):
        """Get various DNS records for the domain"""
        results = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.args.timeout
        resolver.lifetime = self.args.timeout
        
        for record_type in DNS_RECORD_TYPES:
            try:
                answers = resolver.resolve(domain, record_type)
                results[record_type] = [str(answer) for answer in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                results[record_type] = []
        
        return results
    
    def _check_ssl(self, domain):
        """Check SSL certificate information"""
        result = {
            "has_ssl": False,
            "issuer": None,
            "subject": None,
            "version": None,
            "serial_number": None,
            "not_before": None,
            "not_after": None,
            "expired": None,
            "signature_algorithm": None,
            "san": []
        }
        
        try:
            # Try to connect and get certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=self.args.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
                    
                    # Extract certificate information
                    result["has_ssl"] = True
                    result["issuer"] = ", ".join([f"{name[0].decode()}={name[1].decode()}" for name in x509.get_issuer().get_components()])
                    result["subject"] = ", ".join([f"{name[0].decode()}={name[1].decode()}" for name in x509.get_subject().get_components()])
                    result["version"] = x509.get_version()
                    result["serial_number"] = str(x509.get_serial_number())
                    result["not_before"] = x509.get_notBefore().decode()
                    result["not_after"] = x509.get_notAfter().decode()
                    result["expired"] = x509.has_expired()
                    result["signature_algorithm"] = x509.get_signature_algorithm().decode()
                    
                    # Get Subject Alternative Names (SAN)
                    for i in range(x509.get_extension_count()):
                        ext = x509.get_extension(i)
                        if ext.get_short_name().decode() == "subjectAltName":
                            san_data = ext.get_data()
                            san_text = OpenSSL.crypto.dump_extension(ext.get_short_name(), ext.get_data(), ext.get_critical())
                            san_list = str(san_text).split(",")
                            result["san"] = [s.strip() for s in san_list if s.strip()]
        except Exception as e:
            if self.args.verbose:
                print(f"{Fore.YELLOW}SSL check failed for {domain}: {str(e)}")
        
        return result
    
    def _scan_ports(self, domain):
        """Scan common ports on the domain"""
        results = {}
        
        # Get the first IPv4 address
        ip_addresses = self._resolve_ips(domain)
        if not ip_addresses["ipv4"]:
            return results
        
        ip = ip_addresses["ipv4"][0]
        
        # Scan each port
        for port in COMMON_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.args.port_timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    # Port is open
                    service = self._identify_service(sock, port)
                    results[port] = {
                        "status": "open",
                        "service": service
                    }
                sock.close()
            except:
                results[port] = {
                    "status": "error",
                    "service": "unknown"
                }
        
        return results
    
    def _identify_service(self, sock, port):
        """Try to identify the service running on a port"""
        common_services = {
            21: "FTP",
            22: "SSH",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt"
        }
        
        return common_services.get(port, "unknown")
    
    def _get_whois(self, domain):
        """Get WHOIS information for the domain"""
        try:
            w = whois.whois(domain)
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "last_updated": str(w.updated_date) if w.updated_date else None,
                "name_servers": w.name_servers if w.name_servers else [],
                "status": w.status if w.status else [],
                "emails": w.emails if w.emails else []
            }
        except Exception as e:
            if self.args.verbose:
                print(f"{Fore.YELLOW}WHOIS lookup failed for {domain}: {str(e)}")
            return {}
    
    def _detect_waf(self, domain):
        """Detect if the domain is protected by a WAF"""
        waf_signatures = {
            "Cloudflare": ["__cfduid", "cloudflare", "cloudflare-nginx"],
            "AWS WAF": ["x-amzn-waf", "aws-waf"],
            "Akamai": ["akamai"],
            "Imperva": ["incapsula", "imperva"],
            "F5 BIG-IP": ["big-ip", "f5"],
            "Sucuri": ["sucuri"],
            "Barracuda": ["barracuda"]
        }
        
        try:
            url = f"https://{domain}"
            response = self.session.get(url, timeout=self.args.timeout, verify=False)
            headers = str(response.headers).lower()
            
            for waf, signatures in waf_signatures.items():
                for signature in signatures:
                    if signature.lower() in headers:
                        return True
            
            # Try with a suspicious request
            suspicious_url = f"https://{domain}/wp-login.php?action=rpc"
            response = self.session.get(suspicious_url, timeout=self.args.timeout, verify=False)
            if response.status_code == 403 or response.status_code == 406:
                return True
                
        except:
            pass
            
        return False
    
    def _take_screenshot(self, domain):
        """Take a screenshot of the domain's website"""
        if not hasattr(self, "driver"):
            return None
            
        screenshot_path = os.path.join(self.args.output_dir, f"{domain}.png")
        
        try:
            # Navigate to the domain
            self.driver.get(f"https://{domain}")
            time.sleep(3)  # Wait for page to load
            
            # Take screenshot
            self.driver.save_screenshot(screenshot_path)
            
            # Resize image to save space
            with Image.open(screenshot_path) as img:
                img = img.resize((800, int(800 * img.height / img.width)))
                img.save(screenshot_path)
                
            return screenshot_path
        except Exception as e:
            if self.args.verbose:
                print(f"{Fore.YELLOW}Screenshot failed for {domain}: {str(e)}")
            return None
    
    def _save_results(self, results, alive_domains, dead_domains):
        """Save results to output files"""
        # Create output directory if it doesn't exist
        if not os.path.exists(self.args.output_dir):
            os.makedirs(self.args.output_dir)
            
        # Save all domains
        all_domains_file = os.path.join(self.args.output_dir, self.args.output_file)
        with open(all_domains_file, "w") as f:
            for result in results:
                domain = result["domain"]
                ip_list = ", ".join(result["ip_addresses"].get("ipv4", []))
                status = "Alive" if result["is_alive"] else "Dead"
                f.write(f"{domain} - {ip_list} [{status}]\n")
        
        # Save dead domains
        if dead_domains:
            dead_domains_file = os.path.join(self.args.output_dir, self.args.dead_file)
            with open(dead_domains_file, "w") as f:
                for result in dead_domains:
                    domain = result["domain"]
                    ip_list = ", ".join(result["ip_addresses"].get("ipv4", []))
                    f.write(f"{domain} - {ip_list} [Dead]\n")
        
        # Save JSON results if requested
        if self.args.json:
            json_file = os.path.join(self.args.output_dir, self.args.json_file)
            with open(json_file, "w") as f:
                json.dump(results, f, indent=4)
    
    def _generate_html_report(self, results, scan_duration):
        """Generate HTML report from results"""
        if HTMLReportGenerator is None:
            print(f"{Fore.YELLOW}Warning: HTML report generation is not available. Make sure html_report.py is in the same directory.")
            return
            
        try:
            report_path = os.path.join(self.args.output_dir, self.args.html_report_file)
            generator = HTMLReportGenerator(results, scan_duration, VERSION, AUTHOR)
            success = generator.generate_report(report_path)
            
            if success and not self.args.quiet:
                print(f"{Fore.GREEN}HTML report generated: {report_path}")
        except Exception as e:
            print(f"{Fore.RED}Error generating HTML report: {str(e)}")
            if self.args.verbose:
                import traceback
                traceback.print_exc()
    
    def _print_summary(self, results, alive_domains, dead_domains, duration):
        """Print a summary of the results"""
        # Count main domains and subdomains
        main_domains = [r for r in results if not r["is_subdomain"]]
        subdomains = [r for r in results if r["is_subdomain"]]
        
        print(f"\n{Fore.GREEN}✅ Scan Completed in {duration:.2f} seconds!")
        print(f"{Fore.CYAN}Total domains processed: {len(results)}")
        print(f"{Fore.CYAN}Main domains: {len(main_domains)}")
        print(f"{Fore.CYAN}Subdomains: {len(subdomains)}")
        
        if self.args.check_alive:
            print(f"{Fore.GREEN}Alive: {len(alive_domains)}")
            print(f"{Fore.RED}Dead: {len(dead_domains)}")
        
        # Print file paths
        output_dir = os.path.abspath(self.args.output_dir)
        print(f"\n{Fore.YELLOW}Results saved in: {output_dir}")
        print(f"{Fore.YELLOW}All domains saved in: {os.path.join(output_dir, self.args.output_file)}")
        
        if dead_domains:
            print(f"{Fore.YELLOW}Dead domains saved in: {os.path.join(output_dir, self.args.dead_file)}")
        
        if self.args.json:
            print(f"{Fore.YELLOW}JSON results saved in: {os.path.join(output_dir, self.args.json_file)}")
            
        if self.args.html_report:
            print(f"{Fore.YELLOW}HTML report saved in: {os.path.join(output_dir, self.args.html_report_file)}")
        
        # Print table of alive domains if verbose
        if self.args.verbose and alive_domains:
            print(f"\n{Fore.CYAN}Alive Domains Summary:")
            table_data = []
            for domain in alive_domains[:10]:  # Limit to 10 domains to avoid cluttering the console
                table_data.append([
                    domain["domain"],
                    ", ".join(domain["ip_addresses"].get("ipv4", []))[:20],
                    domain["response_code"],
                    domain["response_time"],
                    domain["server"] if domain.get("server") else "Unknown"
                ])
            
            headers = ["Domain", "IP", "Status", "Response Time", "Server"]
            print(tabulate(table_data, headers=headers, tablefmt="grid"))
            
            if len(alive_domains) > 10:
                print(f"...and {len(alive_domains) - 10} more domains")

def load_config(config_file):
    """Load configuration from a JSON file"""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"{Fore.YELLOW}Warning: Could not load config file: {str(e)}")
        return None

def apply_config_to_args(args, config):
    """Apply configuration settings to command line arguments"""
    if not config:
        return args
        
    # General settings
    if 'general' in config:
        if 'threads' in config['general'] and not args.threads_set:
            args.threads = config['general']['threads']
        if 'timeout' in config['general'] and not args.timeout_set:
            args.timeout = config['general']['timeout']
        if 'port_timeout' in config['general'] and not args.port_timeout_set:
            args.port_timeout = config['general']['port_timeout']
        if 'follow_redirects' in config['general'] and not args.follow_redirects_set:
            args.follow_redirects = config['general']['follow_redirects']
        if 'ignore_ssl_errors' in config['general'] and not args.ignore_ssl_errors_set:
            args.ignore_ssl_errors = config['general']['ignore_ssl_errors']
        if 'output_dir' in config['general'] and not args.output_dir_set:
            args.output_dir = config['general']['output_dir']
            
    # Analysis settings
    if 'analysis' in config:
        if 'check_alive' in config['analysis'] and not args.check_alive_set:
            args.check_alive = config['analysis']['check_alive']
        if 'dns' in config['analysis'] and not args.dns_set:
            args.dns = config['analysis']['dns']
        if 'ssl' in config['analysis'] and not args.ssl_set:
            args.ssl = config['analysis']['ssl']
        if 'ports' in config['analysis'] and not args.ports_set:
            args.ports = config['analysis']['ports']
        if 'whois' in config['analysis'] and not args.whois_set:
            args.whois = config['analysis']['whois']
        if 'waf' in config['analysis'] and not args.waf_set:
            args.waf = config['analysis']['waf']
        if 'screenshot' in config['analysis'] and not args.screenshot_set:
            args.screenshot = config['analysis']['screenshot']
            
    # Output settings
    if 'output' in config:
        if 'verbose' in config['output'] and not args.verbose_set:
            args.verbose = config['output']['verbose']
        if 'json' in config['output'] and not args.json_set:
            args.json = config['output']['json']
        if 'json_file' in config['output'] and not args.json_file_set:
            args.json_file = config['output']['json_file']
        if 'output_file' in config['output'] and not args.output_file_set:
            args.output_file = config['output']['output_file']
        if 'dead_file' in config['output'] and not args.dead_file_set:
            args.dead_file = config['output']['dead_file']
        if 'html_report' in config['output'] and not args.html_report_set:
            args.html_report = config['output']['html_report']
        if 'html_report_file' in config['output'] and not args.html_report_file_set:
            args.html_report_file = config['output']['html_report_file']
            
    # Proxy settings
    if 'proxy' in config and 'enabled' in config['proxy'] and config['proxy']['enabled'] and not args.proxy_set:
        args.proxy = config['proxy']['url']
        
    # Custom ports
    if 'ports' in config and 'common' in config['ports']:
        global COMMON_PORTS
        COMMON_PORTS = config['ports']['common']
        if 'custom' in config['ports'] and config['ports']['custom']:
            COMMON_PORTS.extend(config['ports']['custom'])
            
    # User agents
    if 'user_agents' in config and config['user_agents']:
        global USER_AGENTS
        USER_AGENTS = config['user_agents']
        
    return args

def setup_logging(args):
    """Set up logging based on verbosity level"""
    log_level = logging.WARNING
    if args.verbose:
        log_level = logging.INFO
    if args.debug:
        log_level = logging.DEBUG
        
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(args.output_dir, "domain_splitter.log")),
            logging.StreamHandler()
        ]
    )
    
    # Suppress verbose logging from libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("selenium").setLevel(logging.WARNING)
    
    return logging.getLogger("domain_splitter")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description=f"Domain Splitter Advanced v{VERSION} - A comprehensive domain analysis tool")
    
    # Input/output options
    parser.add_argument("input_file", help="Input file with domains (one per line)")
    parser.add_argument("-o", "--output-file", default="all_domains.txt", help="File to save all domains")
    parser.add_argument("-d", "--dead-file", default="dead_domains.txt", help="File to save only dead domains")
    parser.add_argument("--output-dir", default="results", help="Directory to save all output files")
    parser.add_argument("--json", action="store_true", help="Save results in JSON format")
    parser.add_argument("--json-file", default="results.json", help="JSON output filename")
    parser.add_argument("--html-report", action="store_true", help="Generate HTML report")
    parser.add_argument("--html-report-file", default="report.html", help="HTML report filename")
    
    # Analysis options
    parser.add_argument("-a", "--check-alive", action="store_true", help="Check if domains are alive")
    parser.add_argument("--dns", action="store_true", help="Get DNS records")
    parser.add_argument("--ssl", action="store_true", help="Check SSL certificate")
    parser.add_argument("--ports", action="store_true", help="Scan common ports")
    parser.add_argument("--whois", action="store_true", help="Get WHOIS information")
    parser.add_argument("--waf", action="store_true", help="Detect WAF protection")
    parser.add_argument("--screenshot", action="store_true", help="Take screenshots of alive domains")
    parser.add_argument("--all", action="store_true", help="Enable all analysis options")
    
    # Performance options
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout for HTTP requests in seconds")
    parser.add_argument("--port-timeout", type=float, default=2.0, help="Timeout for port scanning in seconds")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow HTTP redirects")
    parser.add_argument("--ignore-ssl-errors", action="store_true", help="Ignore SSL certificate errors")
    
    # Proxy options
    parser.add_argument("--proxy", help="Use proxy (format: http://user:pass@host:port)")
    
    # Output options
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (no output except errors)")
    parser.add_argument("--debug", action="store_true", help="Debug mode (very verbose)")
    
    # Config options
    parser.add_argument("-c", "--config", help="Path to configuration file")
    
    # Export options
    parser.add_argument("--export-config", help="Export current settings to a config file")
    
    args = parser.parse_args()
    
    # Track which arguments were explicitly set on the command line
    args.threads_set = 'threads' in sys.argv
    args.timeout_set = 'timeout' in sys.argv
    args.port_timeout_set = 'port_timeout' in sys.argv
    args.follow_redirects_set = 'follow_redirects' in sys.argv
    args.ignore_ssl_errors_set = 'ignore_ssl_errors' in sys.argv
    args.output_dir_set = 'output_dir' in sys.argv
    args.check_alive_set = 'check_alive' in sys.argv
    args.dns_set = 'dns' in sys.argv
    args.ssl_set = 'ssl' in sys.argv
    args.ports_set = 'ports' in sys.argv
    args.whois_set = 'whois' in sys.argv
    args.waf_set = 'waf' in sys.argv
    args.screenshot_set = 'screenshot' in sys.argv
    args.verbose_set = 'verbose' in sys.argv
    args.json_set = 'json' in sys.argv
    args.json_file_set = 'json_file' in sys.argv
    args.output_file_set = 'output_file' in sys.argv
    args.dead_file_set = 'dead_file' in sys.argv
    args.proxy_set = 'proxy' in sys.argv
    args.html_report_set = 'html_report' in sys.argv
    args.html_report_file_set = 'html_report_file' in sys.argv
    
    # If --all is specified, enable all analysis options
    if args.all:
        args.check_alive = True
        args.dns = True
        args.ssl = True
        args.ports = True
        args.whois = True
        args.waf = True
        args.screenshot = True
    
    # Load configuration if specified
    config = None
    if args.config:
        config = load_config(args.config)
        args = apply_config_to_args(args, config)
    elif os.path.exists('config.json'):
        # Load default config if it exists and no config specified
        config = load_config('config.json')
        args = apply_config_to_args(args, config)
    
    # Create output directory if it doesn't exist
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
    
    # Set up logging
    logger = setup_logging(args)
    
    # Export configuration if requested
    if args.export_config:
        export_config = {
            "general": {
                "threads": args.threads,
                "timeout": args.timeout,
                "port_timeout": args.port_timeout,
                "follow_redirects": args.follow_redirects,
                "ignore_ssl_errors": args.ignore_ssl_errors,
                "output_dir": args.output_dir
            },
            "analysis": {
                "check_alive": args.check_alive,
                "dns": args.dns,
                "ssl": args.ssl,
                "ports": args.ports,
                "whois": args.whois,
                "waf": args.waf,
                "screenshot": args.screenshot
            },
            "output": {
                "verbose": args.verbose,
                "json": args.json,
                "json_file": args.json_file,
                "output_file": args.output_file,
                "dead_file": args.dead_file,
                "html_report": args.html_report,
                "html_report_file": args.html_report_file
            },
            "proxy": {
                "enabled": bool(args.proxy),
                "url": args.proxy if args.proxy else "",
                "rotate": False,
                "proxy_list": []
            },
            "ports": {
                "common": COMMON_PORTS,
                "custom": []
            },
            "user_agents": USER_AGENTS
        }
        
        with open(args.export_config, 'w') as f:
            json.dump(export_config, f, indent=2)
            
        if not args.quiet:
            print(f"{Fore.GREEN}Configuration exported to {args.export_config}")
            
        return 0
    
    # Print banner unless quiet mode is enabled
    if not args.quiet:
        print(BANNER)
    
    try:
        # Read domains from input file
        with open(args.input_file, "r") as f:
            domains = [line.strip() for line in f if line.strip()]
        
        if not domains:
            print(f"{Fore.RED}❌ No domains found in input file: {args.input_file}")
            return 1
        
        # Create analyzer and run analysis
        analyzer = DomainAnalyzer(args)
        analyzer.analyze_domains(domains)
        
        return 0
        
    except FileNotFoundError:
        print(f"{Fore.RED}❌ File not found: {args.input_file}")
        return 1
    except Exception as e:
        print(f"{Fore.RED}❌ Error: {str(e)}")
        if args.verbose or args.debug:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
