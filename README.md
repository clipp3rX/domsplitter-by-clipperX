# domsplitter by clipperX

![Version](https://img.shields.io/badge/version-2.0-blue)
![Python](https://img.shields.io/badge/python-3.6%2B-green)
![License](https://img.shields.io/badge/license-MIT-orange)

A comprehensive domain analysis tool for security researchers, penetration testers, and system administrators.

## Features

Domain Splitter Advanced is a powerful domain analysis tool that provides:

- **Concurrent Domain Processing**: Analyze multiple domains simultaneously for faster results
- **Advanced Domain Validation**: Robust domain validation and categorization
- **HTTP/HTTPS Support**: Check domain availability over both protocols
- **DNS Record Analysis**: Retrieve and analyze various DNS record types (A, AAAA, MX, TXT, NS, SOA, CNAME)
- **Port Scanning**: Check for open ports and identify running services
- **Subdomain Detection**: Identify and categorize subdomains
- **WHOIS Information**: Retrieve domain registration and ownership details
- **SSL Certificate Analysis**: Validate SSL certificates and extract information
- **WAF Detection**: Identify if domains are protected by Web Application Firewalls
- **Screenshot Capability**: Capture visual representation of alive domains
- **Proxy Support**: Route requests through proxies for anonymity
- **User-Agent Rotation**: Avoid detection by rotating user agents
- **Detailed Reporting**: Generate comprehensive reports in multiple formats

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/domain-splitter-advanced.git
cd domain-splitter-advanced

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python domain_splitter_advanced.py domains.txt
```

### Check if Domains are Alive

```bash
python domain_splitter_advanced.py domains.txt -a
```

### Full Analysis

```bash
python domain_splitter_advanced.py domains.txt --all
```

### Custom Output Directory

```bash
python domain_splitter_advanced.py domains.txt --all --output-dir results_folder
```

### Performance Tuning

```bash
python domain_splitter_advanced.py domains.txt --all -t 20 --timeout 3
```

### Using a Proxy

```bash
python domain_splitter_advanced.py domains.txt --all --proxy http://user:pass@host:port
```

## Command Line Options

### Input/Output Options
- `input_file`: Input file with domains (one per line)
- `-o, --output-file`: File to save all domains (default: all_domains.txt)
- `-d, --dead-file`: File to save only dead domains (default: dead_domains.txt)
- `--output-dir`: Directory to save all output files (default: results)
- `--json`: Save results in JSON format
- `--json-file`: JSON output filename (default: results.json)

### Analysis Options
- `-a, --check-alive`: Check if domains are alive
- `--dns`: Get DNS records
- `--ssl`: Check SSL certificate
- `--ports`: Scan common ports
- `--whois`: Get WHOIS information
- `--waf`: Detect WAF protection
- `--screenshot`: Take screenshots of alive domains
- `--all`: Enable all analysis options

### Performance Options
- `-t, --threads`: Number of concurrent threads (default: 10)
- `--timeout`: Timeout for HTTP requests in seconds (default: 5.0)
- `--port-timeout`: Timeout for port scanning in seconds (default: 2.0)
- `--follow-redirects`: Follow HTTP redirects
- `--ignore-ssl-errors`: Ignore SSL certificate errors

### Proxy Options
- `--proxy`: Use proxy (format: http://user:pass@host:port)

### Output Options
- `-v, --verbose`: Enable verbose output
- `-q, --quiet`: Quiet mode (no output except errors)

## Output Example

When running with verbose output, you'll see a detailed summary like:

```
✅ Scan Completed in 15.23 seconds!
Total domains processed: 50
Main domains: 35
Subdomains: 15
Alive: 42
Dead: 8

Results saved in: /path/to/results
All domains saved in: /path/to/results/all_domains.txt
Dead domains saved in: /path/to/results/dead_domains.txt
JSON results saved in: /path/to/results/results.json

Alive Domains Summary:
+--------------------+--------------------+--------+---------------+------------+
| Domain             | IP                 | Status | Response Time | Server     |
+====================+====================+========+===============+============+
| example.com        | 93.184.216.34      | 200    | 0.345         | ECS        |
+--------------------+--------------------+--------+---------------+------------+
| google.com         | 142.250.185.78     | 200    | 0.123         | gws        |
+--------------------+--------------------+--------+---------------+------------+
...
```

## JSON Output Structure

When using the `--json` option, the tool generates a detailed JSON file with the following structure:

```json
[
  {
    "domain": "example.com",
    "timestamp": "2023-07-15T14:23:45.123456",
    "is_subdomain": false,
    "ip_addresses": {
      "ipv4": ["93.184.216.34"],
      "ipv6": ["2606:2800:220:1:248:1893:25c8:1946"]
    },
    "is_alive": true,
    "response_code": 200,
    "response_time": 0.345,
    "http_headers": {
      "Server": "ECS",
      "Content-Type": "text/html; charset=UTF-8",
      ...
    },
    "dns_records": {
      "A": ["93.184.216.34"],
      "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
      "MX": ["0 example.com.s1a1.psmtp.com.", "10 example.com.s1a2.psmtp.com."],
      ...
    },
    "ssl_info": {
      "has_ssl": true,
      "issuer": "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1",
      "subject": "C=US, ST=California, L=Los Angeles, O=Example Inc, CN=example.com",
      ...
    },
    "ports": {
      "80": {"status": "open", "service": "HTTP"},
      "443": {"status": "open", "service": "HTTPS"},
      ...
    },
    "whois": {
      "registrar": "ICANN",
      "creation_date": "1995-08-14 04:00:00",
      "expiration_date": "2023-08-13 04:00:00",
      ...
    },
    "waf_detected": false,
    "screenshot": "results/example.com.png"
  },
  ...
]
```

## Use Cases

- **Security Research**: Identify potential security issues in domains
- **Penetration Testing**: Gather intelligence about target domains
- **Domain Portfolio Management**: Monitor and manage multiple domains
- **Competitive Analysis**: Research competitor web infrastructure
- **IT Infrastructure Auditing**: Audit domain configurations and security

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Original Domain Splitter tool
- Python community for excellent networking libraries
- Open source security tools that inspired this project
