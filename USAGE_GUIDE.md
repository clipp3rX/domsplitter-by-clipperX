# Domain Splitter Advanced - Usage Guide

This guide provides detailed instructions on how to use Domain Splitter Advanced effectively, including examples for common use cases and explanations of advanced features.

## Table of Contents

1. [Basic Usage](#basic-usage)
2. [Analysis Options](#analysis-options)
3. [Output Options](#output-options)
4. [Performance Tuning](#performance-tuning)
5. [Proxy Configuration](#proxy-configuration)
6. [Configuration Files](#configuration-files)
7. [HTML Reports](#html-reports)
8. [Common Use Cases](#common-use-cases)
9. [Troubleshooting](#troubleshooting)

## Basic Usage

The most basic way to use Domain Splitter Advanced is to provide a file containing a list of domains (one per line):

```bash
python domain_splitter_advanced.py domains.txt
```

This will perform a basic analysis without checking if domains are alive or performing additional checks.

## Analysis Options

Domain Splitter Advanced offers several analysis options:

### Check if Domains are Alive

```bash
python domain_splitter_advanced.py domains.txt -a
```

This checks if domains respond to HTTP/HTTPS requests.

### DNS Record Analysis

```bash
python domain_splitter_advanced.py domains.txt --dns
```

This retrieves various DNS records (A, AAAA, MX, TXT, NS, SOA, CNAME) for each domain.

### SSL Certificate Analysis

```bash
python domain_splitter_advanced.py domains.txt --ssl
```

This checks SSL certificates and extracts information such as issuer, expiration date, and more.

### Port Scanning

```bash
python domain_splitter_advanced.py domains.txt --ports
```

This scans common ports to check if they are open and identifies running services.

### WHOIS Information

```bash
python domain_splitter_advanced.py domains.txt --whois
```

This retrieves domain registration and ownership details.

### WAF Detection

```bash
python domain_splitter_advanced.py domains.txt --waf
```

This checks if domains are protected by Web Application Firewalls.

### Screenshot Capture

```bash
python domain_splitter_advanced.py domains.txt --screenshot
```

This captures screenshots of alive domains.

### Full Analysis

```bash
python domain_splitter_advanced.py domains.txt --all
```

This enables all analysis options for comprehensive domain analysis.

## Output Options

### Custom Output Directory

```bash
python domain_splitter_advanced.py domains.txt --output-dir results_folder
```

This saves all output files to the specified directory.

### Custom Output Filenames

```bash
python domain_splitter_advanced.py domains.txt -o all.txt -d dead.txt
```

This specifies custom filenames for all domains and dead domains.

### JSON Output

```bash
python domain_splitter_advanced.py domains.txt --json
```

This saves results in JSON format for further processing.

### Custom JSON Filename

```bash
python domain_splitter_advanced.py domains.txt --json --json-file output.json
```

This specifies a custom filename for JSON output.

### HTML Report

```bash
python domain_splitter_advanced.py domains.txt --html-report
```

This generates an interactive HTML report with detailed analysis results.

### Custom HTML Report Filename

```bash
python domain_splitter_advanced.py domains.txt --html-report --html-report-file analysis.html
```

This specifies a custom filename for the HTML report.

### Verbose Output

```bash
python domain_splitter_advanced.py domains.txt -v
```

This enables verbose output with more detailed information.

### Quiet Mode

```bash
python domain_splitter_advanced.py domains.txt -q
```

This runs in quiet mode with minimal output (useful for scripts).

### Debug Mode

```bash
python domain_splitter_advanced.py domains.txt --debug
```

This enables debug mode with very verbose output for troubleshooting.

## Performance Tuning

### Concurrent Threads

```bash
python domain_splitter_advanced.py domains.txt --all -t 20
```

This increases the number of concurrent threads for faster processing (default is 10).

### Timeout Settings

```bash
python domain_splitter_advanced.py domains.txt --all --timeout 3 --port-timeout 1
```

This sets custom timeout values for HTTP requests and port scanning.

### Follow Redirects

```bash
python domain_splitter_advanced.py domains.txt --all --follow-redirects
```

This follows HTTP redirects when checking if domains are alive.

### Ignore SSL Errors

```bash
python domain_splitter_advanced.py domains.txt --all --ignore-ssl-errors
```

This ignores SSL certificate errors when checking if domains are alive.

## Proxy Configuration

### Using a Proxy

```bash
python domain_splitter_advanced.py domains.txt --all --proxy http://user:pass@host:port
```

This routes all requests through the specified proxy.

## Configuration Files

### Using a Configuration File

```bash
python domain_splitter_advanced.py domains.txt -c config.json
```

This loads settings from the specified configuration file.

### Exporting Configuration

```bash
python domain_splitter_advanced.py domains.txt --export-config my_config.json
```

This exports current settings to a configuration file for future use.

## HTML Reports

The HTML report feature generates an interactive web page with detailed analysis results. The report includes:

- Summary statistics (total domains, alive/dead domains, etc.)
- Detailed information for each domain
- DNS records
- SSL certificate information
- Port scan results
- WHOIS information
- Screenshots (if enabled)

To generate an HTML report:

```bash
python domain_splitter_advanced.py domains.txt --all --html-report
```

The report will be saved in the output directory as `report.html` by default.

## Common Use Cases

### Basic Domain Health Check

```bash
python domain_splitter_advanced.py domains.txt -a
```

This quickly checks if domains are alive without performing additional analysis.

### Security Assessment

```bash
python domain_splitter_advanced.py domains.txt --ssl --waf --ports
```

This checks SSL certificates, WAF protection, and open ports for security assessment.

### Domain Portfolio Management

```bash
python domain_splitter_advanced.py domains.txt --all --html-report
```

This performs comprehensive analysis and generates an HTML report for domain portfolio management.

### Competitive Analysis

```bash
python domain_splitter_advanced.py competitor_domains.txt --all --json
```

This performs comprehensive analysis and saves results in JSON format for further processing.

### CI/CD Integration

```bash
python domain_splitter_advanced.py domains.txt -a -q --json --output-dir /path/to/results
```

This runs in quiet mode and saves results in JSON format for CI/CD integration.

## Troubleshooting

### SSL Certificate Errors

If you encounter SSL certificate errors, try using the `--ignore-ssl-errors` option:

```bash
python domain_splitter_advanced.py domains.txt --all --ignore-ssl-errors
```

### Timeout Errors

If you encounter timeout errors, try increasing the timeout values:

```bash
python domain_splitter_advanced.py domains.txt --all --timeout 10 --port-timeout 5
```

### Memory Issues

If you encounter memory issues with large domain lists, try reducing the number of concurrent threads:

```bash
python domain_splitter_advanced.py domains.txt --all -t 5
```

### Screenshot Issues

If screenshot capture fails, make sure you have Chrome or Chromium installed and try running with the `--debug` option to see detailed error messages:

```bash
python domain_splitter_advanced.py domains.txt --screenshot --debug
```

### Proxy Issues

If you encounter issues with proxy configuration, make sure the proxy URL is correctly formatted:

```bash
python domain_splitter_advanced.py domains.txt --all --proxy http://user:pass@host:port
```

If you still encounter issues, try running with the `--debug` option to see detailed error messages.