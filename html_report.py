#!/usr/bin/env python3
"""
HTML Report Generator for Domain Splitter Advanced
"""
import os
import json
import base64
from datetime import datetime

class HTMLReportGenerator:
    """Generate HTML reports from domain analysis results"""
    
    def __init__(self, results, scan_duration, version, author):
        """Initialize with analysis results"""
        self.results = results
        self.scan_duration = scan_duration
        self.version = version
        self.author = author
        self.template_path = "report_template.html"
        
    def generate_report(self, output_path):
        """Generate HTML report and save to output_path"""
        # Load template
        try:
            with open(self.template_path, 'r') as f:
                template = f.read()
        except FileNotFoundError:
            print("Error: Report template not found")
            return False
            
        # Calculate summary statistics
        total_domains = len(self.results)
        main_domains = sum(1 for r in self.results if not r.get('is_subdomain', False))
        subdomains = total_domains - main_domains
        alive_domains = sum(1 for r in self.results if r.get('is_alive', False))
        dead_domains = total_domains - alive_domains
        ssl_domains = sum(1 for r in self.results if r.get('ssl_info', {}).get('has_ssl', False))
        waf_domains = sum(1 for r in self.results if r.get('waf_detected', False))
        
        # Generate domain cards
        domain_cards = ""
        for result in self.results:
            domain_cards += self._generate_domain_card(result)
            
        # Replace template placeholders
        template = template.replace('{{timestamp}}', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        template = template.replace('{{total_domains}}', str(total_domains))
        template = template.replace('{{main_domains}}', str(main_domains))
        template = template.replace('{{subdomains}}', str(subdomains))
        template = template.replace('{{alive_domains}}', str(alive_domains))
        template = template.replace('{{dead_domains}}', str(dead_domains))
        template = template.replace('{{ssl_domains}}', str(ssl_domains))
        template = template.replace('{{waf_domains}}', str(waf_domains))
        template = template.replace('{{scan_duration}}', f"{self.scan_duration:.2f}")
        template = template.replace('{{domain_cards}}', domain_cards)
        template = template.replace('{{version}}', self.version)
        template = template.replace('{{year}}', str(datetime.now().year))
        template = template.replace('{{author}}', self.author)
        
        # Write output file
        try:
            with open(output_path, 'w') as f:
                f.write(template)
            return True
        except Exception as e:
            print(f"Error saving HTML report: {str(e)}")
            return False
            
    def _generate_domain_card(self, result):
        """Generate HTML for a single domain card"""
        domain = result.get('domain', 'Unknown')
        is_alive = result.get('is_alive', False)
        status_class = "status-alive" if is_alive else "status-dead"
        status_text = "Alive" if is_alive else "Dead"
        
        # Basic information
        ip_addresses = result.get('ip_addresses', {})
        ipv4_list = ip_addresses.get('ipv4', [])
        ipv6_list = ip_addresses.get('ipv6', [])
        
        # HTTP information
        response_code = result.get('response_code', 'N/A')
        response_time = result.get('response_time', 'N/A')
        if response_time != 'N/A':
            response_time = f"{response_time:.3f}s"
        server = result.get('server', 'Unknown')
        content_type = result.get('content_type', 'Unknown')
        
        # Create the card HTML
        card = f"""
        <div class="domain-card">
            <div class="domain-header">
                <span class="domain-name">{domain}</span>
                <span class="domain-status {status_class}">{status_text}</span>
            </div>
            <div class="domain-body">
                <div class="domain-details">
                    <div class="detail-section">
                        <h4>Basic Information</h4>
                        <table>
                            <tr>
                                <th>Domain</th>
                                <td>{domain}</td>
                            </tr>
                            <tr>
                                <th>Type</th>
                                <td>{"Subdomain" if result.get('is_subdomain', False) else "Main Domain"}</td>
                            </tr>
                            <tr>
                                <th>IPv4 Addresses</th>
                                <td>{', '.join(ipv4_list) if ipv4_list else 'None'}</td>
                            </tr>
                            <tr>
                                <th>IPv6 Addresses</th>
                                <td>{', '.join(ipv6_list) if ipv6_list else 'None'}</td>
                            </tr>
                        </table>
                    </div>
        """
        
        # Add HTTP information if domain is alive
        if is_alive:
            card += f"""
                    <div class="detail-section">
                        <h4>HTTP Information</h4>
                        <table>
                            <tr>
                                <th>Response Code</th>
                                <td>{response_code}</td>
                            </tr>
                            <tr>
                                <th>Response Time</th>
                                <td>{response_time}</td>
                            </tr>
                            <tr>
                                <th>Server</th>
                                <td>{server}</td>
                            </tr>
                            <tr>
                                <th>Content Type</th>
                                <td>{content_type}</td>
                            </tr>
                        </table>
                    </div>
            """
            
            # Add redirect information if available
            redirect_url = result.get('redirect_url')
            if redirect_url:
                card += f"""
                    <div class="detail-section">
                        <h4>Redirect</h4>
                        <table>
                            <tr>
                                <th>Redirects To</th>
                                <td>{redirect_url}</td>
                            </tr>
                        </table>
                    </div>
                """
        
        # Add DNS records if available
        dns_records = result.get('dns_records', {})
        if dns_records:
            card += f"""
                    <div class="detail-section">
                        <h4 class="collapsible">DNS Records</h4>
                        <div class="content">
                            <table>
            """
            
            for record_type, records in dns_records.items():
                if records:
                    card += f"""
                                <tr>
                                    <th>{record_type}</th>
                                    <td>{', '.join(records)}</td>
                                </tr>
                    """
            
            card += """
                            </table>
                        </div>
                    </div>
            """
        
        # Add SSL information if available
        ssl_info = result.get('ssl_info', {})
        if ssl_info and ssl_info.get('has_ssl', False):
            expired = ssl_info.get('expired', False)
            ssl_class = "ssl-expired" if expired else "ssl-valid"
            
            card += f"""
                    <div class="detail-section">
                        <h4 class="collapsible">SSL Certificate</h4>
                        <div class="content">
                            <table>
                                <tr>
                                    <th>Status</th>
                                    <td class="{ssl_class}">{"Expired" if expired else "Valid"}</td>
                                </tr>
                                <tr>
                                    <th>Issuer</th>
                                    <td>{ssl_info.get('issuer', 'Unknown')}</td>
                                </tr>
                                <tr>
                                    <th>Subject</th>
                                    <td>{ssl_info.get('subject', 'Unknown')}</td>
                                </tr>
                                <tr>
                                    <th>Valid From</th>
                                    <td>{ssl_info.get('not_before', 'Unknown')}</td>
                                </tr>
                                <tr>
                                    <th>Valid Until</th>
                                    <td>{ssl_info.get('not_after', 'Unknown')}</td>
                                </tr>
                                <tr>
                                    <th>Signature Algorithm</th>
                                    <td>{ssl_info.get('signature_algorithm', 'Unknown')}</td>
                                </tr>
            """
            
            # Add Subject Alternative Names if available
            san = ssl_info.get('san', [])
            if san:
                card += f"""
                                <tr>
                                    <th>Alternative Names</th>
                                    <td>
                """
                
                for name in san:
                    card += f'<span class="badge badge-info">{name}</span> '
                
                card += """
                                    </td>
                                </tr>
                """
            
            card += """
                            </table>
                        </div>
                    </div>
            """
        
        # Add port information if available
        ports = result.get('ports', {})
        if ports:
            card += f"""
                    <div class="detail-section">
                        <h4 class="collapsible">Port Scan</h4>
                        <div class="content">
                            <table>
                                <tr>
                                    <th>Port</th>
                                    <th>Status</th>
                                    <th>Service</th>
                                </tr>
            """
            
            for port, port_info in ports.items():
                status = port_info.get('status', 'unknown')
                service = port_info.get('service', 'unknown')
                status_class = "port-open" if status == "open" else "port-closed"
                
                card += f"""
                                <tr>
                                    <td>{port}</td>
                                    <td class="{status_class}">{status}</td>
                                    <td>{service}</td>
                                </tr>
                """
            
            card += """
                            </table>
                        </div>
                    </div>
            """
        
        # Add WHOIS information if available
        whois_info = result.get('whois', {})
        if whois_info:
            card += f"""
                    <div class="detail-section">
                        <h4 class="collapsible">WHOIS Information</h4>
                        <div class="content">
                            <table>
            """
            
            if whois_info.get('registrar'):
                card += f"""
                                <tr>
                                    <th>Registrar</th>
                                    <td>{whois_info.get('registrar')}</td>
                                </tr>
                """
                
            if whois_info.get('creation_date'):
                card += f"""
                                <tr>
                                    <th>Creation Date</th>
                                    <td>{whois_info.get('creation_date')}</td>
                                </tr>
                """
                
            if whois_info.get('expiration_date'):
                card += f"""
                                <tr>
                                    <th>Expiration Date</th>
                                    <td>{whois_info.get('expiration_date')}</td>
                                </tr>
                """
                
            if whois_info.get('last_updated'):
                card += f"""
                                <tr>
                                    <th>Last Updated</th>
                                    <td>{whois_info.get('last_updated')}</td>
                                </tr>
                """
                
            if whois_info.get('name_servers'):
                card += f"""
                                <tr>
                                    <th>Name Servers</th>
                                    <td>{', '.join(whois_info.get('name_servers'))}</td>
                                </tr>
                """
                
            card += """
                            </table>
                        </div>
                    </div>
            """
        
        # Add WAF information if available
        if 'waf_detected' in result:
            waf_status = "Detected" if result['waf_detected'] else "Not Detected"
            waf_class = "badge-danger" if result['waf_detected'] else "badge-success"
            
            card += f"""
                    <div class="detail-section">
                        <h4>WAF Protection</h4>
                        <span class="badge {waf_class}">{waf_status}</span>
                    </div>
            """
        
        # Add screenshot if available
        screenshot = result.get('screenshot')
        if screenshot and os.path.exists(screenshot):
            card += f"""
                    <div class="detail-section">
                        <h4>Screenshot</h4>
                        <img src="{screenshot}" alt="Screenshot of {domain}" class="screenshot">
                    </div>
            """
        
        # Close the card
        card += """
                </div>
            </div>
        </div>
        """
        
        return card