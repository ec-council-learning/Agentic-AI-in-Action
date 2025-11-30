"""
Generate Sample Log Files for ReAct Agent Demo
Creates all required JSON log files in the logs/ directory
"""

import json
import os


def create_logs_directory():
    """Create logs directory"""
    os.makedirs('logs', exist_ok=True)
    print("✅ Created/verified 'logs' directory")


def generate_all_logs():
    """Generate all log files"""
    
    logs = {
        "logs/nmap_quick_scan.json": {
            "target": "172.28.0.10",
            "scan_type": "quick",
            "timestamp": "2025-10-24T10:30:00",
            "open_ports": [
                {"port": "80", "service": "http", "state": "open"},
                {"port": "3306", "service": "mysql", "state": "open"}
            ],
            "total_ports_scanned": 1000,
            "scan_duration": "12.5 seconds"
        },
        
        "logs/nmap_service_scan.json": {
            "target": "172.28.0.10",
            "scan_type": "service",
            "timestamp": "2025-10-24T10:35:00",
            "open_ports": [
                {
                    "port": "80",
                    "service": "http",
                    "version": "Apache httpd 2.4.25 (Debian)",
                    "state": "open"
                },
                {
                    "port": "3306",
                    "service": "mysql",
                    "version": "MySQL 5.7.31",
                    "state": "open"
                }
            ],
            "security_notes": [
                "Apache 2.4.25 has known CVEs",
                "MySQL exposed on default port without firewall",
                "No HTTPS detected on port 443"
            ],
            "scan_duration": "45.2 seconds"
        },
        
        "logs/osint_data.json": {
            "localhost": {
                "target": "localhost",
                "timestamp": "2025-10-24T10:25:00",
                "dns_records": {
                    "A": ["127.0.0.1"],
                    "MX": [],
                    "NS": [],
                    "TXT": []
                },
                "http_info": {
                    "server": "Apache/2.4.25 (Debian)",
                    "status_code": 200,
                    "x_powered_by": "PHP/7.0.33",
                    "title": "Damn Vulnerable Web Application (DVWA)",
                    "content_type": "text/html; charset=utf-8"
                },
                "technologies": {
                    "Web Server": "Apache 2.4.25",
                    "Programming Language": "PHP 7.0.33",
                    "Database": "MySQL 5.7.31",
                    "Operating System": "Debian Linux"
                },
                "security_headers": {
                    "X-Frame-Options": "missing",
                    "Content-Security-Policy": "missing",
                    "Strict-Transport-Security": "missing"
                }
            },
            "default": {
                "target": "example.com",
                "dns_records": {
                    "A": ["192.168.1.100"],
                    "MX": ["mail.example.com"]
                },
                "http_info": {
                    "server": "nginx/1.18.0",
                    "status_code": 200
                },
                "technologies": {
                    "Web Server": "Nginx 1.18.0"
                }
            }
        },
        
        "logs/vulnerability_scan.json": {
            "target": "172.28.0.10",
            "scan_date": "2025-10-24T10:40:00",
            "vulnerabilities": [
                {
                    "severity": "CRITICAL",
                    "title": "End-of-Life PHP Version",
                    "service": "PHP 7.0.33",
                    "description": "PHP 7.0 reached end-of-life. No security patches available.",
                    "recommendation": "Upgrade to PHP 8.1 or later"
                },
                {
                    "severity": "HIGH",
                    "title": "Apache Known Vulnerabilities",
                    "service": "Apache 2.4.25",
                    "description": "Multiple CVEs exist including remote code execution.",
                    "recommendation": "Upgrade to Apache 2.4.57 or later"
                },
                {
                    "severity": "MEDIUM",
                    "title": "MySQL Service Exposed",
                    "service": "MySQL 5.7.31",
                    "description": "Database accessible from external network.",
                    "recommendation": "Implement firewall rules"
                }
            ],
            "total_vulnerabilities": 3,
            "risk_score": 8.5
        },
        
        "logs/port_summary.json": {
            "target": "172.28.0.10",
            "scan_date": "2025-10-24",
            "total_scans": 3,
            "total_open_ports": 2,
            "total_services": 2,
            "scan_types_performed": ["quick_scan", "service_detection", "vulnerability_assessment"],
            "notable_findings": [
                "2 services identified: HTTP and MySQL",
                "Both services on default ports",
                "Multiple critical vulnerabilities detected"
            ],
            "summary": {
                "web_services": 1,
                "database_services": 1,
                "ssh_services": 0
            }
        }
    }
    
    print("\n📝 Generating log files...\n")
    
    for filepath, data in logs.items():
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"✅ {filepath}")
    
    print(f"\n✅ Generated {len(logs)} log files")
    print("\n🚀 Ready! Run: python recon_agent.py\n")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  Sample Log File Generator")
    print("=" * 60 + "\n")
    
    create_logs_directory()
    generate_all_logs()