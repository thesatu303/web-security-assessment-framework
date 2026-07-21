#!/usr/bin/env python3
import argparse
import sys
import logging
from pathlib import Path
import yaml
from datetime import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from scanner import WebScanner
from sql_injection import SQLInjectionTester
from xss_injection import XSSInjectionTester
from csrf_detector import CSRFDetector
from auth_bypass import AuthBypassTester
from api_tester import APISecurityTester
from report_generator import ReportGenerator
from utils import setup_logging, validate_url

class SecurityAssessmentFramework:
    def __init__(self, config_file=None):
        self.config = self.load_config(config_file)
        self.logger = setup_logging()
        self.findings = {
            'reconnaissance': [],
            'sql_injection': [],
            'xss': [],
            'csrf': [],
            'auth_bypass': [],
            'api_vulnerabilities': [],
        }
        self.start_time = datetime.now()
    
    @staticmethod
    def load_config(config_file):
        if config_file and Path(config_file).exists():
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        return {'threads': 10, 'timeout': 10, 'verbose': False}
    
    def run_reconnaissance(self, target):
        self.logger.info(f"[*] Starting reconnaissance on {target}")
        scanner = WebScanner(target, self.config)
        findings = scanner.scan()
        self.findings['reconnaissance'] = findings
        self.logger.info(f"[+] Reconnaissance complete!")
        return findings
    
    def run_sql_injection_tests(self, target):
        self.logger.info(f"[*] Testing SQL Injection (200+ payloads)")
        sqli_tester = SQLInjectionTester(target, self.config)
        findings = sqli_tester.test_all()
        self.findings['sql_injection'] = findings
        self.logger.info(f"[+] SQL Injection: {len(findings)} vulnerabilities")
        return findings
    
    def run_xss_tests(self, target):
        self.logger.info(f"[*] Testing XSS (50+ payloads)")
        xss_tester = XSSInjectionTester(target, self.config)
        findings = xss_tester.test_all()
        self.findings['xss'] = findings
        self.logger.info(f"[+] XSS: {len(findings)} vulnerabilities")
        return findings
    
    def run_csrf_tests(self, target):
        self.logger.info(f"[*] Testing CSRF (50+ payloads)")
        csrf_tester = CSRFDetector(target, self.config)
        findings = csrf_tester.test_all()
        self.findings['csrf'] = findings
        self.logger.info(f"[+] CSRF: {len(findings)} vulnerabilities")
        return findings
    
    def run_auth_bypass_tests(self, target):
        self.logger.info(f"[*] Testing Authentication Bypass (50+ payloads)")
        auth_tester = AuthBypassTester(target, self.config)
        findings = auth_tester.test_all()
        self.findings['auth_bypass'] = findings
        self.logger.info(f"[+] Auth Bypass: {len(findings)} vulnerabilities")
        return findings
    
    def run_api_security_tests(self, target):
        self.logger.info(f"[*] Testing API security")
        api_tester = APISecurityTester(target, self.config)
        findings = api_tester.test_endpoints()
        self.findings['api_vulnerabilities'] = findings
        self.logger.info(f"[+] API: {len(findings)} vulnerabilities")
        return findings
    
    def generate_report(self, output_file):
        self.logger.info(f"[*] Generating report: {output_file}")
        generator = ReportGenerator(self.findings, self.start_time)
        generator.create_pdf_report(output_file)
        self.logger.info(f"[+] Report saved to {output_file}")
    
    def run_full_assessment(self, target, output_file):
        if not validate_url(target):
            self.logger.error("Invalid target URL")
            return False
        
        print("\n" + "="*70)
        print("  WEB SECURITY ASSESSMENT FRAMEWORK")
        print("  5 Vulnerability Types | 350+ Payloads | Professional Tool")
        print("="*70 + "\n")
        
        try:
            print("[1/7] Running reconnaissance...")
            self.run_reconnaissance(target)
            
            print("[2/7] Testing SQL Injection (200+ payloads)...")
            self.run_sql_injection_tests(target)
            
            print("[3/7] Testing XSS vulnerabilities (50+ payloads)...")
            self.run_xss_tests(target)
            
            print("[4/7] Testing CSRF vulnerabilities (50+ payloads)...")
            self.run_csrf_tests(target)
            
            print("[5/7] Testing Authentication Bypass (50+ payloads)...")
            self.run_auth_bypass_tests(target)
            
            print("[6/7] Testing API security...")
            self.run_api_security_tests(target)
            
            print("[7/7] Generating professional report...")
            self.generate_report(output_file)
            
            # Calculate total vulnerabilities
            total_vulns = sum(len(v) for v in self.findings.values() if isinstance(v, list))
            
            print("\n" + "="*70)
            print(f"[+] Assessment Complete!")
            print(f"[+] Total Vulnerabilities Found: {total_vulns}")
            print(f"[+] Report Generated: {output_file}")
            print("="*70 + "\n")
            
            # Detailed breakdown
            print("📊 Vulnerability Breakdown:")
            print(f"  • Reconnaissance: {len(self.findings['reconnaissance'])} URLs found")
            print(f"  • SQL Injection: {len(self.findings['sql_injection'])} vulnerabilities")
            print(f"  • XSS: {len(self.findings['xss'])} vulnerabilities")
            print(f"  • CSRF: {len(self.findings['csrf'])} vulnerabilities")
            print(f"  • Auth Bypass: {len(self.findings['auth_bypass'])} vulnerabilities")
            print(f"  • API Issues: {len(self.findings['api_vulnerabilities'])} vulnerabilities")
            print()
            
            return True
        
        except Exception as e:
            self.logger.error(f"Assessment failed: {e}")
            print(f"\n[-] Error during assessment: {e}\n")
            return False

def main():
    parser = argparse.ArgumentParser(
        description='Web Security Assessment Framework - Complete Penetration Testing Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Features:
  • SQL Injection Detection (200+ payloads)
  • XSS Vulnerability Testing (50+ payloads)
  • CSRF Detection (50+ payloads)
  • Authentication Bypass Testing (50+ payloads)
  • API Security Assessment
  • Professional PDF Report Generation

Examples:
  python main.py --target https://example.com --output report.pdf
  python main.py --target https://example.com --config config.yaml --output report.pdf
  python main.py --target https://example.com --output report.pdf --verbose
        '''
    )
    
    parser.add_argument('--target', required=True, help='Target URL to assess')
    parser.add_argument('--output', default='security_report.pdf', help='Output report file')
    parser.add_argument('--config', default=None, help='Configuration file (YAML)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Create framework and run assessment
    framework = SecurityAssessmentFramework(args.config)
    success = framework.run_full_assessment(args.target, args.output)
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()