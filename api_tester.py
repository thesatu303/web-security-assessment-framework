# src/api_tester.py
import requests
import logging
import json

from xss_injection import XSSInjectionTester

def test_xss(self):
    """Test XSS vulnerabilities"""
    self.logger.info("[*] Testing XSS vulnerabilities")
    xss_tester = XSSInjectionTester(self.target, self.config)
    findings = xss_tester.test_all()
    return findings

class APISecurityTester:
    def __init__(self, target, config):
        self.target = target
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.common_endpoints = [
            '/api/users', '/api/admin', '/api/auth',
            '/api/login', '/api/register', '/api/profile'
        ]
    
    def test_endpoints(self):
        """Test API endpoints for vulnerabilities"""
        findings = []
        
        for endpoint in self.common_endpoints:
            url = self.target.rstrip('/') + endpoint
            
            # Test authentication bypass
            result = self.test_auth_bypass(url)
            if result['vulnerable']:
                findings.append(result)
            
            # Test input validation
            result = self.test_input_validation(url)
            if result['vulnerable']:
                findings.append(result)
        
        return findings
    
    def test_auth_bypass(self, url):
        """Test authentication bypass"""
        headers = {'Authorization': 'Bearer invalid'}
        try:
            response = requests.get(url, headers=headers, timeout=5)
            vulnerable = response.status_code == 200
            return {
                'endpoint': url,
                'test': 'authentication_bypass',
                'vulnerable': vulnerable,
                'status_code': response.status_code
            }
        except:
            return {'vulnerable': False}
    
    def test_input_validation(self, url):
        """Test input validation"""
        payloads = ['<script>alert(1)</script>', "'; DROP TABLE users;--"]
        
        for payload in payloads:
            try:
                response = requests.get(url, params={'input': payload}, timeout=5)
                if payload in response.text:
                    return {
                        'endpoint': url,
                        'test': 'input_validation',
                        'vulnerable': True,
                        'payload': payload
                    }
            except:
                pass
        
        return {'vulnerable': False}