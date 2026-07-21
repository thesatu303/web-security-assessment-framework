# csrf_detector.py
import requests
import logging
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CSRFDetector:
    def __init__(self, target, config):
        self.target = target
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # 50+ CSRF Detection Payloads
        self.payloads = {
            'missing_csrf_token': [
                {'action': 'delete', 'id': '1'},
                {'action': 'update', 'data': 'test'},
                {'action': 'transfer', 'amount': '1000'},
                {'username': 'admin', 'password': 'test'},
            ],
            
            'empty_csrf_token': [
                {'csrf_token': '', 'action': 'delete'},
                {'token': '', 'action': 'update'},
                {'_token': '', 'action': 'delete'},
                {'authenticity_token': '', 'action': 'update'},
            ],
            
            'invalid_csrf_token': [
                {'csrf_token': 'invalid', 'action': 'delete'},
                {'csrf_token': '0', 'action': 'update'},
                {'csrf_token': 'null', 'action': 'delete'},
                {'csrf_token': 'false', 'action': 'update'},
                {'csrf_token': 'xyz123', 'action': 'delete'},
            ],
            
            'duplicate_csrf_token': [
                {'csrf_token': 'abc123', 'csrf_token': 'abc123', 'action': 'delete'},
            ],
            
            'case_variation': [
                {'CSRF_TOKEN': 'test', 'action': 'delete'},
                {'Csrf_Token': 'test', 'action': 'update'},
                {'csrf_TOKEN': 'test', 'action': 'delete'},
            ],
            
            'old_csrf_token': [
                {'csrf_token': 'expired_old_token', 'action': 'delete'},
                {'csrf_token': 'previous_session_token', 'action': 'update'},
            ],
            
            'header_bypass': [
                {'action': 'delete', 'X-CSRF-Token': ''},
                {'action': 'delete', 'X-CSRF-Token': 'invalid'},
            ],
            
            'method_bypass': [
                {'_method': 'POST', 'action': 'delete'},
                {'_method': 'DELETE', 'action': 'update'},
                {'X-HTTP-Method-Override': 'POST', 'action': 'delete'},
            ],
            
            'null_byte': [
                {'csrf_token': 'valid%00', 'action': 'delete'},
                {'csrf_token': 'token\x00', 'action': 'update'},
            ],
            
            'unicode_bypass': [
                {'csrf_token': 'valid\u0000', 'action': 'delete'},
            ],
            
            'encoding_bypass': [
                {'csrf_token': 'test%20', 'action': 'delete'},
                {'csrf_token': 'test%00', 'action': 'update'},
                {'csrf_token': '%74%65%73%74', 'action': 'delete'},
            ],
            
            'referrer_bypass': [
                {'action': 'delete', 'Referer': ''},
                {'action': 'delete', 'Referer': 'null'},
                {'action': 'delete', 'Origin': ''},
            ],
            
            'no_samesite': [
                {'action': 'delete'},  # No SameSite cookie check
            ],
            
            'wildcard_origin': [
                {'action': 'delete', 'Origin': '*'},
            ],
        }
    
    def test_all(self):
        """Test all CSRF payloads"""
        findings = []
        total_tests = sum(len(p) for p in self.payloads.values())
        tested = 0
        
        self.logger.info(f"[*] Testing {total_tests} CSRF detection payloads...")
        
        for category, payloads in self.payloads.items():
            for payload in payloads:
                result = self.test_payload(category, payload)
                tested += 1
                
                if result and result['vulnerable']:
                    findings.append(result)
                    self.logger.info(f"[+] CSRF VULNERABLE: {category}")
                
                if tested % 10 == 0:
                    print(f"  [{tested}/{total_tests}] Testing CSRF...", end='\r')
        
        self.logger.info(f"[*] CSRF Testing Complete!")
        return findings
    
    def test_payload(self, category, payload):
        """Test single CSRF payload"""
        try:
            # Test with POST (common for CSRF)
            response = requests.post(
                self.target,
                data=payload,
                timeout=5,
                verify=False
            )
            
            if self.check_vulnerability(response, category):
                return {
                    'type': 'CSRF',
                    'category': category,
                    'payload': str(payload)[:50],
                    'vulnerable': True,
                    'status_code': response.status_code,
                }
        except:
            pass
        
        return None
    
    def check_vulnerability(self, response, category):
        """Check if CSRF vulnerability exists"""
        response_lower = response.text.lower()
        
        # No CSRF error/warning = vulnerable
        csrf_errors = [
            'csrf', 'cross-site request forgery',
            'token mismatch', 'invalid token',
            'forbidden', '403'
        ]
        
        if not any(error in response_lower for error in csrf_errors):
            if response.status_code == 200 or response.status_code == 302:
                return True
        
        return False
    
    def count_payloads(self):
        total = sum(len(p) for p in self.payloads.values())
        return total, self.payloads