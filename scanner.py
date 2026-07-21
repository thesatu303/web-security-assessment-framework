# scanner.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging

class WebScanner:
    def __init__(self, target, config):
        self.target = target
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.found_urls = set()
        self.found_parameters = {}
    
    def scan(self):
        """Run complete web scanning"""
        self.logger.info(f"Scanning {self.target}")
        
        findings = {
            'target': self.target,
            'urls_found': [],
            'parameters': [],
            'headers': {},
            'technologies': [],
            'status_code': 0,
            'page_title': 'N/A'
        }
        
        try:
            # Get base page
            self.logger.info(f"[*] Fetching target URL: {self.target}")
            response = requests.get(
                self.target, 
                timeout=self.config.get('timeout', 10),
                verify=False
            )
            
            findings['status_code'] = response.status_code
            findings['headers'] = dict(response.headers)
            
            self.logger.info(f"[+] Status Code: {response.status_code}")
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract title
            title_tag = soup.find('title')
            if title_tag:
                findings['page_title'] = title_tag.string
            
            # Extract URLs
            self.logger.info(f"[*] Extracting URLs...")
            urls = self.extract_urls(soup)
            findings['urls_found'] = list(set(urls))  # Remove duplicates
            self.logger.info(f"[+] Found {len(findings['urls_found'])} URLs")
            
            # Extract parameters
            self.logger.info(f"[*] Extracting parameters...")
            params = self.extract_parameters(soup)
            findings['parameters'] = params
            self.logger.info(f"[+] Found {len(params)} parameters")
            
            # Detect technologies
            self.logger.info(f"[*] Detecting technologies...")
            tech = self.detect_technologies(response)
            findings['technologies'] = tech
            self.logger.info(f"[+] Found {len(tech)} technologies")
            
            self.logger.info(f"[+] Reconnaissance complete!")
            
        except requests.exceptions.Timeout:
            self.logger.error("Request timeout")
            findings['error'] = 'Timeout'
        except Exception as e:
            self.logger.error(f"Error scanning: {e}")
            findings['error'] = str(e)
        
        return findings
    
    def extract_urls(self, soup):
        """Extract all URLs from page"""
        urls = []
        
        # From <a> tags
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href:
                url = urljoin(self.target, href)
                urls.append(url)
        
        # From <form> tags
        for form in soup.find_all('form'):
            action = form.get('action')
            if action:
                url = urljoin(self.target, action)
                urls.append(url)
        
        # From <script> tags
        for script in soup.find_all('script', src=True):
            src = script['src']
            if src:
                url = urljoin(self.target, src)
                urls.append(url)
        
        # From <link> tags
        for link in soup.find_all('link', href=True):
            href = link['href']
            if href:
                url = urljoin(self.target, href)
                urls.append(url)
        
        # Remove duplicates and invalid
        valid_urls = []
        for url in urls:
            if url and url.startswith(('http://', 'https://')):
                valid_urls.append(url)
        
        return valid_urls
    
    def extract_parameters(self, soup):
        """Extract form parameters"""
        params = []
        
        for form in soup.find_all('form'):
            form_params = {
                'form_action': form.get('action', 'N/A'),
                'form_method': form.get('method', 'POST'),
                'fields': []
            }
            
            for input_field in form.find_all(['input', 'textarea', 'select']):
                param = {
                    'name': input_field.get('name', 'N/A'),
                    'type': input_field.get('type', 'text'),
                    'value': input_field.get('value', '')
                }
                form_params['fields'].append(param)
            
            if form_params['fields']:
                params.append(form_params)
        
        return params
    
    def detect_technologies(self, response):
        """Detect web technologies"""
        technologies = []
        response_lower = response.text.lower()
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        # Common frameworks/CMS
        tech_signatures = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Joomla': ['joomla', 'com_'],
            'Drupal': ['drupal', '/sites/'],
            'Django': ['csrf token', 'django'],
            'Flask': ['flask', 'werkzeug'],
            'Laravel': ['laravel', 'app.blade.php'],
            'ASP.NET': ['aspx', 'asp.net'],
            'PHP': ['php', '.php'],
            'Node.js': ['node.js', 'express'],
            'jQuery': ['jquery', 'jquery.js'],
            'Bootstrap': ['bootstrap', 'bootstrap.css'],
            'Angular': ['angular', 'ng-app'],
            'React': ['react', '__react'],
            'Vue': ['vue', 'v-app']
        }
        
        for tech, signatures in tech_signatures.items():
            for sig in signatures:
                if sig in response_lower or sig in headers_lower.get('server', ''):
                    technologies.append(tech)
                    break
        
        return list(set(technologies))