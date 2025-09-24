import requests
from bs4 import BeautifulSoup
import time
from urllib.parse import urljoin

class SecurityScanner:
    def __init__(self, url, session=None):
        self.url = url
        self.session = session or requests.Session()
        self.results = {
            'url': url,
            'vulnerabilities': [],
            'metrics': {}
        }
    
    def scan(self):
        start_time = time.time()
        
        # Realizar pruebas de seguridad
        self.test_xss()
        self.test_sql_injection()
        self.test_headers()
        self.test_forms()
        self.test_sensitive_files()
        
        # Calcular métricas
        end_time = time.time()
        self.results['metrics']['scan_duration'] = round(end_time - start_time, 2)
        
        return self.results
    
    def test_xss(self):
        # Prueba XSS simple
        test_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            'javascript:alert("XSS")'
        ]
        
        for payload in test_payloads:
            try:
                response = self.session.get(self.url, params={'q': payload}, timeout=5)
                if payload in response.text:
                    self.results['vulnerabilities'].append({
                        'type': 'XSS',
                        'severity': 'High',
                        'description': 'Possible XSS vulnerability detected',
                        'details': f'Input reflected without sanitization: {payload}',
                        'payload': payload
                    })
                    break
            except:
                continue
    
    def test_sql_injection(self):
        # Pruebas básicas de SQL injection
        test_payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--"
        ]
        
        for payload in test_payloads:
            try:
                response = self.session.get(self.url, params={'id': payload}, timeout=5)
                response_text = response.text.lower()
                
                if 'error' in response_text and ('sql' in response_text or 'mysql' in response_text):
                    self.results['vulnerabilities'].append({
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'description': 'Possible SQL injection vulnerability',
                        'details': f'SQL error returned for payload: {payload}',
                        'payload': payload
                    })
                    break
            except:
                continue
    
    def test_headers(self):
        # Verificar headers de seguridad
        try:
            response = self.session.get(self.url, timeout=5)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Missing',
                'X-Content-Type-Options': 'Missing',
                'Strict-Transport-Security': 'Missing',
                'Content-Security-Policy': 'Missing'
            }
            
            for header in security_headers:
                if header in headers:
                    security_headers[header] = 'Present'
            
            # Añadir hallazgos a los resultados
            for header, status in security_headers.items():
                if status == 'Missing':
                    self.results['vulnerabilities'].append({
                        'type': 'Security Header Missing',
                        'severity': 'Medium',
                        'description': f'{header} header is missing',
                        'details': f'The {header} header helps protect against clickjacking and other attacks'
                    })
                    
        except Exception as e:
            print(f"Header test error: {e}")
    
    def test_forms(self):
        # Probar formularios para protección CSRF
        try:
            response = self.session.get(self.url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                csrf_token = form.find('input', {'name': ['csrf', 'csrfmiddlewaretoken', '_token']})
                if not csrf_token:
                    self.results['vulnerabilities'].append({
                        'type': 'CSRF Protection Missing',
                        'severity': 'Medium',
                        'description': 'Form without CSRF token detected',
                        'details': 'A form without CSRF protection could be vulnerable to Cross-Site Request Forgery attacks'
                    })
                    break
                    
        except Exception as e:
            print(f"Form test error: {e}")
    
    def test_sensitive_files(self):
        # Verificar archivos sensibles expuestos
        sensitive_files = [
            '/.env',
            '/robots.txt',
            '/.git/config',
            '/phpinfo.php',
            '/admin.php',
            '/wp-config.php'
        ]
        
        for file_path in sensitive_files:
            try:
                response = self.session.get(urljoin(self.url, file_path), timeout=5)
                if response.status_code == 200:
                    self.results['vulnerabilities'].append({
                        'type': 'Sensitive File Exposure',
                        'severity': 'Low' if 'txt' in file_path else 'Medium',
                        'description': f'Sensitive file accessible: {file_path}',
                        'details': f'The file {file_path} is accessible and may expose sensitive information'
                    })
            except:
                continue