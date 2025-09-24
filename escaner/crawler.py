import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
from scanner import SecurityScanner

class WebCrawler:
    def __init__(self, base_url, max_pages=10, session=None):
        self.base_url = base_url
        self.max_pages = max_pages
        self.visited = set()
        self.to_visit = set()
        self.session = session or requests.Session()
        self.results = []
    
    def crawl(self):
        self.to_visit.add(self.base_url)
        
        while self.to_visit and len(self.visited) < self.max_pages:
            url = self.to_visit.pop()
            
            if url in self.visited:
                continue
                
            try:
                print(f"Escaneando: {url}")
                response = self.session.get(url, timeout=10)
                self.visited.add(url)
                
                # Scan page for vulnerabilities
                scanner = SecurityScanner(url, session=self.session)
                page_results = scanner.scan()
                page_results['url'] = url
                self.results.append(page_results)
                
                # Parse page and extract links (si es HTML)
                if 'text/html' in response.headers.get('Content-Type', ''):
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find all links on page
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(url, href)
                        
                        # Only follow links within the same domain
                        if urlparse(full_url).netloc == urlparse(self.base_url).netloc:
                            if full_url not in self.visited and full_url not in self.to_visit:
                                self.to_visit.add(full_url)
                
            except Exception as e:
                print(f"Error al escanear {url}: {e}")
                # Registrar el error en los resultados
                self.results.append({
                    'url': url,
                    'error': str(e),
                    'vulnerabilities': []
                })
                continue
        
        return self.results


# Función para escanear múltiples URLs sin crawling
def scan_multiple_urls(urls, session=None):
    results = []
    session = session or requests.Session()
    
    for url in urls:
        try:
            scanner = SecurityScanner(url, session=session)
            page_results = scanner.scan()
            page_results['url'] = url
            results.append(page_results)
        except Exception as e:
            print(f"Error al escanear {url}: {e}")
            results.append({
                'url': url,
                'error': str(e),
                'vulnerabilities': []
            })
    
    return results