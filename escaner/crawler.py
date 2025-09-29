import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
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

        def fetch_and_extract(url):
            try:
                response = self.session.get(url, timeout=10)
                links = []
                if 'text/html' in response.headers.get('Content-Type', ''):
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(url, href)
                        if urlparse(full_url).netloc == urlparse(self.base_url).netloc:
                            links.append(full_url)
                return url, response, links, None
            except requests.RequestException as e:
                return url, None, [], str(e)

        while self.to_visit and len(self.visited) < self.max_pages:
            batch = []
            # construir un batch de URLs nuevas
            while self.to_visit and len(batch) + len(self.visited) < self.max_pages:
                u = self.to_visit.pop()
                if u not in self.visited:
                    batch.append(u)

            futures = []
            with ThreadPoolExecutor(max_workers=6) as ex:
                for u in batch:
                    futures.append(ex.submit(fetch_and_extract, u))

                # escanear cada página conforme llega
                for fut in as_completed(futures):
                    url, _response, links, err = fut.result()
                    self.visited.add(url)
                    if err:
                        print(f"Error al escanear {url}: {err}")
                        self.results.append({'url': url, 'error': err, 'vulnerabilities': []})
                        continue

                    # lanzar scanner (en el mismo pool para reutilizar sesión)
                    scanner = SecurityScanner(url, session=self.session)
                    page_results = scanner.scan()
                    page_results['url'] = url
                    self.results.append(page_results)

                    for full_url in links:
                        if full_url not in self.visited and full_url not in self.to_visit:
                            self.to_visit.add(full_url)

        return self.results


# Función para escanear múltiples URLs sin crawling
def scan_multiple_urls(urls, session=None):
    results = []
    session = session or requests.Session()

    def do_scan(u):
        try:
            scanner = SecurityScanner(u, session=session)
            r = scanner.scan()
            r['url'] = u
            return r
        except requests.RequestException as e:
            print(f"Error al escanear {u}: {e}")
            return {'url': u, 'error': str(e), 'vulnerabilities': []}

    with ThreadPoolExecutor(max_workers=min(8, max(2, len(urls)))) as ex:
        futures = [ex.submit(do_scan, u) for u in urls]
        for fut in as_completed(futures):
            results.append(fut.result())

    return results