import requests
from bs4 import BeautifulSoup
import time
from urllib.parse import urljoin, urlparse, parse_qs
import re


DB_ERROR_SIGNATURES = [
    'you have an error in your sql syntax', 'warning: mysql', 'mysql_fetch',
    'native client', 'sql server', 'unclosed quotation mark', 'odbc sql',
    'postgresql', 'pg_query', 'sqlite error', 'ora-00933', 'oracle error'
]


class SecurityScanner:
    def __init__(self, url, session=None):
        self.url = url
        self.parsed = urlparse(url)
        self.session = session or requests.Session()

        # Optimizar la sesión con pool de conexiones
        from requests.adapters import HTTPAdapter
        adapter = HTTPAdapter(pool_connections=20, pool_maxsize=20, max_retries=1)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        self.results = {
            'url': url,
            'vulnerabilities': [],
            'metrics': {}
        }

        # Cargar HTML base una vez
        self._base_html = None
        self._base_headers = None
        self._forms = []

        # Ponderaciones para score de riesgo
        self._sev_scores = {'Critical': 9, 'High': 7, 'Medium': 4, 'Low': 1, 'Info': 0}

    def _ensure_base(self):
        if self._base_html is not None:
            return
        try:
            resp = self.session.get(self.url, timeout=7)
            self._base_headers = resp.headers
            if 'text/html' in resp.headers.get('Content-Type', ''):
                self._base_html = resp.text
                soup = BeautifulSoup(self._base_html, 'html.parser')
                self._forms = soup.find_all('form')
            else:
                self._base_html = ''
                self._forms = []
        except requests.RequestException:
            self._base_html = ''
            self._forms = []

    def _discover_params(self):
        """Descubre parámetros potenciales en la URL y en formularios (GET/POST)."""
        self._ensure_base()

        params = set()

        # Parámetros de la query de la URL
        for k in parse_qs(self.parsed.query).keys():
            params.add((k, 'get', self.url))

        # Inputs de formularios
        for form in self._forms:
            method = (form.get('method') or 'get').lower()
            action = form.get('action') or self.url
            action_url = urljoin(self.url, action)
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                if name:
                    params.add((name, method, action_url))
        return list(params)

    def _add_vuln(self, vuln):
        self.results['vulnerabilities'].append(vuln)

    def _page_risk_score(self):
        return sum(self._sev_scores.get(v.get('severity', 'Low'), 0) for v in self.results['vulnerabilities'])

    def scan(self):
        start_time = time.time()

        # Realizar pruebas de seguridad
        self.test_xss()
        self.test_sql_injection()
        self.test_headers()
        self.test_forms()
        self.test_sensitive_files()

        # Calcular métricas y riesgo
        end_time = time.time()
        self.results['metrics']['scan_duration'] = round(end_time - start_time, 2)
        self.results['metrics']['risk_score'] = self._page_risk_score()
        # Nivel de riesgo según la mayor severidad detectada
        levels = [v.get('severity', 'Low') for v in self.results['vulnerabilities']]
        highest = 'None'
        for lvl in ['Critical', 'High', 'Medium', 'Low']:
            if lvl in levels:
                highest = lvl
                break
        self.results['metrics']['risk_level'] = highest

        return self.results

    # ---------------- XSS -----------------
    def test_xss(self):
        self._ensure_base()
        # Payloads representativos por contexto
        payloads = [
            '<script>alert(1)</script>',
            '" onmouseover="alert(1)"',
            "'>\"/><img src=x onerror=alert(1)>",
        ]

        xss_found_for = set()
        params = self._discover_params() or [('q', 'get', self.url)]

        for name, method, action_url in params:
            if (name, action_url) in xss_found_for:
                continue

            for p in payloads:
                try:
                    if method == 'post':
                        resp = self.session.post(action_url, data={name: p}, timeout=6)
                    else:
                        resp = self.session.get(action_url, params={name: p}, timeout=6)
                except requests.RequestException:
                    continue

                ctype = resp.headers.get('Content-Type', '')
                if 'text/html' not in ctype:
                    continue
                body = resp.text

                # Heurísticas por contexto
                evidence = None
                severity = 'High'

                # Reflejado literal
                if p in body:
                    evidence = 'Reflected payload in HTML'
                else:
                    # En atributo HTML
                    attr_pat = re.compile(rf'{re.escape(name)}[\"\"][^>]*on\w+\s*=\s*[\"\"]?')
                    if attr_pat.search(body):
                        evidence = 'Payload reached HTML attribute context'
                        severity = 'Medium'
                    # Codificado pero ejecutable (img onerror)
                    if not evidence and 'onerror=alert(1)' in body:
                        evidence = 'Possible event handler execution context'

                if evidence:
                    self._add_vuln({
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': severity,
                        'description': f'Input reflejado sin sanitización en parámetro "{name}"',
                        'details': f'{evidence} at {action_url}',
                        'payload': p,
                        'parameter': name,
                        'method': method.upper(),
                    })
                    xss_found_for.add((name, action_url))
                    # Evitar demasiadas peticiones por parámetro
                    break

    # ---------------- SQLi -----------------
    def test_sql_injection(self):
        params = self._discover_params() or [('id', 'get', self.url)]

        # Payloads de error basado
        error_payloads = ["'", '"', "\\"]
        # Boolean-based (comparativa True/False)
        bool_payloads = [
            ("' AND 1=1-- ", "' AND 1=2-- "),
            ('" AND 1=1-- ', '" AND 1=2-- '),
        ]
        # Time-based (pequeña espera para no ralentizar)
        time_payloads = [
            ("' OR SLEEP(2)-- ", 2.0),
            ("'; SELECT pg_sleep(2)-- ", 2.0),
        ]

        for name, method, action_url in params:
            # Obtener baseline
            try:
                if method == 'post':
                    base = self.session.post(action_url, data={name: '1'}, timeout=6)
                else:
                    base = self.session.get(action_url, params={name: '1'}, timeout=6)
                base_time = base.elapsed.total_seconds() or 0
            except requests.RequestException:
                base_time = 0

            # 1) Error-based
            sqli_detected = False
            for p in error_payloads:
                try:
                    if method == 'post':
                        r = self.session.post(action_url, data={name: p}, timeout=6)
                    else:
                        r = self.session.get(action_url, params={name: p}, timeout=6)
                    low = r.text.lower()
                    if any(sig in low for sig in DB_ERROR_SIGNATURES):
                        self._add_vuln({
                            'type': 'SQL Injection (Error-based)',
                            'severity': 'High',
                            'description': f'Errores SQL detectados al inyectar en "{name}"',
                            'details': f'Endpoint: {action_url}',
                            'payload': p,
                            'parameter': name,
                            'method': method.upper(),
                        })
                        sqli_detected = True
                        break
                except requests.RequestException:
                    continue

            if sqli_detected:
                continue

            # 2) Boolean-based
            for p_true, p_false in bool_payloads:
                try:
                    if method == 'post':
                        r1 = self.session.post(action_url, data={name: p_true}, timeout=6)
                        r2 = self.session.post(action_url, data={name: p_false}, timeout=6)
                    else:
                        r1 = self.session.get(action_url, params={name: p_true}, timeout=6)
                        r2 = self.session.get(action_url, params={name: p_false}, timeout=6)
                    # Heurística de diferencia
                    if abs(len(r1.text) - len(r2.text)) > max(50, 0.15 * max(len(r1.text), 1)):
                        self._add_vuln({
                            'type': 'SQL Injection (Boolean-based)',
                            'severity': 'High',
                            'description': f'Diferencias significativas entre expresiones TRUE/FALSE en "{name}"',
                            'details': f'Endpoint: {action_url}',
                            'payload': f'T:{p_true} | F:{p_false}',
                            'parameter': name,
                            'method': method.upper(),
                        })
                        sqli_detected = True
                        break
                except requests.RequestException:
                    continue

            if sqli_detected:
                continue

            # 3) Time-based (una sola prueba rápida)
            for p, wait_s in time_payloads:
                try:
                    t0 = time.time()
                    if method == 'post':
                        _ = self.session.post(action_url, data={name: p}, timeout=wait_s + 4)
                    else:
                        _ = self.session.get(action_url, params={name: p}, timeout=wait_s + 4)
                    dt = time.time() - t0
                    if dt - base_time >= wait_s - 0.5:  # margen
                        self._add_vuln({
                            'type': 'SQL Injection (Time-based)',
                            'severity': 'High',
                            'description': f'Respuestas con retardo inducido al inyectar en "{name}"',
                            'details': f'Endpoint: {action_url} (+{round(dt,2)}s)',
                            'payload': p,
                            'parameter': name,
                            'method': method.upper(),
                        })
                        break
                except requests.RequestException:
                    continue

    # ---------------- Headers -----------------
    def test_headers(self):
        try:
            self._ensure_base()
            headers = self._base_headers or {}

            security_headers = {
                'X-Frame-Options': 'Missing',
                'X-Content-Type-Options': 'Missing',
                'Strict-Transport-Security': 'Missing',
                'Content-Security-Policy': 'Missing'
            }

            for header in security_headers:
                if header in headers:
                    security_headers[header] = 'Present'

            for header, status in security_headers.items():
                if status == 'Missing':
                    sev = 'Medium' if header != 'Content-Security-Policy' else 'High'
                    self._add_vuln({
                        'type': 'Security Header Missing',
                        'severity': sev,
                        'description': f'Falta cabecera de seguridad {header}',
                        'details': 'La cabecera ayuda a mitigar ataques comunes (clickjacking, MIME sniffing, etc.)'
                    })
        except requests.RequestException as e:
            print(f"Header test error: {e}")

    # ---------------- Formularios (CSRF) -----------------
    def test_forms(self):
        try:
            self._ensure_base()
            for form in self._forms:
                csrf_token = form.find('input', {'name': ['csrf', 'csrfmiddlewaretoken', '_token', '__requestverificationtoken']})
                if not csrf_token:
                    self._add_vuln({
                        'type': 'CSRF Protection Missing',
                        'severity': 'Medium',
                        'description': 'Formulario sin token CSRF detectado',
                        'details': 'Un formulario sin protección CSRF puede permitir acciones no autorizadas.'
                    })
                    break
        except requests.RequestException as e:
            print(f"Form test error: {e}")

    # ---------------- Archivos sensibles -----------------
    def test_sensitive_files(self):
        sensitive_files = [
            '/.env',
            '/robots.txt',
            '/.git/config',
            '/phpinfo.php',
            '/admin.php',
            '/wp-config.php'
        ]

        for file_path in sensitive_files:
            full = urljoin(self.url, file_path)
            try:
                # Probar primero con HEAD para rapidez
                response = self.session.head(full, timeout=4, allow_redirects=True)
                status = response.status_code
                if status == 200 or (status in (301, 302, 307, 308) and 'Location' in response.headers):
                    # Confirmar con GET solo para 200 o redirección sospechosa
                    if status != 200:
                        response = self.session.get(full, timeout=6)
                    if response.status_code == 200:
                        self._add_vuln({
                            'type': 'Sensitive File Exposure',
                            'severity': 'Low' if 'robots.txt' in file_path else 'Medium',
                            'description': f'Archivo sensible accesible: {file_path}',
                            'details': f'El recurso {file_path} es accesible y podría exponer información.'
                        })
            except requests.RequestException:
                continue