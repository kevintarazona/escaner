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
        # Payloads representativos por contexto con descripción
        payloads = [
            { 'p': '<script>alert(1)</script>', 'd': 'Script tag clásico (reflejado en HTML)'},
            { 'p': '" onmouseover="alert(1)"', 'd': 'Inyección en atributo con event handler'},
            { 'p': "'>\"/><img src=x onerror=alert(1)>", 'd': 'Rompimiento de contexto + onerror'},
            { 'p': '<img src=x onerror=alert(1)>', 'd': 'XSS a través de onerror en imagen'},
            { 'p': '"><svg/onload=alert(1)>', 'd': 'SVG onload ejecutable'},
            { 'p': '<iframe src=javascript:alert(1)>', 'd': 'javascript: URI dentro de iframe'},
            { 'p': '<body onload=alert(1)>', 'd': 'Ejecución al cargar el body'},
            { 'p': '<details open ontoggle=alert(1)>', 'd': 'Evento HTML5 ontoggle'},
            { 'p': '"><script>alert(1)</script>', 'd': 'Cierre de atributo + script tag'},
            { 'p': '<svg><a xlink:href=javascript:alert(1)>x</a></svg>', 'd': 'SVG xlink javascript:'},
            { 'p': '<input autofocus onfocus=alert(1)>', 'd': 'Evento onfocus en input'},
            { 'p': '<video src=x onerror=alert(1)>', 'd': 'onerror en elemento media'},
        ]

        xss_found_for = set()
        params = self._discover_params() or [('q', 'get', self.url)]

        for name, method, action_url in params:
            if (name, action_url) in xss_found_for:
                continue

            for item in payloads:
                p = item['p']
                p_desc = item['d']
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
                        'description': f'Entrada del usuario reflejada sin la sanitización/escape adecuados en el parámetro "{name}", lo que permite la ejecución de JavaScript.',
                        'details': f'Contexto detectado: {evidence}',
                        'payload': p,
                        'payload_description': p_desc,
                        'parameter': name,
                        'method': method.upper(),
                        'endpoint': action_url,
                        'evidence': evidence,
                        'recommendation': 'Implemente escape de salida según el contexto (HTML, atributo, JS), valide/encode inputs y habilite una CSP restrictiva.'
                    })
                    xss_found_for.add((name, action_url))
                    # Evitar demasiadas peticiones por parámetro
                    break

    # ---------------- SQLi -----------------
    def test_sql_injection(self):
        params = self._discover_params() or [('id', 'get', self.url)]

        # Payloads de error basado (ampliados)
        error_payloads = [
            { 'p': "'", 'd': 'Comilla simple para forzar error de sintaxis'},
            { 'p': '"', 'd': 'Comilla doble para forzar error de sintaxis'},
            { 'p': "'-- ", 'd': 'Comilla + comentario estilo SQL'},
            { 'p': "'#", 'd': 'Comilla + comentario (#) MySQL'},
            { 'p': "'/*", 'd': 'Comilla + inicio de comentario'},
            { 'p': '"-- ', 'd': 'Comilla doble + comentario'},
            { 'p': '")', 'd': 'Cierre de paréntesis desbalanceado'},
            { 'p': "))", 'd': 'Paréntesis desbalanceados'},
        ]
        # Boolean-based (comparativa True/False) ampliados
        bool_payloads = [
            ("' AND 1=1-- ", "' AND 1=2-- ", 'AND tautología vs contradicción (comilla simple)'),
            ('" AND 1=1-- ', '" AND 1=2-- ', 'AND tautología vs contradicción (comilla doble)'),
            ("' OR '1'='1'-- ", "' OR '1'='2'-- ", 'OR tautología vs contradicción (quoted)'),
            ('" OR "1"="1"-- ', '" OR "1"="2"-- ', 'OR tautología vs contradicción (quoted, dbl)'),
            ("') OR ('1'='1')-- ", "') OR ('1'='2')-- ", 'Cierre de paréntesis + OR'),
        ]
        # Time-based (ampliado, tiempos cortos)
        time_payloads = [
            ("' OR SLEEP(2)-- ", 2.0, 'MySQL SLEEP(2)'),
            ("'; SELECT pg_sleep(2)-- ", 2.0, 'PostgreSQL pg_sleep(2)'),
            ("'; WAITFOR DELAY '0:0:2'-- ", 2.0, 'MSSQL WAITFOR DELAY 2s'),
            ("' AND SLEEP(2)-- ", 2.0, 'MySQL AND SLEEP(2)')
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
            for item in error_payloads:
                p = item['p']
                p_desc = item['d']
                try:
                    if method == 'post':
                        r = self.session.post(action_url, data={name: p}, timeout=6)
                    else:
                        r = self.session.get(action_url, params={name: p}, timeout=6)
                    low = r.text.lower()
                    matched = [sig for sig in DB_ERROR_SIGNATURES if sig in low]
                    if matched:
                        self._add_vuln({
                            'type': 'SQL Injection (Error-based)',
                            'severity': 'High',
                            'description': f'Posible inyección SQL: el parámetro "{name}" provoca errores del motor de base de datos.',
                            'details': f'Firma(s) detectada(s): {", ".join(matched[:3])}',
                            'payload': p,
                            'payload_description': p_desc,
                            'parameter': name,
                            'method': method.upper(),
                            'endpoint': action_url,
                            'evidence': 'Mensaje de error SQL devuelto por el servidor',
                            'recommendation': 'Use consultas parametrizadas/preparadas, valide y tipifique entradas, y desactive mensajes de error detallados en producción.'
                        })
                        sqli_detected = True
                        break
                except requests.RequestException:
                    continue

            if sqli_detected:
                continue

            # 2) Boolean-based
            for p_true, p_false, pair_desc in bool_payloads:
                try:
                    if method == 'post':
                        r1 = self.session.post(action_url, data={name: p_true}, timeout=6)
                        r2 = self.session.post(action_url, data={name: p_false}, timeout=6)
                    else:
                        r1 = self.session.get(action_url, params={name: p_true}, timeout=6)
                        r2 = self.session.get(action_url, params={name: p_false}, timeout=6)
                    # Heurística de diferencia
                    diff = abs(len(r1.text) - len(r2.text))
                    if diff > max(50, 0.15 * max(len(r1.text), 1)):
                        self._add_vuln({
                            'type': 'SQL Injection (Boolean-based)',
                            'severity': 'High',
                            'description': f'Posible inyección SQL: diferencias significativas al evaluar expresiones TRUE/FALSE inyectadas en "{name}".',
                            'details': f'Diferencia de tamaño: {diff} bytes',
                            'payload': f'T:{p_true} | F:{p_false}',
                            'payload_description': pair_desc,
                            'parameter': name,
                            'method': method.upper(),
                            'endpoint': action_url,
                            'evidence': 'Variación notable en la longitud/estructura de la respuesta entre TRUE y FALSE',
                            'recommendation': 'Aplicar consultas parametrizadas y normalizar/validar entradas; evitar concatenación dinámica en SQL.'
                        })
                        sqli_detected = True
                        break
                except requests.RequestException:
                    continue

            if sqli_detected:
                continue

            # 3) Time-based (una sola prueba rápida)
            for p, wait_s, p_desc in time_payloads:
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
                            'description': f'Posible inyección SQL: respuestas con retardo inducido por funciones de espera al inyectar en "{name}".',
                            'details': f'Retardo observado: +{round(dt,2)}s (baseline: ~{round(base_time,2)}s, esperado: ~{wait_s}s)',
                            'payload': p,
                            'payload_description': p_desc,
                            'parameter': name,
                            'method': method.upper(),
                            'endpoint': action_url,
                            'evidence': 'Diferencia de tiempo consistente ante payloads con SLEEP/WAIT',
                            'recommendation': 'Use consultas parametrizadas; limite funciones bloqueantes y haga validación/normalización estricta.'
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
                        'description': f'Falta cabecera de seguridad {header}.',
                        'details': 'La cabecera ayuda a mitigar ataques comunes (p. ej., clickjacking, sniffing o MITM).',
                        'endpoint': self.url,
                        'recommendation': 'Configure el servidor para incluir las cabeceras de seguridad recomendadas; revise valores adecuados para su app.'
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
                        'description': 'Formulario sin token CSRF detectado.',
                        'details': 'Sin token anti-CSRF, un atacante puede forzar acciones autenticadas del usuario.',
                        'endpoint': self.url,
                        'recommendation': 'Implemente tokens CSRF únicos por sesión/solicitud y verifique en el servidor; use SameSite en cookies.'
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
                            'description': f'Archivo sensible accesible: {file_path}.',
                            'details': f'El recurso {file_path} es accesible y podría exponer información de entorno o configuración.',
                            'endpoint': full,
                            'recommendation': 'Restrinja acceso por servidor (403), mueva secretos fuera del docroot y revise configuración.'
                        })
            except requests.RequestException:
                continue