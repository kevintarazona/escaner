from fpdf import FPDF
import os
from datetime import datetime


def _safe_text(s):
    """Convierte a str y elimina caracteres no representables en latin-1 para evitar errores en FPDF."""
    if s is None:
        return ''
    s = str(s)
    try:
        s.encode('latin-1')
        return s
    except UnicodeEncodeError:
        return s.encode('latin-1', 'ignore').decode('latin-1')


class ReportPDF(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 14)
        self.cell(0, 10, _safe_text('Informe de Escaneo de Seguridad'), 0, 1, 'C')
        self.set_draw_color(50, 50, 50)
        self.set_line_width(0.4)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, _safe_text(f'Página {self.page_no()}'), 0, 0, 'C')

    def section_title(self, title):
        self.set_font('Helvetica', 'B', 12)
        self.set_fill_color(230, 230, 230)
        self.cell(0, 8, _safe_text(title), 0, 1, 'L', True)
        self.ln(2)

    def add_key_value(self, key, value):
        self.set_font('Helvetica', '', 10)
        self.multi_cell(self.epw, 6, _safe_text(f'{key}: {value}'))

    def add_code_block(self, text, label=None):
        """Muestra texto en fuente monoespaciada con fondo para payloads/evidencias."""
        txt = '' if text is None else str(text)
        if label:
            self.set_font('Helvetica', 'I', 9)
            self.multi_cell(self.epw, 5, _safe_text(label))
        # Estilo de bloque
        self.set_font('Courier', '', 9)
        self.set_fill_color(245, 245, 245)
        self.set_draw_color(220, 220, 220)
        # Bordes ligeros y relleno
        self.multi_cell(self.epw, 5, _safe_text(txt), border=1, align='L', fill=True)
        self.set_font('Helvetica', '', 9)

    def add_vulnerability(self, idx, vuln):
        self.set_font('Helvetica', 'B', 11)
        sev = vuln.get('severity', 'N/A')
        self.set_text_color(0, 0, 0)
        if sev.lower() == 'high':
            self.set_text_color(200, 30, 30)
        elif sev.lower() == 'medium':
            self.set_text_color(200, 120, 30)
        elif sev.lower() == 'low':
            self.set_text_color(30, 100, 200)
        self.multi_cell(self.epw, 6, _safe_text(f'{idx}. {vuln.get("type", "Vulnerabilidad")}  (Severidad: {sev})'))
        self.set_text_color(0, 0, 0)
        self.set_font('Helvetica', '', 9)
        # Descripción amigable con fallback
        desc = vuln.get('description') or f'Detección de {vuln.get("type", "vulnerabilidad").lower()} basada en heurísticas del escáner.'
        self.multi_cell(self.epw, 5, _safe_text(f'Descripción: {desc}'))
        if vuln.get('details'):
            self.multi_cell(self.epw, 5, _safe_text(f'Detalles: {vuln.get("details")}'))
        if vuln.get('payload'):
            self.add_code_block(vuln.get('payload'), label='Payload:')
        if vuln.get('payload_description'):
            self.multi_cell(self.epw, 5, _safe_text(f'Descripción del payload: {vuln.get("payload_description")}'))
        # Nuevos campos opcionales
        if vuln.get('parameter'):
            self.multi_cell(self.epw, 5, _safe_text(f'Parámetro: {vuln.get("parameter")}'))
        if vuln.get('method'):
            self.multi_cell(self.epw, 5, _safe_text(f'Método: {vuln.get("method")}'))
        if vuln.get('endpoint'):
            self.multi_cell(self.epw, 5, _safe_text(f'Endpoint: {vuln.get("endpoint")}'))
        if vuln.get('evidence'):
            self.add_code_block(vuln.get('evidence'), label='Evidencia:')
        if vuln.get('recommendation'):
            self.multi_cell(self.epw, 5, _safe_text(f'Recomendación: {vuln.get("recommendation")}'))
        # Separador visual
        self.set_draw_color(230, 230, 230)
        y = self.get_y()
        self.line(10, y, 200, y)
        self.ln(2)


def _compute_stats(scan_results_dict):
    total_vulns = 0
    sev_counts = {'high': 0, 'medium': 0, 'low': 0}
    type_counts = {}
    for page in scan_results_dict.get('results', []):
        vulns = page.get('vulnerabilities', [])
        total_vulns += len(vulns)
        for v in vulns:
            sev = v.get('severity', '').lower()
            if sev in sev_counts:
                sev_counts[sev] += 1
            t = v.get('type', 'Otro')
            type_counts[t] = type_counts.get(t, 0) + 1
    return {
        'total_pages': len(scan_results_dict.get('results', [])),
        'total_vulnerabilities': total_vulns,
        'high_vulnerabilities': sev_counts['high'],
        'medium_vulnerabilities': sev_counts['medium'],
        'low_vulnerabilities': sev_counts['low'],
        'type_counts': type_counts
    }


def generate_pdf_report(scan_results):
    """Genera un PDF a partir de los resultados del escaneo.

    scan_results puede ser:
      - dict con clave 'results'
      - lista de páginas (se envolverá en dict)
      - dict con clave 'scan_results' (como anidado o alias)
    """
    # Aceptar diferentes formas de entrada
    if isinstance(scan_results, dict) and 'scan_results' in scan_results and 'results' not in scan_results:
        scan_results = scan_results['scan_results']
    if isinstance(scan_results, list):
        scan_results = {'results': scan_results}

    # Timestamp
    scan_results['generated_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Calcular estadísticas
    scan_results['stats'] = _compute_stats(scan_results)

    pdf = ReportPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Resumen
    pdf.section_title(_safe_text('Resumen del Escaneo'))
    pdf.add_key_value('Fecha de generación', _safe_text(scan_results['generated_date']))
    pdf.add_key_value('Páginas analizadas', _safe_text(scan_results['stats']['total_pages']))
    pdf.add_key_value('Vulnerabilidades totales', _safe_text(scan_results['stats']['total_vulnerabilities']))
    pdf.add_key_value('Altas', _safe_text(scan_results['stats']['high_vulnerabilities']))
    pdf.add_key_value('Medias', _safe_text(scan_results['stats']['medium_vulnerabilities']))
    pdf.add_key_value('Bajas', _safe_text(scan_results['stats']['low_vulnerabilities']))
    pdf.ln(4)

    # Resumen por tipo (si existe)
    type_counts = scan_results['stats'].get('type_counts') or {}
    if type_counts:
        pdf.section_title(_safe_text('Resumen por tipo de vulnerabilidad'))
        # Mostrar top 10 tipos ordenados por frecuencia
        for t, c in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            pdf.add_key_value(_safe_text(t), _safe_text(c))
        pdf.ln(2)

    # Detalle por página
    for idx, page in enumerate(scan_results.get('results', []), start=1):
        pdf.section_title(_safe_text(f'Página {idx}: {page.get("url", "(sin URL)")}'))
        metrics = page.get('metrics', {})
        if metrics:
            risk = metrics.get('risk_level', 'N/A')
            duration = metrics.get('scan_duration', 'N/A')
            pdf.add_key_value('Riesgo de la página', _safe_text(risk))
            pdf.add_key_value('Duración del escaneo (s)', _safe_text(duration))
        vulns = page.get('vulnerabilities', [])
        if not vulns:
            pdf.set_font('Helvetica', 'I', 9)
            pdf.multi_cell(pdf.epw, 6, _safe_text('Sin vulnerabilidades reportadas en esta página.'))
            pdf.ln(2)
        else:
            for v_i, vuln in enumerate(vulns, start=1):
                pdf.add_vulnerability(v_i, vuln)

    # Salida
    # Usar ruta absoluta al directorio raíz del proyecto (un nivel arriba de 'escaner')
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir = os.path.join(base_dir, 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    output_path = os.path.join(reports_dir, f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
    pdf.output(output_path)
    return output_path