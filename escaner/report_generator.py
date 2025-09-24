from fpdf import FPDF
import os
from datetime import datetime


class ReportPDF(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 14)
        self.cell(0, 10, 'Informe de Escaneo de Seguridad', 0, 1, 'C')
        self.set_draw_color(50, 50, 50)
        self.set_line_width(0.4)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'Página {self.page_no()}', 0, 0, 'C')

    def section_title(self, title):
        self.set_font('Helvetica', 'B', 12)
        self.set_fill_color(230, 230, 230)
        self.cell(0, 8, title, 0, 1, 'L', True)
        self.ln(2)

    def add_key_value(self, key, value):
        self.set_font('Helvetica', '', 10)
        self.multi_cell(0, 6, f'{key}: {value}')

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
        self.multi_cell(0, 6, f'{idx}. {vuln.get("type", "Vulnerabilidad")}  (Severidad: {sev})')
        self.set_text_color(0, 0, 0)
        self.set_font('Helvetica', '', 9)
        if vuln.get('description'):
            self.multi_cell(0, 5, f'Descripción: {vuln.get("description")}')
        if vuln.get('details'):
            self.multi_cell(0, 5, f'Detalles: {vuln.get("details")}')
        if vuln.get('payload'):
            self.multi_cell(0, 5, f'Payload: {vuln.get("payload")}')
        self.ln(2)


def _compute_stats(scan_results_dict):
    total_vulns = 0
    sev_counts = {'high': 0, 'medium': 0, 'low': 0}
    for page in scan_results_dict.get('results', []):
        vulns = page.get('vulnerabilities', [])
        total_vulns += len(vulns)
        for v in vulns:
            sev = v.get('severity', '').lower()
            if sev in sev_counts:
                sev_counts[sev] += 1
    return {
        'total_pages': len(scan_results_dict.get('results', [])),
        'total_vulnerabilities': total_vulns,
        'high_vulnerabilities': sev_counts['high'],
        'medium_vulnerabilities': sev_counts['medium'],
        'low_vulnerabilities': sev_counts['low']
    }


def generate_pdf_report(scan_results):
    """Genera un PDF a partir de los resultados del escaneo.

    scan_results puede ser:
      - dict con clave 'results'
      - lista de páginas (se envolverá en dict)
    """
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
    pdf.section_title('Resumen del Escaneo')
    pdf.add_key_value('Fecha de generación', scan_results['generated_date'])
    pdf.add_key_value('Páginas analizadas', scan_results['stats']['total_pages'])
    pdf.add_key_value('Vulnerabilidades totales', scan_results['stats']['total_vulnerabilities'])
    pdf.add_key_value('Altas', scan_results['stats']['high_vulnerabilities'])
    pdf.add_key_value('Medias', scan_results['stats']['medium_vulnerabilities'])
    pdf.add_key_value('Bajas', scan_results['stats']['low_vulnerabilities'])
    pdf.ln(4)

    # Detalle por página
    for idx, page in enumerate(scan_results.get('results', []), start=1):
        pdf.section_title(f'Página {idx}: {page.get("url", "(sin URL)")}')
        vulns = page.get('vulnerabilities', [])
        if not vulns:
            pdf.set_font('Helvetica', 'I', 9)
            pdf.multi_cell(0, 6, 'Sin vulnerabilidades reportadas en esta página.')
            pdf.ln(2)
        else:
            for v_i, vuln in enumerate(vulns, start=1):
                pdf.add_vulnerability(v_i, vuln)

    # Salida
    os.makedirs('reports', exist_ok=True)
    output_path = f"reports/security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(output_path)
    return output_path