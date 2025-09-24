from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
from scanner import SecurityScanner
from crawler import WebCrawler, scan_multiple_urls
from report_generator import generate_pdf_report
import json
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Habilitar CORS para todas las rutas

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        scanner = SecurityScanner(url)
        results = scanner.scan()
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/multi-scan', methods=['POST'])
def multi_scan():
    data = request.json
    urls = data.get('urls', [])
    max_pages = data.get('max_pages', 10)
    deep_scan = data.get('deep_scan', False)
    crawl_links = data.get('crawl_links', False)
    
    if not urls:
        return jsonify({'error': 'At least one URL is required'}), 400
    
    all_results = []
    
    try:
        if deep_scan and crawl_links:
            # Escaneo profundo con crawling para cada URL
            for base_url in urls:
                crawler = WebCrawler(base_url, max_pages)
                page_results = crawler.crawl()
                all_results.extend(page_results)
        else:
            # Escaneo de múltiples URLs sin crawling
            all_results = scan_multiple_urls(urls)
        
        return jsonify({
            'total_pages': len(all_results),
            'results': all_results
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-report', methods=['POST'])
def generate_report():
    data = request.json or {}
    # Acepta 'scan_results' o directamente 'results'
    scan_results = data.get('scan_results') or data.get('results')
    if not scan_results:
        return jsonify({'error': 'scan_results or results field is required'}), 400
    try:
        pdf_path = generate_pdf_report(scan_results)
        return send_file(pdf_path, as_attachment=True, download_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Crear directorio para reportes si no existe
    os.makedirs('reports', exist_ok=True)
    app.run(debug=True, port=5000)

