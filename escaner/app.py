from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
from scanner import SecurityScanner
from crawler import WebCrawler, scan_multiple_urls
from concurrent.futures import ThreadPoolExecutor, as_completed
from report_generator import generate_pdf_report
import os
from datetime import datetime
import requests
from werkzeug.exceptions import HTTPException

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
    except requests.RequestException as e:
        return jsonify({'error': f'Request error: {str(e)}'}), 502
    except HTTPException as e:
        return jsonify({'error': e.description}), e.code

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
            # Escaneo profundo con crawling para cada URL en paralelo
            def do_crawl(u):
                crawler = WebCrawler(u, max_pages)
                return crawler.crawl()

            with ThreadPoolExecutor(max_workers=min(4, max(1, len(urls)))) as ex:
                futures = [ex.submit(do_crawl, u) for u in urls]
                for fut in as_completed(futures):
                    res = fut.result()
                    all_results.extend(res)
        else:
            # Escaneo de múltiples URLs sin crawling (paralelizado en crawler.scan_multiple_urls)
            all_results = scan_multiple_urls(urls)
        
        return jsonify({
            'total_pages': len(all_results),
            'results': all_results
        })
    except requests.RequestException as e:
        return jsonify({'error': f'Request error: {str(e)}'}), 502
    except HTTPException as e:
        return jsonify({'error': e.description}), e.code

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
    except (OSError, ValueError, RuntimeError) as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Crear directorio para reportes si no existe
    os.makedirs('reports', exist_ok=True)
    app.run(debug=True, port=5000)

