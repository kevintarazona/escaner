document.addEventListener('DOMContentLoaded', function() {
            const scanButton = document.getElementById('scan-button');
            const addUrlBtn = document.getElementById('add-url-btn');
            const urlInputsContainer = document.getElementById('url-inputs');
            const progressBar = document.getElementById('progress-bar');
            const progressStatus = document.getElementById('progress-status');
            const progressPercentage = document.getElementById('progress-percentage');
            const resultsSection = document.getElementById('results-section');
            const scanAnimation = document.getElementById('scan-animation');
            const showReportButton = document.getElementById('show-report');
            const reportSection = document.getElementById('report-section');
            const backToResults = document.getElementById('back-to-results');
            const vulnTableBody = document.getElementById('vuln-table-body');
            const vulnDetails = document.getElementById('vuln-details');
            const pageList = document.getElementById('page-list');
            
            // Sample vulnerabilities data
            const vulnerabilities = [
                {
                    name: "Cross-Site Scripting (XSS)",
                    risk: "high",
                    description: "Entrada de usuario no sanitizada en el parámetro 'search'",
                    details: "La aplicación no sanitiza adecuadamente la entrada del usuario en el parámetro 'search', lo que permite la inyección de JavaScript arbitrario."
                },
                {
                    name: "CSRF Protection Missing",
                    risk: "medium",
                    description: "Falta de tokens CSRF en formularios críticos",
                    details: "El formulario de cambio de contraseña no incluye tokens CSRF, lo que podría permitir a un atacante realizar cambios sin consentimiento del usuario."
                },
                {
                    name: "Clickjacking",
                    risk: "medium",
                    description: "Cabeceras X-Frame-Options missing",
                    details: "La aplicación no incluye la cabecera X-Frame-Options, lo que podría permitir que la página sea embebida en un iframe y sea vulnerable a clickjacking."
                },
                {
                    name: "Exposure of Sensitive Information",
                    risk: "low",
                    description: "Rutas de directorio expuestas en respuesta HTTP",
                    details: "Las respuestas del servidor incluyen rutas de directorio internas en los headers, lo que podría revelar información sobre la estructura del sistema."
                }
            ];
            
            // Add new URL input field
            addUrlBtn.addEventListener('click', function() {
                const newInputGroup = document.createElement('div');
                newInputGroup.className = 'url-input-group';
                newInputGroup.innerHTML = `
                    <input type="url" class="target-url" placeholder="https://example.com" value="https://">
                    <button class="remove-url"><i class="fas fa-times"></i></button>
                `;
                urlInputsContainer.appendChild(newInputGroup);
                
                // Add event to remove button
                newInputGroup.querySelector('.remove-url').addEventListener('click', function() {
                    if (urlInputsContainer.children.length > 1) {
                        urlInputsContainer.removeChild(newInputGroup);
                    }
                });
            });
            
            // Add event to initial remove button
            document.querySelector('.remove-url').addEventListener('click', function() {
                if (urlInputsContainer.children.length > 1) {
                    urlInputsContainer.removeChild(this.parentElement);
                }
            });
            
            // Populate vulnerabilities table
            function populateVulnerabilities() {
                vulnTableBody.innerHTML = '';
                
                // Simulate vulnerabilities for multiple pages
                const pageUrls = Array.from(document.querySelectorAll('.target-url'))
                    .map(input => input.value)
                    .filter(url => url && url !== 'https://');
                
                pageUrls.forEach((url, index) => {
                    // Add 1-3 vulnerabilities per page
                    const vulnCount = Math.floor(Math.random() * 3) + 1;
                    
                    for (let i = 0; i < vulnCount; i++) {
                        const vuln = vulnerabilities[Math.floor(Math.random() * vulnerabilities.length)];
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${url}</td>
                            <td>${vuln.name}</td>
                            <td><span class="risk-${vuln.risk}">${vuln.risk.toUpperCase()}</span></td>
                            <td>${vuln.description}</td>
                        `;
                        vulnTableBody.appendChild(row);
                    }
                });
                
                // Update summary
                document.getElementById('pages-scanned').textContent = pageUrls.length;
                document.getElementById('total-vulnerabilities').textContent = vulnTableBody.children.length;
                document.getElementById('report-pages').textContent = pageUrls.length;
                document.getElementById('report-total-vulns').textContent = vulnTableBody.children.length;
                
                // Populate report details
                vulnDetails.innerHTML = '';
                pageUrls.forEach((url, index) => {
                    const pageSection = document.createElement('div');
                    pageSection.innerHTML = `<h4>Página: ${url}</h4>`;
                    vulnDetails.appendChild(pageSection);
                    
                    // Add 1-3 vulnerabilities per page
                    const vulnCount = Math.floor(Math.random() * 3) + 1;
                    
                    for (let i = 0; i < vulnCount; i++) {
                        const vuln = vulnerabilities[Math.floor(Math.random() * vulnerabilities.length)];
                        const detailDiv = document.createElement('div');
                        detailDiv.className = 'vuln-detail';
                        detailDiv.innerHTML = `
                            <h4>${vuln.name} - <span class="risk-${vuln.risk}">${vuln.risk.toUpperCase()}</span></h4>
                            <p><strong>Descripción:</strong> ${vuln.description}</p>
                            <p><strong>Detalles:</strong> ${vuln.details}</p>
                            <p><strong>Recomendación:</strong> Implementar sanitización de entrada, validar y codificar salida.</p>
                        `;
                        vulnDetails.appendChild(detailDiv);
                    }
                });
            }
            
            // Simulate scanning process for multiple pages
            scanButton.addEventListener('click', function() {
                const pageUrls = Array.from(document.querySelectorAll('.target-url'))
                    .map(input => input.value)
                    .filter(url => url && url !== 'https://');
                
                if (pageUrls.length === 0) {
                    alert('Por favor, introduce al menos una URL válida');
                    return;
                }
                
                // Reset UI
                progressBar.style.width = '0%';
                progressPercentage.textContent = '0%';
                resultsSection.style.display = 'none';
                scanAnimation.style.display = 'block';
                
                // Clear page list
                pageList.innerHTML = '';
                
                // Add pages to list
                pageUrls.forEach(url => {
                    const pageItem = document.createElement('div');
                    pageItem.className = 'page-item';
                    pageItem.innerHTML = `
                        <div>${url}</div>
                        <div class="page-status">
                            <span class="status-icon status-queued"><i class="fas fa-clock"></i></span>
                            <span>En cola</span>
                        </div>
                    `;
                    pageList.appendChild(pageItem);
                });
                
                // Update status
                progressStatus.textContent = 'Iniciando escaneo multi-página...';
                
                // Simulate progress
                let progress = 0;
                const pageCount = pageUrls.length;
                let completedPages = 0;
                
                const interval = setInterval(() => {
                    progress += Math.random() * 5;
                    if (progress >= 100) {
                        progress = 100;
                        clearInterval(interval);
                        
                        // Show results
                        progressStatus.textContent = 'Escaneo completado';
                        scanAnimation.style.display = 'none';
                        resultsSection.style.display = 'block';
                        
                        // Update metrics with random values
                        document.getElementById('total-time').textContent = 
                            (Math.random() * 120 + 30).toFixed(0) + 's';
                        
                        // Set report details
                        const now = new Date();
                        document.getElementById('report-date').textContent = 
                            now.toLocaleDateString('es-ES', { day: 'numeric', month: 'long', year: 'numeric' });
                        document.getElementById('report-duration').textContent = 
                            '5 minutos 22 segundos';
                            
                        // Populate vulnerabilities
                        populateVulnerabilities();
                    }
                    
                    progressBar.style.width = progress + '%';
                    progressPercentage.textContent = Math.round(progress) + '%';
                    
                    // Update page statuses randomly
                    if (progress > 20 && completedPages < pageCount) {
                        const pages = pageList.querySelectorAll('.page-item');
                        if (Math.random() > 0.7) {
                            pages[completedPages].querySelector('.status-icon').className = 'status-icon status-scanning';
                            pages[completedPages].querySelector('.page-status span:last-child').textContent = 'Escaneando';
                            progressStatus.textContent = `Escaneando ${pageUrls[completedPages]}`;
                        }
                    }
                    
                    if (progress > 50 && completedPages < pageCount) {
                        const pages = pageList.querySelectorAll('.page-item');
                        if (Math.random() > 0.8) {
                            pages[completedPages].querySelector('.status-icon').className = 'status-icon status-completed';
                            pages[completedPages].querySelector('.page-status span:last-child').textContent = 'Completado';
                            completedPages++;
                        }
                    }
                    
                    // Update status messages during scan
                    if (progress < 30) {
                        progressStatus.textContent = 'Analizando estructura de las páginas...';
                    } else if (progress < 60) {
                        progressStatus.textContent = 'Testeando parámetros de entrada...';
                    } else if (progress < 90) {
                        progressStatus.textContent = 'Buscando vulnerabilidades XSS...';
                    } else {
                        progressStatus.textContent = 'Generando reporte multi-página...';
                    }
                }, 100);
            });
            
            // Show report section
            showReportButton.addEventListener('click', function() {
                resultsSection.style.display = 'none';
                reportSection.style.display = 'block';
            });
            
            // Back to results
            backToResults.addEventListener('click', function() {
                reportSection.style.display = 'none';
                resultsSection.style.display = 'block';
            });
            
            // Simulate PDF download
            document.getElementById('download-pdf').addEventListener('click', function() {
                alert('En una implementación real, esto descargaría un PDF con el reporte completo de múltiples páginas.');
            });
        });
