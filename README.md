# Proyecto Ciberseguridad

Aplicación Flask para escanear URLs básicas y generar reportes PDF de vulnerabilidades encontradas.

## Requisitos previos

- Windows 10/11
- Python 3.11+ instalado (agregado al PATH) 
- PowerShell (ejecutar como usuario normal está bien)

## Puesta en marcha rápida (opción A: manual mínima)

En PowerShell dentro de la carpeta del proyecto (este README):

```powershell
python -m venv .venv
./.venv/Scripts/Activate.ps1
python -m pip install --upgrade pip
pip install -r escaner/requirements.txt
python escaner/app.py
```

Abre el navegador: http://127.0.0.1:5000

Si PowerShell bloquea la activación (ExecutionPolicy), puedes permitir scripts SOLO en esta sesión:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## Puesta en marcha recomendada (opción B: script automatizado)

Ejecuta el script que hace todo por ti (crea entorno, instala dependencias e inicia la app):

```powershell
./run.ps1
```

Si aparece error de ejecución de scripts, antes:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; ./run.ps1
```

El script hará:
1. Verificar que exista Python en PATH
2. Crear `.venv` si no existe
3. Activar el entorno
4. Actualizar pip e instalar requirements
5. Lanzar la aplicación en `http://127.0.0.1:5000`

### ¿No tienes Python instalado?
1. Descarga desde: https://www.python.org/downloads/
2. Marca la casilla "Add python to PATH" en el instalador
3. Cierra y vuelve a abrir la ventana de PowerShell
4. Repite los pasos (opción A o B)

## Estructura del proyecto

```
escaner/
	app.py                # Punto de entrada Flask
	scanner.py            # Lógica de escaneo (XSS, headers, etc.)
	crawler.py            # Crawling opcional de sitios
	report_generator.py   # Generación de PDF (fpdf2)
	templates/            # HTML, JS, CSS
```

## Generación de reporte PDF

El endpoint POST `/api/generate-report` recibe un JSON con `scan_results` o `results` y devuelve un PDF descargable. Los PDF se guardan también en `reports/`.

## Notas sobre dependencias

El paquete `fpdf2` proporciona la clase `FPDF`. Si hubiera errores instalando dependencias en un Python tipo MSYS/MinGW, usa el Python oficial de python.org.

## Problemas comunes

- Error: `No module named fpdf` -> Ejecuta de nuevo `pip install fpdf2` dentro del entorno virtual activo.
- Error ExecutionPolicy al activar -> Usa el comando Set-ExecutionPolicy mostrado arriba.
- Puerto ocupado 5000 -> Cambia el puerto en `app.py` (última línea `app.run(...)`).

## Comando alternativo sin activar (one-liner)

```powershell
python -m venv .venv; ./.venv/Scripts/python.exe -m pip install -r escaner/requirements.txt; ./.venv/Scripts/python.exe escaner/app.py
```

---

Enjoy / Disfruta :)