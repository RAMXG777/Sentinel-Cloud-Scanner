# Sentinel-Cloud-Scanner

A Python-based scanner that connects to a WebDAV server (e.g., from a mobile device) to analyze folders and subfolders for duplicate files. It utilizes SHA-256 streaming hashing to identify duplicates efficiently, even with large files. The system reports their location and size, helping to free up unnecessary storage space.

Un escáner en Python que se conecta a un servidor WebDAV (por ejemplo, desde un dispositivo móvil) para analizar carpetas y subcarpetas en busca de archivos duplicados. Utiliza hashing SHA-256 en streaming para identificar duplicados de forma eficiente, incluso con archivos grandes. El sistema informa su ubicación y tamaño, ayudando a liberar espacio de almacenamiento innecesario.

---

## Características principales

- **Registro profesional (logging):** Uso de `logging.debug`, `info`, `warning` y `error` para registrar toda la actividad del programa, facilitando la depuración y el seguimiento de errores.
- **Diseño orientado a objetos:** Implementación de la clase `SentinelScanner` que encapsula los atributos (URL, autenticación, ruta de base de datos) y métodos, permitiendo una fácil escalabilidad y mantenimiento del código.
- **Base de datos SQLite local:** Creación de una base de datos con dos tablas normalizadas (`archivos` y `ubicaciones`) y uso de claves foráneas para relacionar la identidad del archivo (hash) con sus múltiples ubicaciones.
- **Hashing SHA-256 en streaming:** Cálculo del hash de cada archivo sin cargarlo completamente en memoria, dividiendo el contenido en fragmentos (chunks) para optimizar la transferencia y evitar saturar la RAM, incluso con archivos de gran tamaño.
- **Filtro opcional por tamaño:** Permite omitir archivos mayores a un límite configurable (por defecto 500 MB) para acelerar el escaneo en dispositivos con recursos limitados.
- **Optimización de escaneos:** Antes de calcular un hash, consulta la base de datos para verificar si el archivo ya fue procesado y no ha cambiado (comparando tamaño), evitando trabajo redundante.
- **Limpieza automática de rutas huérfanas:** Detecta y elimina de la base de datos las rutas que ya no existen en el servidor WebDAV, manteniendo la información siempre actualizada.
- **Manejo de errores de red con reintentos:** Implementa reintentos con backoff exponencial ante fallos de conexión o timeouts, lo que hace al escáner robusto en redes inestables.
- **Reporte detallado de duplicados:** Al finalizar el escaneo, genera un informe legible con todos los archivos duplicados, mostrando su tamaño y las distintas rutas donde se encuentran, para facilitar la limpieza manual.

---

## Key Features

- **Professional logging:** Uses `logging.debug`, `info`, `warning`, and `error` to record all program activity, making debugging and error tracking straightforward.
- **Object‑oriented design:** Implements a `SentinelScanner` class that encapsulates core attributes (URL, authentication, database path) and methods, ensuring clean scalability and maintainability.
- **Local SQLite database:** Creates a normalized two‑table database (`archivos` and `ubicaciones`) with foreign keys to link a file’s identity (hash) with its multiple locations.
- **Streaming SHA-256 hashing:** Calculates file hashes without loading entire files into memory by reading them in chunks, optimising data transfer and preventing RAM overload even for very large files.
- **Configurable size filter:** Optionally skips files larger than a user‑defined limit (default 500 MB), speeding up scans on resource‑constrained devices.
- **Scan optimisation:** Before hashing, it queries the database to check whether a file has already been processed and unchanged (by comparing size), avoiding redundant work.
- **Automatic orphaned path cleanup:** Detects and removes from the database any paths that no longer exist on the WebDAV server, keeping the information up‑to‑date.
- **Network error handling with retries:** Implements exponential backoff retries for connection failures or timeouts, making the scanner resilient on unstable networks.
- **Detailed duplicate report:** After scanning, produces a clear, human‑readable report listing all duplicate files, their sizes, and every path where they reside, helping you manually reclaim storage space.

---

## Requisitos

- **Versión de Python:** 3.6 o superior.
- **Paquetes externos:** `requests` (instalable vía `pip install requests`).
- **Servidor WebDAV:** Una aplicación en tu dispositivo móvil que actúe como servidor WebDAV (por ejemplo, "WebDAV Server" o "MiXplorer" con el plugin correspondiente). Debe estar configurada con IP fija, puerto, usuario y contraseña.
- **Espacio en disco:** Suficiente para la base de datos SQLite (el tamaño dependerá de la cantidad de archivos escaneados).

---

## Requirements

- **Python version:** 3.6 or higher.
- **External packages:** `requests` (install via `pip install requests`).
- **WebDAV server:** An app on your mobile device that acts as a WebDAV server (e.g., "WebDAV Server" or "MiXplorer" with the appropriate plugin). It must be configured with a static IP, port, username, and password.
- **Disk space:** Enough for the SQLite database (size depends on the number of files scanned).

---

## Instalación

### 1. Instalar Python
El escáner requiere Python 3.6 o superior.

**Linux (Ubuntu/Debian):**
```bash
sudo apt update && sudo apt install python3 python3-pip -y

Windows:
Descarga el instalador desde python.org.
Asegúrate de marcar la opción "Add Python to PATH" durante la instalación.

2. Instalar dependencias
Este proyecto utiliza la librería requests para la comunicación WebDAV.

bash
pip install requests
3. Configurar el servidor WebDAV
Instala una aplicación de servidor WebDAV en tu dispositivo móvil o PC (por ejemplo, "WebDAV Server" en Android).

Anota tu dirección IP, puerto y credenciales.

Edita las siguientes líneas en scanner.py con tus datos:

python
IP = 'TU_IP_AQUI'
PUERTO = 8080
USUARIO = 'tu_usuario'
CONTRASENA = 'tu_contraseña'
Installation
1. Install Python
The scanner requires Python 3.6 or higher.

Linux (Ubuntu/Debian):

bash
sudo apt update && sudo apt install python3 python3-pip -y
Windows:
Download the installer from python.org.
Make sure to check "Add Python to PATH" during setup.

2. Install Dependencies
This project uses the requests library for WebDAV communication.

bash
pip install requests
3. Server Configuration
Install a WebDAV Server app on your mobile device or PC (e.g., "WebDAV Server" on Android).

Note your IP address, port, and credentials.

Edit the following lines in scanner.py with your data:

python
IP = 'YOUR_IP_HERE'
PUERTO = 8080
USUARIO = 'your_user'
CONTRASENA = 'your_password'
Solución de problemas / Troubleshooting
Revisa la documentación – consulta rápidamente este README para verificar la configuración.

Verifica la conexión WebDAV – asegúrate de que el servidor esté activo y que la IP, puerto, usuario y contraseña sean correctos.

Inspecciona los logs – observa la salida en consola y el archivo scanner.log; los mensajes de error suelen indicar la causa.

Consulta a una IA o busca en línea – si el error persiste, pega el mensaje de error en un buscador o pide ayuda a una IA.

Check the documentation – quickly review this README for setup instructions.

Verify the WebDAV connection – ensure your server is running, and the IP, port, username, and password are correct.

Inspect the logs – look at the console output and the scanner.log file; error messages usually point to the issue.

Consult an AI or search online – if the error persists, paste the error message into a search engine or ask an AI for help.

Estructura del proyecto / Project Structure
Una vez que tengas todo configurado, la carpeta de tu proyecto tendrá esta estructura:

text
sentinel-cloud-scanner/
├── sentinel_scanner.py      # Script principal que contiene la clase SentinelScanner
├── scanner.log              # Archivo de log generado automáticamente al ejecutar
├── sentinel.db              # Base de datos SQLite (se crea en el primer escaneo)
└── README.md                # Este archivo de documentación
Once you have everything set up, your project folder will look like this:

text
sentinel-cloud-scanner/
├── sentinel_scanner.py      # Main script containing the SentinelScanner class
├── scanner.log              # Log file automatically generated after running
├── sentinel.db              # SQLite database (created on first scan)
└── README.md                # This documentation file
Explicación breve / Brief explanation
sentinel_scanner.py – Contiene toda la lógica del escáner, incluyendo la clase principal y los métodos auxiliares.

scanner.log – Registro detallado de cada ejecución, útil para depurar errores.

sentinel.db – Almacena los hashes, nombres, tamaños y ubicaciones de los archivos escaneados.

README.md – Instrucciones y documentación del proyecto.

sentinel_scanner.py – Contains all the scanner logic, including the main class and helper methods.

scanner.log – Detailed log of each run, useful for debugging errors.

sentinel.db – Stores the hashes, names, sizes, and locations of scanned files.

README.md – Instructions and project documentation.

Reporte detallado de duplicados: Al finalizar el escaneo, genera un informe legible con todos los archivos duplicados, mostrando su tamaño y las distintas rutas donde se encuentran, para facilitar la limpieza manual.
