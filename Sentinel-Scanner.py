import requests
from requests.auth import HTTPBasicAuth
import sqlite3
import hashlib
import logging
from xml.etree import ElementTree as ET
from urllib.parse import urljoin
import time
import tempfile
import os

# Configuración de logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SentinelScanner:
    def __init__(self, ip, puerto, usuario, contraseña, db_path=None):
        """
        Inicializa el escáner con los datos de conexión al servidor WebDAV.
        :param ip: Dirección IP del servidor (ej. '192.168.1.7')
        :param puerto: Puerto del servidor (ej. 8080)
        :param usuario: Nombre de usuario para autenticación
        :param contraseña: Contraseña para autenticación
        :param db_path: Ruta del archivo de base de datos SQLite (opcional, por defecto en carpeta temporal)
        """
        self.base_url = f"http://{ip}:{puerto}/"
        self.auth = HTTPBasicAuth(usuario, contraseña)
        
        if db_path is None:
            db_path = os.path.join(tempfile.gettempdir(), 'sentinel.db')
        self.db_path = db_path
        
        self._inicializar_bd()
        logger.info(f"Escáner inicializado para {self.base_url}")
        logger.info(f"Base de datos en: {self.db_path}")

    def _inicializar_bd(self):
        """Crea las tablas en la base de datos si no existen."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS archivos (
                hash_id TEXT PRIMARY KEY,
                nombre TEXT,
                tamano_bytes INTEGER,
                fecha_escaneo TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ubicaciones (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash_id TEXT,
                ruta_remota TEXT,
                FOREIGN KEY (hash_id) REFERENCES archivos(hash_id)
            )
        ''')
        conn.commit()
        conn.close()
        logger.info("Base de datos inicializada.")

    def _generar_hash_streaming(self, url, tamano=None, max_size_mb=500):
        """
        Calcula el hash SHA-256 de un archivo descargándolo en streaming.
        :param url: URL completa del archivo
        :param tamano: Tamaño del archivo (opcional, para filtro)
        :param max_size_mb: Tamaño máximo en MB para procesar
        :return: Hash hexadecimal o None si hay error
        """
        if tamano and tamano > max_size_mb * 1024 * 1024:
            logger.warning(f"Archivo de {tamano/1024/1024:.2f} MB supera el límite de {max_size_mb} MB, se omite hash.")
            return None

        sha256_hash = hashlib.sha256()
        for intento in range(1, 4):
            try:
                with requests.get(url, auth=self.auth, stream=True, timeout=(15, 60)) as r:
                    r.raise_for_status()
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            sha256_hash.update(chunk)
                return sha256_hash.hexdigest()
            except requests.exceptions.RequestException as e:
                logger.warning(f"Intento {intento} falló al obtener hash de {url}: {e}")
                if intento == 3:
                    logger.error(f"Se agotaron los reintentos para {url}")
                    return None
                time.sleep(2 ** intento)

    def _obtener_tamano(self, url):
        """
        Obtiene el tamaño de un archivo mediante una petición HEAD.
        :param url: URL completa del archivo
        :return: Tamaño en bytes, o 0 si hay error
        """
        try:
            response = requests.head(url, auth=self.auth, timeout=10)
            response.raise_for_status()
            return int(response.headers.get('Content-Length', 0))
        except requests.exceptions.RequestException as e:
            logger.error(f"Error al obtener tamaño de {url}: {e}")
            return 0

    def _obtener_hash_y_tamano_por_ruta(self, ruta):
        """
        Consulta la BD y devuelve el hash y tamaño almacenados para una ruta dada.
        Retorna (hash_id, tamano_bytes) o (None, None) si no existe.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT a.hash_id, a.tamano_bytes
            FROM archivos a
            JOIN ubicaciones u ON a.hash_id = u.hash_id
            WHERE u.ruta_remota = ?
        ''', (ruta,))
        fila = cursor.fetchone()
        conn.close()
        if fila:
            return fila[0], fila[1]
        return None, None

    def _peticion_con_reintentos(self, url, headers, max_reintentos=3):
        """
        Realiza una petición PROPFIND con reintentos ante fallos de red.
        :param url: URL a consultar
        :param headers: Cabeceras HTTP (ej. {'Depth': '1'})
        :param max_reintentos: Número máximo de reintentos
        :return: Respuesta de requests si tiene éxito, o lanza excepción
        """
        for intento in range(1, max_reintentos + 1):
            try:
                logger.debug(f"Intento {intento} para {url}")
                response = requests.request('PROPFIND', url, auth=self.auth, headers=headers, timeout=10)
                response.raise_for_status()
                return response
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                logger.warning(f"Intento {intento} falló para {url}: {e}")
                if intento == max_reintentos:
                    logger.error(f"Se agotaron los reintentos para {url}")
                    raise
                tiempo_espera = 2 ** (intento - 1)
                logger.info(f"Reintentando en {tiempo_espera} segundos...")
                time.sleep(tiempo_espera)
            except requests.exceptions.HTTPError as e:
                logger.error(f"Error HTTP {e.response.status_code} en {url}")
                raise

    def _registrar_archivo(self, hash_id, nombre, tamano, ruta):
        """
        Inserta un archivo en la base de datos si no existe, y añade su ubicación.
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO archivos (hash_id, nombre, tamano_bytes)
                VALUES (?, ?, ?)
            ''', (hash_id, nombre, tamano))
            cursor.execute('''
                INSERT OR IGNORE INTO ubicaciones (hash_id, ruta_remota)
                VALUES (?, ?)
            ''', (hash_id, ruta))
            conn.commit()
            conn.close()
            logger.debug(f"Registrado: {ruta} con hash {hash_id[:8]}...")
        except sqlite3.Error as e:
            logger.error(f"Error de base de datos al registrar {ruta}: {e}")

    def _listar_archivos_webdav_recursivo(self, url, visitadas, rutas_actuales):
        """
        Escanea recursivamente un directorio WebDAV y registra los archivos en la BD.
        :param url: URL de la carpeta a escanear
        :param visitadas: Conjunto de URLs ya procesadas (para evitar ciclos)
        :param rutas_actuales: Conjunto donde se guardan las rutas de archivos encontradas
        :return: Lista de rutas de archivos encontrados en esta carpeta (opcional)
        """
        if not url.endswith('/'):
            url += '/'

        if url in visitadas:
            logger.debug(f"Carpeta ya visitada, omitiendo: {url}")
            return []

        visitadas.add(url)
        logger.info(f"Escaneando carpeta: {url}")

        headers = {'Depth': '1'}
        try:
            response = self._peticion_con_reintentos(url, headers)
            namespace = '{DAV:}'
            tree = ET.fromstring(response.content)
            responses = tree.findall(f'.//{namespace}response')

            archivos = []
            subcarpetas = []

            for resp in responses:
                href_elem = resp.find(f'{namespace}href')
                if href_elem is not None:
                    href = href_elem.text
                    if href and not href.endswith('/'):
                        # Es un archivo
                        archivos.append(href)
                        rutas_actuales.add(href)
                        url_completa = urljoin(url, href)
                        nombre = href.split('/')[-1]

                        tamano = self._obtener_tamano(url_completa)
                        if tamano == 0:
                            logger.warning(f"No se pudo obtener tamaño de {href}, se omite.")
                            continue

                        hash_almacenado, tamano_almacenado = self._obtener_hash_y_tamano_por_ruta(href)

                        if hash_almacenado and tamano_almacenado == tamano:
                            logger.debug(f"Archivo sin cambios, se omite hash: {href}")
                        else:
                            hash_val = self._generar_hash_streaming(url_completa, tamano=tamano)
                            if hash_val:
                                self._registrar_archivo(hash_val, nombre, tamano, href)

                    elif href and href != url:
                        subcarpetas.append(href)
                        logger.debug(f"Subcarpeta encontrada: {href}")

            for subcarpeta in subcarpetas:
                sub_url = urljoin(url, subcarpeta)
                self._listar_archivos_webdav_recursivo(sub_url, visitadas, rutas_actuales)

            logger.info(f"Carpeta {url} procesada. {len(archivos)} archivos encontrados.")
            return archivos

        except requests.exceptions.RequestException as e:
            logger.error(f"Error crítico en {url}: {e}")
            return []

    def _limpiar_rutas_huerfanas(self, rutas_actuales):
        """
        Elimina de la BD las rutas que ya no existen en el sistema de archivos.
        Luego, elimina los archivos que no tienen ninguna ubicación.
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT ruta_remota FROM ubicaciones')
            rutas_bd = set(row[0] for row in cursor.fetchall())
            rutas_huerfanas = rutas_bd - rutas_actuales

            if rutas_huerfanas:
                logger.info(f"Eliminando {len(rutas_huerfanas)} rutas huérfanas...")
                for ruta in rutas_huerfanas:
                    cursor.execute('DELETE FROM ubicaciones WHERE ruta_remota = ?', (ruta,))
                conn.commit()
                logger.debug(f"Rutas eliminadas: {', '.join(rutas_huerfanas)}")
            else:
                logger.info("No hay rutas huérfanas.")

            cursor.execute('''
                DELETE FROM archivos
                WHERE hash_id NOT IN (SELECT DISTINCT hash_id FROM ubicaciones)
            ''')
            conn.commit()
            eliminados = cursor.rowcount
            if eliminados:
                logger.info(f"Se eliminaron {eliminados} archivos huérfanos (sin ubicaciones).")
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"Error al limpiar rutas huérfanas: {e}")

    def escanear(self):
        """
        Método público que inicia el escaneo desde la URL base.
        Crea un conjunto de carpetas visitadas y otro de rutas actuales.
        Al finalizar, limpia rutas huérfanas y muestra el reporte de duplicados.
        """
        logger.info("Iniciando escaneo desde la raíz...")
        visitadas = set()
        rutas_actuales = set()
        self._listar_archivos_webdav_recursivo(self.base_url, visitadas, rutas_actuales)
        logger.info("Escaneo finalizado. Limpiando rutas huérfanas...")
        self._limpiar_rutas_huerfanas(rutas_actuales)
        logger.info("Generando reporte de duplicados...")
        self.reportar_duplicados()

    def reportar_duplicados(self):
        """
        Consulta la base de datos y muestra los archivos duplicados.
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT a.hash_id, a.nombre, a.tamano_bytes, u.ruta_remota
                FROM archivos a
                JOIN ubicaciones u ON a.hash_id = u.hash_id
                WHERE a.hash_id IN (
                    SELECT hash_id
                    FROM ubicaciones
                    GROUP BY hash_id
                    HAVING COUNT(*) > 1
                )
                ORDER BY a.hash_id, u.ruta_remota
            ''')
            filas = cursor.fetchall()
            conn.close()

            if not filas:
                print("\nNo se encontraron archivos duplicados.")
                return

            duplicados = {}
            for hash_id, nombre, tamano, ruta in filas:
                if hash_id not in duplicados:
                    duplicados[hash_id] = {
                        'nombre': nombre,
                        'tamano': tamano,
                        'rutas': []
                    }
                duplicados[hash_id]['rutas'].append(ruta)

            print("\n=== ARCHIVOS DUPLICADOS ENCONTRADOS ===")
            for hash_id, datos in duplicados.items():
                print(f"Hash: {hash_id[:8]}... ({datos['nombre']}) - Tamaño: {datos['tamano']} bytes")
                for ruta in datos['rutas']:
                    print(f"  - {ruta}")
                print()
        except sqlite3.Error as e:
            logger.error(f"Error al consultar duplicados: {e}")

if __name__ == '__main__':
    IP = '192.168.1.7'
    PUERTO = 8080
    USUARIO = 'admin'
    CONTRASENA = 'admin'

    scanner = SentinelScanner(IP, PUERTO, USUARIO, CONTRASENA)
    scanner.escanear()
