<p align="left">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="logo/fenreitsu-white.png">
    <source media="(prefers-color-scheme: light)" srcset="logo/fenreitsu.png">
    <img src="fenreitsu-white.png" width="64" height="64" ">
  </picture>
</p>

# Vulnet — Security Scanner CLI

Escáner de seguridad modular para terminal. Ejecuta **21 herramientas** de auditoría contra un objetivo (IP/dominio/URL) y exporta resultados a CSV y JSON.

---

## Requisitos

- **Python 3.8+**
- **Pip** para instalar dependencias
- Las herramientas de seguridad deben estar instaladas en el sistema (ver tabla abajo)

### Instalación de dependencias Python

```bash
pip install -r requirements.txt
```

---

## Health Check — ¿Qué significan los iconos?

Al arrancar, Vulnet analiza qué herramientas tienes instaladas y cuáles son compatibles con tu sistema operativo.

| Icono | Color | Significado |
|-------|-------|-------------|
| ✅ | Verde | Instalada y disponible para usar |
| ❌ | Amarillo | **Compatible con tu SO pero no instalada** — puedes descargarla e instalarla |
| ⛔ | Rojo | **No compatible con tu SO** — solo funciona en el otro sistema operativo |

### Ejemplo práctico

```
  ✅     Nmap                   ✅ Sí     ← Instalada y Windows compatible
  ❌     SQLmap                 ✅ Sí     ← No instalada, pero funcionaría en Windows
  ⛔     Hydra                  ❌ No     ← Solo Linux, no funcionará en Windows
```

---

## Lista completa de herramientas

### Funcionan en Windows 11 y Linux (11 herramientas)

| # | Herramienta | Descripción | Instalación / Descarga |
|---|-------------|-------------|------------------------|
| 1 | **Nmap** | Escaneo de puertos y servicios | [nmap.org](https://nmap.org/download.html) |
| 2 | **SQLmap** | Detección de inyección SQL automática | [sqlmap.org](https://sqlmap.org/) |
| 3 | **Dirsearch** | Fuzzing de directorios web | [github.com/maurosoria/dirsearch](https://github.com/maurosoria/dirsearch) |
| 4 | **WPScan** | Escáner de seguridad WordPress | [wpscan.com](https://wpscan.com/) |
| 5 | **SSLyze** | Análisis de configuración SSL/TLS | [github.com/nabla-c0d3/sslyze](https://github.com/nabla-c0d3/sslyze) |
| 6 | **Gobuster** | Fuerza bruta de directorios/DNS | [github.com/OJ/gobuster](https://github.com/OJ/gobuster) |
| 7 | **Amass** | Enumeración de subdominios y ASN | [github.com/owasp-amass/amass](https://github.com/owasp-amass/amass) |
| 8 | **Metasploit** | Framework de exploits y escaneo | [metasploit.com](https://www.metasploit.com/) |
| 9 | **ZAP** (OWASP) | Escáner de vulnerabilidades web | [zaproxy.org](https://www.zaproxy.org/download/) |
| 10 | **Tshark** | Captura y análisis de tráfico de red | [wireshark.org](https://www.wireshark.org/download.html) |
| 11 | **Wappalyzer** | Detección de tecnologías web | [github.com/aliasio/wappalyzer](https://github.com/aliasio/wappalyzer) |

### Solo Linux (9 herramientas)

| # | Herramienta | Descripción | Instalación / Descarga |
|---|-------------|-------------|------------------------|
| 12 | **Nikto** | Escáner de vulnerabilidades web | [github.com/sullo/nikto](https://github.com/sullo/nikto) |
| 13 | **Wapiti** | Escáner de seguridad web | [github.com/wapiti-scanner/wapiti](https://github.com/wapiti-scanner/wapiti) |
| 14 | **Skipfish** | Escáner de seguridad web (C++) | [github.com/spinkham/skipfish](https://github.com/spinkham/skipfish) |
| 15 | **WhatWeb** | Fingerprinting de tecnologías web | [github.com/urbanadventurer/WhatWeb](https://github.com/urbanadventurer/WhatWeb) |
| 16 | **Googler** | Búsqueda Google desde terminal | [github.com/jarun/googler](https://github.com/jarun/googler) |
| 17 | **Fierce** | Enumeración DNS | [github.com/mschwager/fierce](https://github.com/mschwager/fierce) |
| 18 | **DNSenum** | Enumeración de registros DNS | [github.com/fwaeytens/dnsenum](https://github.com/fwaeytens/dnsenum) |
| 19 | **Masscan** | Escaneo masivo de puertos | [github.com/robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan) |
| 20 | **Hydra** | Fuerza bruta de credenciales | [github.com/vanhauser-thc/thc-hydra](https://github.com/vanhauser-thc/thc-hydra) |

### Experimental (solo Linux, deshabilitada por defecto)

| # | Herramienta | Descripción | Instalación / Descarga |
|---|-------------|-------------|------------------------|
| 21 | **THC-SSL-DOS** | ⚠️ DoS contra SSL. No recomendado sin autorización expresa | [github.com/nicolasff/thc-ssl-dos](https://github.com/nicolasff/thc-ssl-dos) |

> [!CAUTION]
> **THC-SSL-DOS** es una herramienta de denegación de servicio. No la actives a menos que tengas permiso escrito del objetivo. Vulnet la trae deshabilitada y requiere confirmación explícita ("ACEPTO") para ejecutarse.

---

## Instalación de herramientas

### En Windows

La mayoría de herramientas Windows-compatibles tienen instaladores oficiales. Algunas recomendaciones:

- **Nmap, Wireshark (Tshark), Metasploit** — Instaladores .exe desde sus sitios oficiales
- **SQLmap, Dirsearch, SSLyze** — Python puro: `pip install sqlmap dirsearch sslyze`
- **Gobuster, Amass** — Binarios precompilados en GitHub (descargar .exe y agregar al PATH)
- **WPScan** — `gem install wpscan` (requiere Ruby)
- **ZAP** — Instalador Java desde [zaproxy.org](https://www.zaproxy.org/download/)
- **Wappalyzer** — `npm install -g wappalyzer` (requiere Node.js)

### En Linux (Kali/Ubuntu/Debian)

```bash
# Las más comunes vienen preinstaladas en Kali. Si faltan:
sudo apt-get install -y nmap nikto sqlmap dirsearch wpscan sslyze \
  masscan gobuster amass hydra metasploit-framework wapiti \
  whatweb skipfish fierce dnsenum tshark

# Otras vía gem/pip/npm:
sudo gem install wpscan
sudo pip install sslyze dirsearch
sudo npm install -g wappalyzer
```

---

## Uso

### Modo interactivo (recomendado)

```bash
python vulnet.py
```

Te guiará paso a paso: target, modo, herramientas, wordlist, exportación.

### Modo CLI (directo)

```bash
python vulnet.py --target scanme.nmap.org --mode normal --tools Nmap,SQLmap --output ./mis_reportes
```

| Flag | Descripción |
|------|-------------|
| `--target` | IP, dominio o URL |
| `--mode` | `simple`, `normal` o `complejo` |
| `--tools` | Herramientas separadas por coma |
| `--output` | Directorio de reportes (default: `./reports`) |
| `--wordlist` | Ruta a wordlist personalizada |
| `--fast` | Ejecución en paralelo (3 hilos) |
| `--no-export` | No exportar resultados a archivo |

---

## Primeros pasos (ejemplo rápido)

Si es tu primera vez, prueba con Nmap (la herramienta más fácil de instalar):

1. Instala Nmap desde [nmap.org](https://nmap.org/download.html)
2. Instala dependencias Python: `pip install -r requirements.txt`
3. Ejecuta: `python vulnet.py`
4. Escribe `scanme.nmap.org` como objetivo
5. Presiona Enter para modo Normal
6. En la selección de herramientas, marca solo Nmap
7. Al final elige exportar a CSV
8. Revisa el archivo generado en `reports/`

---

## Configuración

Edita `config.yaml` para personalizar:

- **Rutas de wordlists** — Directorio, passwords, subdominios, listas personalizadas
- **Secciones separadas por SO** — `windows:` y `linux:` con rutas diferentes
- **Timeout global** — Tiempo máximo por herramienta
- **Directorio de salida** — Dónde se guardan los reportes

```yaml
general:
  output_dir: "./reports"
  timeout: 600
  default_mode: "normal"

windows:
  wordlists:
    directory: "C:\\tools\\wordlists\\directory-list-2.3-medium.txt"
    custom:
      - path: "C:\\tools\\wordlists\\api_paths.txt"
        alias: "api-rutas"

linux:
  wordlists:
    directory: "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
```

---

## Formatos de exportación

### CSV

Plano, para abrir en Excel, Google Sheets, pandas o Splunk.

```csv
timestamp,severity,tool,title,description,remediation
2026-05-10_143000,CRÍTICO,SQLmap,SQLi Detectada,Inyección SQL encontrada,Sanitizar inputs
```

### JSON

Estructurado con metadatos (target, fecha, modo, OS, estadísticas), ideal para procesamiento posterior.

---

## Aviso para Windows

> [!WARNING]
> En Windows solo **11 de 21 herramientas** están disponibles. Las herramientas Linux-only se ocultan automáticamente del menú. Para experiencia completa, usa **WSL** o Linux nativo.

---

## Solución de problemas

| Problema | Causa probable | Solución |
|----------|---------------|----------|
| `pip install` falla | Python no está en PATH | Reinstalar Python marcando "Add to PATH" |
| Todas las tools muestran ❌ | No has instalado ninguna herramienta | Empieza solo con Nmap, es el más fácil de instalar |
| "No hay herramientas para ejecutar" | No seleccionaste ninguna instalada | Vuelve al menú y marca solo las que tienes |
| "Herramienta no instalada" en resultados | Esa tool específica no está disponible | El resto del escaneo sigue funcionando sin problemas |
| El menú no muestra algunas tools | Son solo Linux, no compatibles con Windows | Usa WSL o Linux nativo para el listado completo |

---

## Disclaimer legal

Vulnet es una herramienta de auditoría de seguridad. Úsala **únicamente contra sistemas que te pertenezcan o para los que tengas autorización por escrito**. El mal uso de esta herramienta puede violar leyes locales e internacionales. El autor no se hace responsable del uso indebido.
