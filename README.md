<p align="left">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="logo/fenreitsu-white.png">
    <source media="(prefers-color-scheme: light)" srcset="logo/fenreitsu.png">
    <img src="fenreitsu-white.png" width="64" height="64" ">
  </picture>
</p>

# Vulnet — Security Scanner CLI

Escáner de seguridad modular para terminal. Ejecuta **21 herramientas** de auditoría contra un objetivo (IP/dominio/URL) y exporta resultados estructurados + logs crudos por herramienta.

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

## Arquitectura del programa

```
vulnet.py                  ← Entrada: menú interactivo + CLI flags
core/
├── models.py              ← ScanConfig, Finding, Severity
├── basetool.py            ← BaseTool: run(), kill(), truncación 100KB, ANSI cleanup
├── console.py             ← ask_yes_no, create_progress, colores, health check
└── exporter.py            ← vulnet_logs/ (CSV+JSON) + raw_tools/ (.txt)
tools/
├── nmap.py, sqlmap.py, ... ← 20 herramientas regulares + 1 experimental
config.yaml                ← Wordlists separadas por SO, timeout, modos
reports/
└── [target]_[timestamp]/
    ├── vulnet_logs/       ← findings.csv + findings.json (estructurados)
    ├── raw_tools/         ← Nmap.txt, Amass.txt, ... (output crudo de cada tool)
    └── tshark_captures/   ← .pcap persistente (no se borra al terminar)
```

---

## Modos de escaneo

| Modo | Tiempo máximo | Descripción |
|------|---------------|-------------|
| **Simple** | 120s por tool | Rápido, herramientas ligeras. Ideal para pruebas |
| **Normal** | 300s por tool | Balanceado. Default recomendado |
| **Complejo** | 600s por tool | Escaneo profundo. Herramientas pesadas (SQLmap, Skipfish...) |
| **Personalizado** | — | Tú eliges tools, tiempo, hilos |

---

## Flags CLI

```bash
python vulnet.py --target scanme.nmap.org --mode simple --fast
```

| Flag | Descripción |
|------|-------------|
| `--target` | IP, dominio o URL |
| `--mode` | `simple`, `normal` o `complejo` |
| `--tools` | Herramientas separadas por coma (ej: `Nmap,SQLmap,Nikto`) |
| `--fast` | Ejecución en paralelo (3 hilos máx.) con progress bars |
| `--output` | Directorio base de reportes (default: `./reports`) |
| `--wordlist` | Ruta a wordlist personalizada |
| `--no-export` | Suprimir exportación a CSV/JSON |

### Ejemplos

```bash
# Scan rápido en paralelo
python vulnet.py --target scanme.nmap.org --mode simple --fast

# Scan normal con tools específicas
python vulnet.py --target ejemplo.com --mode normal --tools Nmap,Nikto,WhatWeb

# Scan completo sin export
python vulnet.py --target 192.168.1.1 --mode complejo --no-export
```

---

## Health Check — ¿Qué significan los iconos?

Al arrancar, Vulnet analiza qué herramientas tienes instaladas y cuáles son compatibles con tu SO.

| Icono | Significado |
|-------|-------------|
| ✅ | Instalada y disponible |
| ❌ | **Compatible con tu SO pero no instalada** |
| ⛔ | **No compatible con tu SO** (solo Linux / solo Windows) |

```
  ✅     Nmap       ← Instalada y compatible
  ❌     SQLmap     ← No instalada pero funcionaría
  ⛔     Hydra      ← Solo Linux, no funciona en Windows
```

---

## Lista completa de herramientas

### Windows 11 + Linux (11 herramientas)

| # | Herramienta | Descripción |
|---|-------------|-------------|
| 1 | **Nmap** | Escaneo de puertos y servicios |
| 2 | **SQLmap** | Detección de inyección SQL automática |
| 3 | **Dirsearch** | Fuzzing de directorios web |
| 4 | **WPScan** | Escáner de seguridad WordPress |
| 5 | **SSLyze** | Análisis de configuración SSL/TLS |
| 6 | **Gobuster** | Fuerza bruta de directorios/DNS |
| 7 | **Amass** | Enumeración de subdominios y ASN |
| 8 | **Metasploit** | Framework de exploits y escaneo |
| 9 | **ZAP** (OWASP) | Escáner de vulnerabilidades web |
| 10 | **Tshark** | Captura y análisis de tráfico de red |
| 11 | **Wappalyzer** | Detección de tecnologías web |

### Solo Linux (9 herramientas)

| # | Herramienta | Descripción |
|---|-------------|-------------|
| 12 | **Nikto** | Escáner de vulnerabilidades web |
| 13 | **Wapiti** | Escáner de seguridad web |
| 14 | **Skipfish** | Escáner de seguridad web (C++) |
| 15 | **WhatWeb** | Fingerprinting de tecnologías web |
| 16 | **Googler** | Búsqueda Google desde terminal |
| 17 | **Fierce** | Enumeración DNS |
| 18 | **DNSenum** | Enumeración de registros DNS |
| 19 | **Masscan** | Escaneo masivo de puertos |
| 20 | **Hydra** | Fuerza bruta de credenciales |

### Experimental (solo Linux, deshabilitada por defecto)

| # | Herramienta | Descripción |
|---|-------------|-------------|
| 21 | **THC-SSL-DOS** | ⚠️ DoS contra SSL. Requiere confirmación explícita |

> [!CAUTION]
> **THC-SSL-DOS** es una herramienta de denegación de servicio. No la actives a menos que tengas permiso escrito del objetivo. Requiere escribir "ACEPTO" para ejecutarse.

---

## Instalación de herramientas

### Windows

| Herramienta | Instalación |
|-------------|-------------|
| Nmap, Wireshark (Tshark), Metasploit | Instaladores .exe desde sitios oficiales |
| SQLmap, Dirsearch, SSLyze | `pip install sqlmap dirsearch sslyze` |
| Gobuster, Amass | Binarios precompilados en GitHub (.exe + PATH) |
| WPScan | `gem install wpscan` (requiere Ruby) |
| ZAP | Instalador Java desde [zaproxy.org](https://www.zaproxy.org/download/) |
| Wappalyzer | `npm install -g wappalyzer` (requiere Node.js) |

### Linux (Kali/Ubuntu/Debian)

```bash
# Mayoría preinstalada en Kali. Si falta:
sudo apt-get install -y nmap nikto sqlmap dirsearch wpscan sslyze \
  masscan gobuster amass hydra metasploit-framework wapiti \
  whatweb skipfish fierce dnsenum tshark

# Vía gem/pip/npm:
sudo gem install wpscan
sudo pip install sslyze dirsearch
sudo npm install -g wappalyzer
```

---

## Configuración (`config.yaml`)

Wordlists separadas por SO, sin rutas personales:

```yaml
general:
  output_dir: "./reports"
  timeout: 300
  default_mode: "normal"

windows:
  wordlists:
    directory: "C:\\tools\\wordlists\\directory-list-2.3-medium.txt"
    passwords: "C:\\tools\\wordlists\\rockyou.txt"
    subdomains: "C:\\tools\\wordlists\\subdomains.txt"
    custom:
      - path: "C:\\tools\\wordlists\\api_paths.txt"
        alias: "api-rutas"

linux:
  wordlists:
    directory: "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    passwords: "/usr/share/wordlists/rockyou.txt"
    subdomains: "/usr/share/wordlists/subdomains.txt"
```

Si una herramienta necesita wordlist y no está configurada, se omite con el mensaje: *"Requiere wordlist — no configurada en config.yaml"*.

---

## Output: estructura de reportes

```
reports/scanme.nmap.org_2026-05-12_134550/
├── vulnet_logs/
│   ├── findings.csv       ← Columnas: timestamp, severity, tool, title, description, remediation
│   └── findings.json      ← Metadatos + todos los findings
├── raw_tools/             ← Output crudo de CADA herramienta (truncado a 100KB)
│   ├── Nmap.txt           ← Texto plano (-oN -), no XML
│   ├── Amass.txt
│   ├── SQLmap.txt
│   └── ... (1 .txt por tool ejecutada)
└── tshark_captures/
    └── scanme_nmap_org_*.pcap   ← Captura de red persistente
```

### CSV

```csv
timestamp,severity,tool,title,description,remediation
2026-05-10_143000,CRÍTICO,SQLmap,SQLi Detectada,Inyección SQL encontrada,Sanitizar inputs
```

### JSON

Con metadatos de escaneo (target, fecha, modo, OS, tools ejecutadas, duración).

### Raw tools

Cada herramienta guarda su salida exacta en `raw_tools/*.txt`. Las herramientas que producen XML (Nmap) se convierten a texto plano. Outputs mayores a 100KB se truncan con aviso.

---

## Comportamiento interno

| Característica | Detalle |
|----------------|---------|
| **Paralelismo** | Hasta 3 hilos simultáneos con `--fast`. Cada tool con timeout propio según modo |
| **Timeout por modo** | Simple: 120s, Normal: 300s, Complejo: 600s |
| **Ctrl+C** | Mata todos los procesos hijos en curso y sale limpio |
| **Root check (Linux)** | Si no eres root, muestra advertencia y sale con `exit(1)` |
| **Validación IP** | Soporta IPv4 e IPv6 via `ipaddress.ip_address()` |
| **ANSIs en output** | Limpiados automáticamente antes de guardar en CSV/JSON/raw |
| **Progress bar** | Spinner + descripción + barra + porcentaje + tiempo transcurrido |
| **Exportación** | Automática al final del scan (sin preguntar de nuevo) si se eligió formato al inicio |
| **Wordlists** | Detecta automáticamente Linux vs Windows desde `config.yaml` |

---

## Solución de problemas

| Problema | Causa | Solución |
|----------|-------|----------|
| `pip install` falla | Python no está en PATH | Reinstalar Python marcando "Add to PATH" |
| Todas las tools ❌ | No has instalado ninguna herramienta | Empieza solo con Nmap |
| "No hay herramientas" | No seleccionaste ninguna instalada | Vuelve al menú y marca solo las que tienes |
| "Requiere wordlist" | Herramienta como Gobuster/Hydra sin wordlist configurada | Agrega ruta en `config.yaml` |
| Tool no aparece en menú | Es solo Linux y estás en Windows (o viceversa) | Usa WSL/Linux nativo para 21 tools |
| Progress bar en 0% | PWsh no actualiza Rich correctamente | El escaneo corre igual, revisa `raw_tools/` |
| Emoji `□` en vez de icono | Terminal legacy Windows (cmd.exe) | Usa Windows Terminal o Linux |

---

## Aviso para Windows

> [!WARNING]
> En Windows solo **11 de 21 herramientas** están disponibles. Las Linux-only se ocultan del menú automáticamente. Para experiencia completa, usa **WSL** o Linux nativo.

---

## Disclaimer legal

Vulnet es una herramienta de auditoría de seguridad. Úsala **únicamente contra sistemas que te pertenezcan o para los que tengas autorización por escrito**. El mal uso puede violar leyes locales e internacionales. El autor no se hace responsable del uso indebido.
