# MCPFP — Model Context Protocol For Pentesting

Servidor **MCP** (Model Context Protocol, SDK oficial de Python) para practicar
evaluación de seguridad contra **una** máquina virtual de laboratorio (VulnHub u
otra). Valida el **OWASP Top 10**, escanea red y protocolo, y **guía** al
estudiante paso a paso.

> **Regla de oro:** el MCP **describe** vulnerabilidades y sugiere acercamientos,
> pero **nunca las explota**. Los hallazgos se entregan en el chat y se guardan
> como reporte Markdown en el directorio desde donde se invocó el MCP.
> Úsalo **solo** en laboratorios propios o con autorización explícita.

## Instalación

```
python -m venv .venv
.venv\Scripts\python -m pip install -e .
copy .env.example .env
```

Edita `.env` con los datos del laboratorio (ver comentarios en `.env.example`):

- `MCPFP_TARGET_HOST`: IP/host de la VM.
- `MCPFP_AUTHORIZED=true`: confirma que tienes permiso (obligatorio para operar).
- `MCPFP_PORT_RANGE`, `MCPFP_REPORT_DIR`, credenciales de lab (opcionales).

**Nunca subas `.env` a un repositorio.**

Herramientas externas recomendadas (el MCP valida su existencia y sugiere cómo
instalarlas): `nmap`, `nikto`, `whatweb`, `openssl`, `curl`, `dig`.

## Uso

### Servidor MCP

Correrlo manualmente (stdio), invocando el módulo del servidor:

```
.venv\Scripts\python -m mcpfp.server
```

Para registrarlo en Claude Code:

```
claude mcp add mcpfp -s user -- "<ruta>\.venv\Scripts\python.exe" -m mcpfp.server
```

o para otro cliente MCP (Claude Desktop, etc.), agrega este bloque a la config
de `mcpServers` del cliente, ajustando las rutas a tu máquina:

```json
{
  "mcpServers": {
    "mcpfp": {
      "command": "C:\\ruta\\a\\MCPFP\\.venv\\Scripts\\python.exe",
      "args": ["-m", "mcpfp.server"],
      "cwd": "C:\\ruta\\a\\MCPFP"
    }
  }
}
```

`cwd` define dónde se escribe el reporte Markdown (por defecto en `reports/`).

## Herramientas expuestas

| Tool | Descripción | ¿Explota? |
|------|-------------|-----------|
| `load_target_info` | Carga y valida el objetivo del `.env` | No |
| `check_environment` | Verifica herramientas externas y sugiere instalación | No |
| `scan_network` | Puertos/servicios/versiones (nmap no intrusivo) | No |
| `analyze_http_headers` | Cabeceras de seguridad HTTP | No |
| `analyze_tls` | Certificado y protocolo TLS | No |
| `assess_owasp` | Fingerprinting + mapeo OWASP Top 10 | No |
| `get_guidance` | Tutor: acercamientos obvios y no obvios | No |
| `write_report` | Guarda hallazgos en Markdown en el cwd | No |

Además, el prompt MCP `metodologia` describe el flujo completo.

## Guardarraíles anti-explotación

`src/mcpfp/guardrails.py` aplica lista blanca de binarios y lista negra de
argumentos intrusivos (exploit, brute, dos, dump, etc.). Herramientas de
explotación (`sqlmap`, `hydra`, `metasploit`, …) están **prohibidas**.

## Skill de Claude

`skills/ciberseguridad-owasp-iso27001/SKILL.md`: metodología de abordaje
defensivo siguiendo **OWASP + ISO/IEC 27001**.

## Estructura

```
src/mcpfp/
├── server.py        # FastMCP: tools, prompt
├── config.py        # objetivo único desde .env
├── guardrails.py    # anti-explotación
├── tools/           # environment, recon, protocol, web_owasp, guidance, report
└── knowledge/       # referencias OWASP / protocolo
skills/               # Skill de Claude (OWASP + ISO 27001)
```

## Aviso legal

Herramienta educativa y defensiva. El uso contra sistemas sin autorización es
ilegal. El autor y los contribuyentes no se responsabilizan del mal uso.
