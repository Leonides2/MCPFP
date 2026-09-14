"""Evaluacion pasiva orientada a OWASP Top 10.

Correlaciona hallazgos observables (cabeceras, tecnologias, configuraciones)
con las categorias del OWASP Top 10 2021, y sugiere que revisar manualmente.
NO envia inyecciones, payloads ni fuerza bruta.
"""

from __future__ import annotations

from ..guardrails import ExploitationBlocked, is_tool_available, run_safe

# Referencia rapida OWASP Top 10 2021 con senales observables de forma pasiva.
OWASP_TOP10 = [
    ("A01:2021", "Broken Access Control",
     "Rutas administrativas expuestas, directorios listables, IDs secuenciales en URLs."),
    ("A02:2021", "Cryptographic Failures",
     "HTTP sin TLS, TLS obsoleto, certificados invalidos, cookies sin Secure/HttpOnly."),
    ("A03:2021", "Injection",
     "Formularios/parametros sin sanitizar (revisar manualmente, sin inyectar payloads)."),
    ("A04:2021", "Insecure Design",
     "Ausencia de controles esperados en el flujo (analisis de diseno)."),
    ("A05:2021", "Security Misconfiguration",
     "Cabeceras de seguridad ausentes, paginas por defecto, banners con versiones, errores verbosos."),
    ("A06:2021", "Vulnerable and Outdated Components",
     "Versiones antiguas de servidores/frameworks detectadas por fingerprinting."),
    ("A07:2021", "Identification and Authentication Failures",
     "Login sin proteccion contra fuerza bruta, sesiones debiles (solo observar)."),
    ("A08:2021", "Software and Data Integrity Failures",
     "Recursos cargados sin integridad, actualizaciones sin firmar."),
    ("A09:2021", "Security Logging and Monitoring Failures",
     "Indicios de falta de registro/monitoreo (dificil de ver pasivamente)."),
    ("A10:2021", "Server-Side Request Forgery (SSRF)",
     "Parametros que reciben URLs (revisar diseno, sin explotar)."),
]


def assess_owasp(host: str, port: int = 80, use_https: bool = False) -> str:
    """Fingerprinting web y mapeo a OWASP Top 10 (descriptivo)."""
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}/"

    tecnologias = "(whatweb no disponible; omite fingerprinting automatico)"
    if is_tool_available("whatweb"):
        try:
            result = run_safe(["whatweb", "--no-errors", url], timeout=60)
            tecnologias = result.stdout.strip() or "(sin datos)"
        except ExploitationBlocked as exc:
            tecnologias = f"Bloqueado: {exc}"
        except Exception as exc:  # noqa: BLE001
            tecnologias = f"Error al ejecutar whatweb: {exc}"

    lineas = [
        f"# Evaluacion OWASP Top 10 (pasiva) - {url}",
        "",
        "## Fingerprinting de tecnologias",
        "```",
        tecnologias,
        "```",
        "",
        "## Mapa OWASP Top 10 2021 - que revisar",
    ]
    for code, nombre, senal in OWASP_TOP10:
        lineas.append(f"- **{code} {nombre}**: {senal}")

    lineas.append("")
    lineas.append(
        "> Este mapa orienta la revision. El MCP no ejecuta inyecciones ni fuerza "
        "bruta: cada verificacion final la realiza el estudiante manualmente y con "
        "autorizacion. Usa `get_guidance` para profundizar en una categoria."
    )
    return "\n".join(lineas)
