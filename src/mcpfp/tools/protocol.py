"""Analisis de protocolo: cabeceras HTTP y configuracion TLS (pasivo).

Lee informacion que el servicio ya expone (banners, cabeceras, certificado)
para senalar debilidades de configuracion. No enviamos payloads de ataque.
"""

from __future__ import annotations

from ..guardrails import ExploitationBlocked, is_tool_available, run_safe

# Cabeceras de seguridad esperadas y su relevancia.
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS: fuerza HTTPS y evita downgrade.",
    "content-security-policy": "CSP: mitiga XSS e inyeccion de contenido.",
    "x-frame-options": "Evita clickjacking (o usar CSP frame-ancestors).",
    "x-content-type-options": "nosniff: evita MIME sniffing.",
    "referrer-policy": "Controla la fuga de informacion via Referer.",
}


def analyze_http_headers(host: str, port: int = 80, use_https: bool = False) -> str:
    """Recupera y evalua las cabeceras HTTP de seguridad del objetivo."""
    if not is_tool_available("curl"):
        return "curl no esta instalado; no se pueden leer las cabeceras HTTP."

    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}/"
    command = ["curl", "-sSIk", "--max-time", "15", url]

    try:
        result = run_safe(command, timeout=30)
    except ExploitationBlocked as exc:
        return f"Bloqueado por guardarrailes: {exc}"
    except Exception as exc:  # noqa: BLE001
        return f"No se pudieron obtener las cabeceras: {exc}"

    headers_raw = result.stdout.strip()
    if not headers_raw:
        return f"Sin respuesta HTTP de {url}. Verifica el puerto/servicio."

    lower = headers_raw.lower()
    faltantes = [
        f"- Falta **{h}**: {desc}"
        for h, desc in SECURITY_HEADERS.items()
        if h not in lower
    ]

    lineas = [
        f"# Analisis de cabeceras HTTP - {url}",
        "",
        "## Cabeceras recibidas",
        "```",
        headers_raw,
        "```",
        "",
        "## Cabeceras de seguridad ausentes (hallazgos)",
    ]
    lineas.extend(faltantes or ["- Ninguna ausencia critica detectada."])
    lineas.append("")
    lineas.append(
        "> Mapea estas ausencias a OWASP A05:2021 (Security Misconfiguration). "
        "El MCP describe la debilidad; la remediacion la aplica el responsable."
    )
    return "\n".join(lineas)


def analyze_tls(host: str, port: int = 443) -> str:
    """Inspecciona el certificado y el protocolo TLS del objetivo (pasivo)."""
    if not is_tool_available("openssl"):
        return "openssl no esta instalado; no se puede inspeccionar TLS."

    command = ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host]
    try:
        # openssl s_client espera input; le pasamos cierre inmediato via timeout corto.
        result = run_safe(command, timeout=20)
    except ExploitationBlocked as exc:
        return f"Bloqueado por guardarrailes: {exc}"
    except Exception as exc:  # noqa: BLE001
        return f"No se pudo inspeccionar TLS: {exc}"

    salida = (result.stdout or result.stderr).strip() or "(sin salida)"
    return (
        f"# Analisis TLS - {host}:{port}\n\n"
        "```\n"
        f"{salida[:4000]}\n"
        "```\n\n"
        "> Revisa version del protocolo (evitar SSLv3/TLS1.0/1.1), vigencia del "
        "certificado y algoritmos debiles. Relaciona con OWASP A02:2021 "
        "(Cryptographic Failures)."
    )
