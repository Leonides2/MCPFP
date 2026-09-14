"""Servidor MCP (SDK oficial) - MCPFP.

Expone herramientas de reconocimiento y analisis DEFENSIVO contra una unica
maquina virtual de laboratorio. Describe vulnerabilidades y guia al estudiante,
pero nunca las explota.
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from .config import ConfigError, load_target
from .tools import environment, guidance, protocol, recon, report, web_owasp

mcp = MCPServer(
    "mcpfp",
    instructions=(
        "MCP educativo de evaluacion de vulnerabilidades sobre UNA maquina virtual "
        "de laboratorio (VulnHub u otra), configurada en .env. Valida OWASP Top 10, "
        "escanea red y protocolo, y GUIA al estudiante. NUNCA explota vulnerabilidades: "
        "solo las describe y sugiere acercamientos. Los hallazgos se entregan en el chat "
        "y se guardan como reporte Markdown en el directorio de invocacion."
    ),
)


# --------------------------------------------------------------------------- #
# Herramientas de configuracion y entorno
# --------------------------------------------------------------------------- #
@mcp.tool()
def load_target_info() -> str:
    """Carga y valida el objetivo unico desde .env, confirmando autorizacion."""
    try:
        cfg = load_target()
        cfg.require_authorized()
    except ConfigError as exc:
        return f"Configuracion invalida: {exc}"
    return (
        f"Objetivo cargado:\n"
        f"- Nombre: {cfg.name}\n"
        f"- Host: {cfg.host}\n"
        f"- Rango de puertos: {cfg.port_range}\n"
        f"- Autorizado: si\n"
        f"- Carpeta de reportes: {cfg.report_dir}\n\n"
        "Recordatorio: solo un objetivo a la vez. Cambia el .env para apuntar a otro."
    )


@mcp.tool()
def check_environment() -> str:
    """Verifica que herramientas externas de reconocimiento estan instaladas."""
    return environment.check_environment()


# --------------------------------------------------------------------------- #
# Reconocimiento y analisis (pasivos)
# --------------------------------------------------------------------------- #
@mcp.tool()
def scan_network() -> str:
    """Descubre puertos y servicios del objetivo (nmap no intrusivo)."""
    try:
        cfg = load_target()
        cfg.require_authorized()
    except ConfigError as exc:
        return f"No se puede escanear: {exc}"
    return recon.scan_network(cfg.host, cfg.port_range)


@mcp.tool()
def analyze_http_headers(port: int = 80, use_https: bool = False) -> str:
    """Evalua las cabeceras de seguridad HTTP del objetivo."""
    try:
        cfg = load_target()
        cfg.require_authorized()
    except ConfigError as exc:
        return f"No se puede analizar: {exc}"
    return protocol.analyze_http_headers(cfg.host, port, use_https)


@mcp.tool()
def analyze_tls(port: int = 443) -> str:
    """Inspecciona el certificado y protocolo TLS del objetivo."""
    try:
        cfg = load_target()
        cfg.require_authorized()
    except ConfigError as exc:
        return f"No se puede analizar: {exc}"
    return protocol.analyze_tls(cfg.host, port)


@mcp.tool()
def assess_owasp(port: int = 80, use_https: bool = False) -> str:
    """Fingerprinting web y mapeo pasivo a OWASP Top 10."""
    try:
        cfg = load_target()
        cfg.require_authorized()
    except ConfigError as exc:
        return f"No se puede evaluar: {exc}"
    return web_owasp.assess_owasp(cfg.host, port, use_https)


# --------------------------------------------------------------------------- #
# Tutor y reporte
# --------------------------------------------------------------------------- #
@mcp.tool()
def get_guidance(topic: str) -> str:
    """Guia pedagogica paso a paso (obvios / no obvios / siguiente paso).

    Temas: reconocimiento, a01, a02, a05, a06, bandera.
    """
    return guidance.get_guidance(topic)


@mcp.tool()
def write_report(findings: str, append: bool = True) -> str:
    """Guarda hallazgos en un reporte Markdown en el directorio de invocacion."""
    try:
        cfg = load_target()
    except ConfigError as exc:
        return f"No se puede escribir el reporte: {exc}"
    return report.write_report(
        target_name=cfg.name,
        target_host=cfg.host,
        findings=findings,
        report_dir=cfg.report_dir,
        append=append,
    )


# --------------------------------------------------------------------------- #
# Prompt de metodologia
# --------------------------------------------------------------------------- #
@mcp.prompt()
def metodologia() -> str:
    """Metodologia de abordaje siguiendo OWASP e ISO 27001 (sin explotacion)."""
    return (
        "Actua como analista de seguridad defensiva. Sigue este flujo sobre el "
        "objetivo unico definido en .env, SIN explotar nada:\n"
        "1. check_environment y load_target_info.\n"
        "2. scan_network para mapear puertos/servicios.\n"
        "3. analyze_http_headers / analyze_tls para el protocolo.\n"
        "4. assess_owasp para mapear al OWASP Top 10.\n"
        "5. get_guidance para profundizar donde el estudiante lo pida.\n"
        "6. write_report para dejar los hallazgos en Markdown.\n"
        "Describe cada debilidad y su remediacion; la verificacion activa la hace "
        "el humano, con autorizacion. Correlaciona con controles ISO 27001 (Anexo A)."
    )


def main() -> None:
    """Punto de entrada del servidor MCP (transporte stdio)."""
    mcp.run()


if __name__ == "__main__":
    main()
