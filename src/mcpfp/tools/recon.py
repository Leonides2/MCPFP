"""Reconocimiento de red: descubrimiento de puertos y servicios (no intrusivo).

Usa nmap en modo deteccion de version (-sV) con scripts por defecto seguros.
Nunca corre scripts de exploit/brute/dos (bloqueados por guardrails).
"""

from __future__ import annotations

from ..guardrails import ExploitationBlocked, is_tool_available, run_safe


def scan_network(host: str, port_range: str = "1-1000") -> str:
    """Escanea puertos y detecta servicios/versiones del objetivo (modo pasivo).

    Args:
        host: IP o hostname del objetivo unico.
        port_range: rango de puertos (ej. "1-1000", "22,80,443").
    """
    if not is_tool_available("nmap"):
        return (
            "nmap no esta instalado. Instalalo para el reconocimiento de red.\n"
            "Alternativa manual: revisa servicios conocidos con `curl -I http://HOST` "
            "o consulta la documentacion del laboratorio."
        )

    # -sV: version; -sT: TCP connect (no requiere raiz); --script=default acota a
    # scripts seguros de descubrimiento. Sin -O, sin vuln, sin brute (guardrails).
    command = [
        "nmap",
        "-sV",
        "-sT",
        "-Pn",
        "-p",
        port_range,
        "--script=default",
        host,
    ]

    try:
        result = run_safe(command, timeout=600)
    except ExploitationBlocked as exc:
        return f"Escaneo bloqueado por guardarrailes: {exc}"
    except Exception as exc:  # noqa: BLE001 - reportamos cualquier fallo de ejecucion
        return f"No se pudo ejecutar el escaneo: {exc}"

    salida = result.stdout.strip() or result.stderr.strip() or "(sin salida)"
    return (
        f"# Reconocimiento de red - {host}\n\n"
        f"Comando: `{' '.join(command)}`\n\n"
        "```\n"
        f"{salida}\n"
        "```\n\n"
        "> Resultado descriptivo. Interpreta puertos/servicios/versiones y contrasta "
        "las versiones con avisos conocidos (CVE) de forma manual. El MCP no explota."
    )
