"""Verificacion del entorno: que herramientas externas estan disponibles.

Antes de escanear conviene saber que binarios existen y sugerir la instalacion
de los que falten. No instala nada por su cuenta.
"""

from __future__ import annotations

from ..guardrails import ALLOWED_BINARIES, is_tool_available

# Sugerencias de instalacion por herramienta (multiplataforma).
INSTALL_HINTS: dict[str, str] = {
    "nmap": "Debian/Ubuntu: sudo apt install nmap | macOS: brew install nmap | Windows: winget install Insecure.Nmap",
    "nikto": "Debian/Ubuntu: sudo apt install nikto | macOS: brew install nikto",
    "whatweb": "Debian/Ubuntu: sudo apt install whatweb | git clone https://github.com/urbanadventurer/WhatWeb",
    "openssl": "Preinstalado en la mayoria de sistemas | Windows: winget install ShiningLight.OpenSSL",
    "curl": "Preinstalado en la mayoria de sistemas | Windows: incluido en Windows 10+",
    "dig": "Debian/Ubuntu: sudo apt install dnsutils | macOS: preinstalado",
    "host": "Debian/Ubuntu: sudo apt install dnsutils | macOS: preinstalado",
}


def check_environment() -> str:
    """Reporta que herramientas de reconocimiento estan instaladas y cuales faltan."""
    disponibles: list[str] = []
    faltantes: list[str] = []

    for binary, descripcion in ALLOWED_BINARIES.items():
        if is_tool_available(binary):
            disponibles.append(f"- **{binary}** disponible - {descripcion}")
        else:
            hint = INSTALL_HINTS.get(binary, "Instala esta herramienta desde tu gestor de paquetes.")
            faltantes.append(f"- **{binary}** NO encontrada - {descripcion}\n  - Instalar: {hint}")

    lineas = ["# Estado del entorno de reconocimiento", ""]

    if disponibles:
        lineas.append("## Herramientas disponibles")
        lineas.extend(disponibles)
        lineas.append("")

    if faltantes:
        lineas.append("## Herramientas faltantes (sugerencias)")
        lineas.extend(faltantes)
        lineas.append("")
        lineas.append(
            "> Puedes operar con las que tengas; algunas comprobaciones se omitiran "
            "si falta la herramienta correspondiente."
        )
    else:
        lineas.append("Todas las herramientas de reconocimiento estan disponibles.")

    return "\n".join(lineas)
