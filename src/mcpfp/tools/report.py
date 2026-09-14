"""Generacion del reporte Markdown en el directorio de invocacion.

Escribe (o adjunta a) un archivo .md dentro de MCPFP_REPORT_DIR, relativo al
cwd donde se invoco el MCP, tal como pide el requisito.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

_DISCLAIMER = (
    "> **Aviso**: Este reporte se genera con fines educativos y de remediacion. "
    "El MCP describe vulnerabilidades pero NO las explota. Cualquier verificacion "
    "activa la realiza una persona autorizada, sobre un laboratorio propio o con permiso."
)


def _report_path(report_dir: str | Path, target_name: str) -> Path:
    base = Path(report_dir)
    base.mkdir(parents=True, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in target_name)
    return base / f"reporte_{safe}.md"


def write_report(
    target_name: str,
    target_host: str,
    findings: str,
    report_dir: str | Path = "reports",
    append: bool = True,
) -> str:
    """Escribe los hallazgos en un reporte Markdown y devuelve la ruta.

    Args:
        target_name: nombre del laboratorio/objetivo.
        target_host: IP/host del objetivo.
        findings: contenido Markdown de los hallazgos a registrar.
        report_dir: carpeta destino (relativa al cwd de invocacion).
        append: si True agrega una nueva seccion; si False reemplaza el archivo.
    """
    path = _report_path(report_dir, target_name)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    seccion = (
        f"\n\n---\n\n## Hallazgo registrado - {timestamp}\n\n{findings.strip()}\n"
    )

    if append and path.exists():
        with path.open("a", encoding="utf-8") as fh:
            fh.write(seccion)
    else:
        encabezado = (
            f"# Reporte de evaluacion - {target_name}\n\n"
            f"- **Objetivo**: {target_host}\n"
            f"- **Generado**: {timestamp}\n\n"
            f"{_DISCLAIMER}\n"
            f"{seccion}"
        )
        path.write_text(encabezado, encoding="utf-8")

    return f"Reporte actualizado en: {path.resolve()}"
