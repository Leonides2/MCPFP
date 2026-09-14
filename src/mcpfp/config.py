"""Carga y validacion de la configuracion del OBJETIVO UNICO.

Regla central del requisito: el MCP solo puede apuntar a una maquina virtual
a la vez, definida en un archivo .env. Aqui se lee, se valida y se garantiza
que exista autorizacion explicita antes de operar.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

# Cargamos el .env del directorio de invocacion (cwd) una sola vez al importar.
load_dotenv(dotenv_path=Path.cwd() / ".env", override=False)

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


class ConfigError(Exception):
    """Error de configuracion del objetivo."""


@dataclass(frozen=True)
class TargetConfig:
    """Configuracion inmutable del unico objetivo permitido."""

    host: str
    name: str
    authorized: bool
    port_range: str
    lab_user: str | None
    lab_password: str | None
    report_dir: Path

    def require_authorized(self) -> None:
        """Lanza ConfigError si el objetivo no fue autorizado explicitamente."""
        if not self.authorized:
            raise ConfigError(
                "El objetivo no esta autorizado. Define MCPFP_AUTHORIZED=true en .env "
                "SOLO si tienes permiso explicito sobre esta maquina (laboratorio propio)."
            )


def _validate_host(host: str) -> str:
    host = host.strip()
    if not host:
        raise ConfigError("MCPFP_TARGET_HOST esta vacio. Define la IP/host del laboratorio.")
    # Aceptamos IP valida o hostname valido.
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if _HOSTNAME_RE.match(host):
        return host
    raise ConfigError(f"MCPFP_TARGET_HOST no es una IP ni un hostname valido: {host!r}")


def _validate_port_range(value: str) -> str:
    value = (value or "1-1000").strip()
    if value == "-":
        return value
    # Formatos permitidos: "1-1000" o "22,80,443" o combinaciones simples.
    if not re.fullmatch(r"[0-9,\-]+", value):
        raise ConfigError(f"MCPFP_PORT_RANGE invalido: {value!r}")
    return value


def load_target() -> TargetConfig:
    """Lee la configuracion del objetivo desde variables de entorno (.env).

    Recarga el .env del cwd para reflejar cambios sin reiniciar el servidor.
    """
    load_dotenv(dotenv_path=Path.cwd() / ".env", override=True)

    host = _validate_host(os.getenv("MCPFP_TARGET_HOST", ""))
    name = os.getenv("MCPFP_TARGET_NAME", "").strip() or host
    authorized = os.getenv("MCPFP_AUTHORIZED", "false").strip().lower() == "true"
    port_range = _validate_port_range(os.getenv("MCPFP_PORT_RANGE", "1-1000"))
    lab_user = os.getenv("MCPFP_LAB_USER", "").strip() or None
    lab_password = os.getenv("MCPFP_LAB_PASSWORD", "").strip() or None
    report_dir = Path(os.getenv("MCPFP_REPORT_DIR", "reports"))

    return TargetConfig(
        host=host,
        name=name,
        authorized=authorized,
        port_range=port_range,
        lab_user=lab_user,
        lab_password=lab_password,
        report_dir=report_dir,
    )
