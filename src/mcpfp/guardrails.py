"""Guardarrailes anti-explotacion.

Este modulo es el corazon de la garantia del requisito:

    EL MCP NO DEBE APROVECHAR LAS VULNERABILIDADES, SOLO DESCRIBIRLAS.

Toda ejecucion de una herramienta externa pasa por aqui. Se aplica una
lista blanca de binarios y una lista negra de flags/argumentos intrusivos.
Si algo huele a explotacion (fuerza bruta, inyeccion, exploits, extraccion
de datos, DoS), se bloquea ANTES de ejecutarse.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


class ExploitationBlocked(Exception):
    """Se intento una accion potencialmente explotadora: se bloquea."""


# Binarios permitidos: solo reconocimiento y analisis, nunca explotacion.
ALLOWED_BINARIES: dict[str, str] = {
    "nmap": "Descubrimiento de puertos/servicios/versiones (modo no intrusivo).",
    "nikto": "Escaneo pasivo de configuraciones web inseguras.",
    "whatweb": "Fingerprinting de tecnologias web.",
    "openssl": "Inspeccion de certificados y cifrados TLS.",
    "curl": "Lectura de cabeceras y respuestas HTTP.",
    "dig": "Consultas DNS.",
    "host": "Resolucion DNS.",
}

# Herramientas explicitamente PROHIBIDAS: son de explotacion, jamas se invocan.
FORBIDDEN_BINARIES: set[str] = {
    "sqlmap",
    "hydra",
    "medusa",
    "john",
    "hashcat",
    "msfconsole",
    "msfvenom",
    "metasploit",
    "searchsploit",
    "wpscan",  # tiene modos intrusivos/brute; se excluye por seguridad
    "crackmapexec",
    "responder",
    "ncrack",
    "patator",
}

# Fragmentos de argumentos que indican intencion explotadora.
FORBIDDEN_ARG_PATTERNS: tuple[str, ...] = (
    "--script=exploit",
    "--script exploit",
    "vuln)",          # categorias nmap que llegan a explotar
    "brute",          # cualquier script/flag de fuerza bruta
    "--script=brute",
    "dos",            # denegacion de servicio
    "--script=dos",
    "-sU",            # UDP masivo agresivo (evitamos por ruido/impacto)
    "--dump",         # extraccion de datos (sqlmap style)
    "--os-shell",
    "--sql-shell",
    "-O",             # nmap OS detection requiere privilegios y es mas intrusivo
    "--min-rate",     # forzar tasas altas -> impacto tipo DoS
)


@dataclass(frozen=True)
class CommandResult:
    """Resultado de ejecutar un comando permitido."""

    command: list[str]
    returncode: int
    stdout: str
    stderr: str


def is_tool_available(binary: str) -> bool:
    """Indica si un binario externo esta disponible en el PATH."""
    return shutil.which(binary) is not None


def _assert_command_is_safe(command: list[str]) -> None:
    """Valida el comando contra las listas blanca/negra. Lanza si es inseguro."""
    if not command:
        raise ExploitationBlocked("Comando vacio.")

    # Normalizamos rutas absolutas: nos quedamos con el nombre del binario.
    binary = command[0].lower().replace("\\", "/").split("/")[-1]
    if binary.endswith(".exe"):
        binary = binary[:-4]

    if binary in FORBIDDEN_BINARIES:
        raise ExploitationBlocked(
            f"'{binary}' es una herramienta de explotacion y esta prohibida. "
            "El MCP solo describe vulnerabilidades; la explotacion la decide y "
            "ejecuta el humano, fuera de esta herramienta."
        )

    if binary not in ALLOWED_BINARIES:
        raise ExploitationBlocked(
            f"'{binary}' no esta en la lista blanca de herramientas de reconocimiento. "
            f"Permitidas: {', '.join(sorted(ALLOWED_BINARIES))}."
        )

    joined = " ".join(command).lower()
    for pattern in FORBIDDEN_ARG_PATTERNS:
        if pattern.lower() in joined:
            raise ExploitationBlocked(
                f"El argumento '{pattern}' sugiere una accion intrusiva/explotadora "
                "y fue bloqueado. Ajusta el escaneo a un modo pasivo y descriptivo."
            )


def run_safe(command: list[str], timeout: int = 300) -> CommandResult:
    """Ejecuta un comando externo SOLO si pasa los guardarrailes.

    Lanza ExploitationBlocked si el comando es inseguro, o RuntimeError si el
    binario no esta instalado.
    """
    _assert_command_is_safe(command)

    binary = command[0].replace("\\", "/").split("/")[-1]
    binary = binary[:-4] if binary.lower().endswith(".exe") else binary
    if not is_tool_available(binary):
        raise RuntimeError(
            f"La herramienta '{binary}' no esta instalada o no esta en el PATH."
        )

    proc = subprocess.run(  # noqa: S603 - comando validado por lista blanca
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return CommandResult(
        command=command,
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )
