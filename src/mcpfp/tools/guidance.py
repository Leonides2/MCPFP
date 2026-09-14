"""Tutor pedagogico: guia paso a paso sin explotar.

Dado un tema o categoria OWASP, devuelve:
  - acercamientos "obvios" (lo primero que un analista revisaria),
  - fuentes "no tan obvias" (donde suele esconderse informacion util),
  - el siguiente paso sugerido, siempre manual y no destructivo.

Nunca entrega un exploit ni comandos de ataque. Guia el razonamiento.
"""

from __future__ import annotations

# Guias por tema. Cada entrada: (obvios, no_obvios, siguiente_paso).
GUIDANCE: dict[str, dict[str, list[str]]] = {
    "reconocimiento": {
        "obvios": [
            "Lista los puertos abiertos y el servicio/version de cada uno.",
            "Abre en el navegador cada servicio web y observa la pagina inicial.",
            "Anota banners y numeros de version exactos.",
        ],
        "no_obvios": [
            "Revisa robots.txt, sitemap.xml y rutas comunes (/admin, /backup, /.git).",
            "Inspecciona el codigo fuente HTML y los comentarios.",
            "Busca cabeceras Server/X-Powered-By que delaten versiones.",
        ],
        "siguiente": [
            "Contrasta cada version detectada con avisos de seguridad publicos (leer, no explotar).",
        ],
    },
    "a01": {
        "obvios": [
            "Prueba acceder directamente a rutas administrativas sin autenticarte.",
            "Observa si hay listado de directorios habilitado.",
        ],
        "no_obvios": [
            "Fijate en IDs secuenciales o predecibles en URLs y parametros.",
            "Revisa si recursos privados se sirven sin verificar sesion (solo observar).",
        ],
        "siguiente": [
            "Documenta el control de acceso ausente; no manipules datos de otros usuarios.",
        ],
    },
    "a02": {
        "obvios": [
            "Verifica si el sitio ofrece HTTP en claro cuando deberia ser HTTPS.",
            "Revisa la version de TLS y la validez del certificado.",
        ],
        "no_obvios": [
            "Comprueba flags de cookies (Secure, HttpOnly, SameSite).",
            "Busca datos sensibles transmitidos o almacenados sin cifrar.",
        ],
        "siguiente": [
            "Relaciona los hallazgos con cifrados/protocolos obsoletos y documentalo.",
        ],
    },
    "a05": {
        "obvios": [
            "Lista las cabeceras de seguridad ausentes.",
            "Busca paginas o credenciales por defecto del software detectado.",
        ],
        "no_obvios": [
            "Provoca un error y observa si el servidor muestra trazas/versiones (stack traces).",
            "Busca archivos de configuracion o backups expuestos.",
        ],
        "siguiente": [
            "Agrupa las malas configuraciones y propon el hardening correspondiente.",
        ],
    },
    "a06": {
        "obvios": [
            "Anota versiones de servidor web, framework y librerias visibles.",
        ],
        "no_obvios": [
            "Correlaciona esas versiones con listas de componentes conocidos vulnerables (leer avisos).",
        ],
        "siguiente": [
            "Documenta el componente y la version; recomienda actualizar. No lances exploits.",
        ],
    },
    "bandera": {
        "obvios": [
            "Revisa ubicaciones tipicas de flags en labs: raiz web, /home de usuarios, archivos de texto expuestos.",
            "Lee mensajes, comentarios y archivos que el servicio ya expone publicamente.",
        ],
        "no_obvios": [
            "Fijate en metadatos, archivos ocultos y respuestas inusuales del servidor.",
            "Correlaciona pistas del reconocimiento (nombres, versiones) con posibles rutas.",
        ],
        "siguiente": [
            "Si la flag requiere aprovechar una vulnerabilidad, el MCP se detiene: describe la "
            "debilidad y el enfoque conceptual, y TU decides y ejecutas el paso final, con autorizacion.",
        ],
    },
}

_ALIASES = {
    "recon": "reconocimiento",
    "flag": "bandera",
    "access control": "a01",
    "crypto": "a02",
    "misconfiguration": "a05",
    "components": "a06",
}


def get_guidance(topic: str) -> str:
    """Devuelve una guia pedagogica para un tema o categoria OWASP.

    Args:
        topic: p. ej. "reconocimiento", "a01", "a02", "a05", "a06", "bandera".
    """
    key = topic.strip().lower()
    key = _ALIASES.get(key, key)
    guia = GUIDANCE.get(key)

    if guia is None:
        disponibles = ", ".join(sorted(set(GUIDANCE) | set(_ALIASES)))
        return (
            f"No tengo una guia especifica para '{topic}'.\n"
            f"Temas disponibles: {disponibles}."
        )

    lineas = [f"# Guia: {topic}", ""]
    lineas.append("## Acercamientos obvios")
    lineas.extend(f"- {x}" for x in guia["obvios"])
    lineas.append("")
    lineas.append("## Fuentes no tan obvias")
    lineas.extend(f"- {x}" for x in guia["no_obvios"])
    lineas.append("")
    lineas.append("## Siguiente paso sugerido")
    lineas.extend(f"- {x}" for x in guia["siguiente"])
    lineas.append("")
    lineas.append(
        "> Recordatorio: esto es orientacion para tu analisis manual. El MCP no "
        "ejecuta la explotacion bajo ninguna circunstancia."
    )
    return "\n".join(lineas)
