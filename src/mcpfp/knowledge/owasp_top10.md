# OWASP Top 10 (2021) - referencia rapida

| Codigo | Categoria | Que observar de forma pasiva |
|--------|-----------|------------------------------|
| A01 | Broken Access Control | Rutas admin sin auth, directory listing, IDs predecibles |
| A02 | Cryptographic Failures | HTTP en claro, TLS obsoleto, cookies sin Secure/HttpOnly |
| A03 | Injection | Parametros/formularios sin validacion (revisar diseno, no inyectar) |
| A04 | Insecure Design | Falta de controles esperados en el flujo |
| A05 | Security Misconfiguration | Cabeceras ausentes, paginas/credenciales por defecto, errores verbosos |
| A06 | Vulnerable & Outdated Components | Versiones antiguas detectadas por fingerprinting |
| A07 | Identification & Auth Failures | Login sin proteccion anti fuerza bruta, sesiones debiles |
| A08 | Software & Data Integrity Failures | Recursos sin integridad, updates sin firmar |
| A09 | Logging & Monitoring Failures | Ausencia de registro/monitoreo |
| A10 | SSRF | Parametros que aceptan URLs |

> Principio: el analisis es **descriptivo**. Ninguna categoria se "verifica"
> enviando exploits desde este MCP.
