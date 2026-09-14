---
name: ciberseguridad-owasp-iso27001
description: Metodologia para abordar una evaluacion de ciberseguridad defensiva siguiendo OWASP (Top 10) e ISO/IEC 27001. Usala cuando el usuario quiera planear, documentar o guiar una revision de seguridad de un sistema o laboratorio de forma estructurada y etica, describiendo vulnerabilidades y su remediacion SIN explotarlas. Cubre alcance/autorizacion, reconocimiento, mapeo OWASP, correlacion con controles ISO 27001 Anexo A, y reporte.
---

# Abordaje de ciberseguridad: OWASP + ISO/IEC 27001

Esta skill describe **como abordar** una evaluacion de seguridad de forma
metodica, etica y defensiva. **No explota** vulnerabilidades: las identifica,
las describe y propone remediacion. La verificacion activa la ejecuta una
persona autorizada, sobre un entorno propio o con permiso explicito.

## Principio rector

> Describir, no explotar. Cada hallazgo se documenta con impacto y remediacion.
> El paso ofensivo final, si existe, queda fuera del alcance de esta guia.

## Fase 0 - Alcance y autorizacion (obligatorio)

Antes de cualquier accion tecnica:

1. Confirma **autorizacion escrita** sobre el objetivo (o que es un laboratorio propio).
2. Define el **alcance**: hosts, rangos, servicios, ventana de tiempo.
3. Registra reglas de compromiso: que esta permitido y que no.
4. ISO 27001: esto se alinea con **A.5 (politicas)** y la gestion de riesgos
   de la clausula 6.

## Fase 1 - Reconocimiento (pasivo primero)

- Enumera puertos, servicios y versiones (sin scripts intrusivos).
- Revisa fuentes obvias: pagina inicial, banners, cabeceras.
- Revisa fuentes **no tan obvias**: `robots.txt`, `sitemap.xml`, comentarios en
  el HTML, rutas comunes, metadatos, archivos de backup expuestos.
- Correlaciona versiones con avisos publicos (leer, no explotar).

## Fase 2 - Mapeo a OWASP Top 10 (2021)

Para cada servicio web, clasifica los hallazgos observables:

| OWASP | Foco | Control ISO 27001 (Anexo A 2022) relacionado |
|-------|------|----------------------------------------------|
| A01 Broken Access Control | Autorizacion, rutas admin | A.8.3 Restriccion de acceso a la informacion |
| A02 Cryptographic Failures | TLS, cifrado, cookies | A.8.24 Uso de criptografia |
| A03 Injection | Validacion de entrada | A.8.28 Codificacion segura |
| A04 Insecure Design | Diseno de controles | A.8.27 Principios de ingenieria segura |
| A05 Security Misconfiguration | Hardening, cabeceras | A.8.9 Gestion de configuracion |
| A06 Componentes vulnerables | Versiones desactualizadas | A.8.8 Gestion de vulnerabilidades tecnicas |
| A07 Auth Failures | Autenticacion, sesiones | A.8.5 Autenticacion segura |
| A08 Integrity Failures | Integridad de software/datos | A.8.28 / A.8.19 |
| A09 Logging & Monitoring | Registro y monitoreo | A.8.15 Registro / A.8.16 Monitoreo |
| A10 SSRF | Peticiones del servidor | A.8.28 Codificacion segura |

## Fase 3 - Analisis y priorizacion

- Estima **impacto x probabilidad** para cada hallazgo (riesgo).
- Prioriza por criticidad, no por facilidad.
- ISO 27001: alimenta el **tratamiento de riesgos** (clausula 6.1.3) y la
  **Declaracion de Aplicabilidad (SoA)**.

## Fase 4 - Reporte

Estructura recomendada del informe:

1. Resumen ejecutivo (riesgo general, hallazgos clave).
2. Alcance y metodologia.
3. Hallazgos: descripcion, evidencia observada, categoria OWASP, control ISO,
   impacto y **remediacion** concreta.
4. Recomendaciones priorizadas.
5. Anexos.

## Fase 5 - Remediacion y mejora continua

- Propon controles concretos y verifica su implementacion (re-test defensivo).
- ISO 27001: cierra el ciclo con **mejora continua (clausula 10)**.

## Que NO hace esta metodologia

- No lanza exploits, fuerza bruta, inyecciones ni ataques de denegacion.
- No extrae datos aprovechando fallos.
- No evade controles de deteccion.

Si un ejercicio (p. ej. capturar una bandera CTF) requiere explotar, esta guia
llega hasta **describir la debilidad y el enfoque conceptual**; el paso final
lo decide y ejecuta la persona autorizada.
