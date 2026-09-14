# Comprobaciones de protocolo (pasivas)

## HTTP
- Cabeceras de seguridad: `Strict-Transport-Security`, `Content-Security-Policy`,
  `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`.
- Cookies: flags `Secure`, `HttpOnly`, `SameSite`.
- Banners: `Server`, `X-Powered-By` (delatan versiones -> A06).
- Errores verbosos / stack traces -> A05.

## TLS
- Versiones a evitar: SSLv2/SSLv3, TLS 1.0, TLS 1.1.
- Certificado: vigencia, CN/SAN correcto, cadena valida.
- Suites de cifrado debiles (RC4, DES, export).

## DNS / red
- Registros expuestos, transferencias de zona mal configuradas (solo observar).
- Servicios inesperados en puertos no estandar.

> Todas estas comprobaciones leen lo que el servicio ya expone. No se envian
> payloads de ataque ni se fuerza el servicio.
