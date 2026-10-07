# carboys-arca

Servidor puente entre la app CarBoys y los web services de ARCA (ex AFIP):
**WSAA** (permiso de acceso), **WSFEv1** (facturas y notas de crédito electrónicas)
y **Padrón** (datos del contribuyente por CUIT). Corre en Railway; la app lo llama
con la sesión de Google del usuario.

## Cómo autentica

1. **Sesión de Google (Firebase ID token)** en `Authorization: Bearer …`. Es la única
   llave. Un token inválido o vencido se rechaza con **401** (no hay otro camino).
2. La app manda además `X-Carboys-User: <id del usuario de la tablet>`. El servidor lee
   `users/{id}` y `meta/config` de la nube de esa sucursal (con el mismo token) y
   exige el permiso **facturar** (igual que la app: `perms.facturar` manda; si no, el
   rol; el encargado sólo si `encargadoPuedeFacturar` está activo). Sin permiso → **403**.
3. `x-api-key` sólo se acepta si está definida `ARCA_API_KEY` **y** el pedido no trae
   token. La clave vieja publicada (`carboys-arca-2026`) se ignora aunque esté definida.

## Variables de entorno (Railway)

| Variable | Obligatoria | Qué es |
|---|---|---|
| `ARCA_ENV` | **sí** | `production` o `homologacion`. Si falta, el servidor arranca pero **no emite** (503) y `/api/health` lo informa. |
| `ENTITY1_CUIT`, `ENTITY1_CERT`, `ENTITY1_KEY` | sí (al menos una entidad) | CUIT y certificado/clave privada (PEM en **base64**) de CARBOYS S.A.S. (FC A/B). |
| `ENTITY2_CUIT`, `ENTITY2_CERT`, `ENTITY2_KEY` | opcional | Ídem para la entidad monotributista (FC C). |
| `FIREBASE_PROJECTS` | recomendada | Proyectos de Firebase cuyos usuarios pueden facturar, separados por coma. Default `carboys-6625b`. |
| `ARCA_ALLOWED_EMAILS` | opcional | Si se define, sólo esos Gmail pueden facturar. |
| `ARCA_ALLOWED_ORIGINS` | recomendada | Dominios de la app permitidos por CORS, separados por coma (ej. `https://carboysapp.vercel.app`). Vacío = cualquiera. |
| `ARCA_API_KEY` | no | Clave compartida opcional para integraciones sin Google. **No usar la vieja.** |
| `ARCA_TLS_INSECURE` | no | `1` desactiva la validación del certificado de AFIP. Sólo para diagnóstico; en producción no definir. |
| `PORT` | no | Puerto (Railway lo define). |

Sólo para pruebas automáticas (nunca en Railway): `GOOGLE_CERTS_URL`, `FIRESTORE_BASE_URL`,
`ARCA_WSAA_URL`, `ARCA_WSFE_URL`, `ARCA_PADRON_URL`, `ARCA_CONSTANCIA_URL`.

Para pasar un PEM a base64: `base64 -w0 archivo.pem`.

## Endpoints

| Método y ruta | Auth | Qué hace |
|---|---|---|
| `GET /api/health` | no | Estado mínimo: `status`, `version`, `env`, `configuracionCompleta`. La app muestra un aviso si `env` no es `production`. |
| `GET /api/health/detalle` | token | Diagnóstico completo (entidades, auth, CORS, TLS). |
| `GET /api/padron?cuit=&entity=` | token | Datos del contribuyente: primero Constancia de Inscripción (trae los impuestos → condición IVA) y, si falla, Padrón A13 (solo nombre y domicilio). Devuelve `condIva`, `condIvaId` y `condIvaDeterminada` (false = no se pudo saber; la app respeta la letra elegida). Límite 30/min. |
| `POST /api/facturar` | token + permiso | Emite FC A/B/C. Cuerpo: `entityId, puntoVenta, tipoFactura, docTipo, docNro, importeTotal, importeNeto, importeIva, concepto, fchServDesde, fchServHasta, fchVtoPago, condicionIVAReceptor, actividad`. Todo se valida (400 con el motivo). |
| `POST /api/nota-credito` | token + permiso | Ídem más `facturaOriginal: { tipo, ptoVta, nro, fecha }`. Misma letra que la FC. |
| `POST /api/recuperar` | token + permiso | Si se cortó la conexión después de pedir el CAE: busca el último comprobante autorizado y, si coincide con lo que se intentó emitir (documento, importe, fecha de hoy) y fue autorizado hace menos de 20 minutos, devuelve su CAE. |
| `POST /api/ultimo-comprobante` | token | Último número autorizado para `entityId, puntoVenta, tipoComprobante`. |
| `POST /api/auth` | token | Fuerza la obtención del permiso de ARCA (TA). |

Respuesta de una emisión exitosa: `{ success, cae, caeVto, cbteNro, cbteTipo, puntoVenta, cbteFch, cbteFchIso,
cuitEmisor, entityId, observaciones, recuperada, emitidoPor, enviado: {…lo que se mandó a ARCA} }`.
La app guarda todo eso junto con la factura.

## Garantías de la emisión

- Una emisión por vez por (entidad, punto de venta, tipo): no se pisan números. Si ARCA
  responde 10016 se consulta el último número y se reintenta una vez.
- Si se corta la conexión con AFIP después de pedir el CAE, se consulta (FECompConsultar)
  si el comprobante salió antes de darlo por fallido.
- El permiso de ARCA (TA, 12 h) se guarda en la nube de la sucursal
  (`meta/arca_ta_{entidad}_{servicio}`) y se reutiliza al reiniciar.
- Fecha del comprobante en hora Argentina. `CondicionIVAReceptorId` siempre informado.
- Se valida el certificado TLS de AFIP. Logs sin datos personales.

## Pruebas

```
npm install
npm test
```

`test/unit.mjs` prueba las funciones puras; `test/run.mjs` levanta servidores simulados de
Google, Firestore, WSAA, WSFEv1 y Padrón, arranca `server.js` contra ellos y recorre
autenticación, permisos, validaciones, emisión A/B/C, notas de crédito, numeración
concurrente, cortes de conexión, recuperación, reinicios y configuraciones incorrectas.
No toca AFIP ni la nube real. Requiere `openssl` en el PATH.

## Deploy

Railway construye la imagen del `Dockerfile` (`npm ci --omit=dev`, usuario sin privilegios,
`HEALTHCHECK` sobre `/api/health`). Después de cada deploy conviene abrir
`/api/health` y confirmar `"env":"production"` y `"configuracionCompleta":true`.
