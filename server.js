// ══════════════════════════════════════════════════════════════════
//  CarBoys ARCA Server — v15
// ──────────────────────────────────────────────────────────────────
//  Puente entre la app del taller y los web services de ARCA (AFIP):
//  WSAA (permiso), WSFEv1 (facturas y notas de crédito) y Padrón.
//
//  QUÉ CAMBIÓ EN v15 (auditoría 2026-10, bloque 1):
//   · Entrar con Google es la única llave. La clave compartida que viajaba
//     dentro de la app ya no existe por defecto: sólo se acepta si está
//     definida en ARCA_API_KEY (la vieja "carboys-arca-2026" se ignora).
//     Un token de Google inválido se rechaza con 401; antes caía a la clave.
//   · El servidor exige el permiso "facturar" del usuario de la tablet
//     (lee users/{id} y meta/config de la nube con el mismo token).
//   · Se valida el certificado de ARCA (antes rejectUnauthorized:false).
//   · Fecha del comprobante en hora Argentina (antes Greenwich).
//   · Validación estricta de lo que manda la app: sin valores por defecto,
//     neto + IVA = total, tipo de documento según letra, condición IVA del
//     receptor obligatoria (RG 5616), fechas con formato.
//   · Una emisión por vez por (entidad, punto de venta, tipo): no se pisan
//     los números. Si ARCA responde 10016 se reintenta una vez.
//   · Si se corta la conexión con ARCA después de pedir el CAE, se consulta
//     si el comprobante salió (FECompConsultar) antes de darlo por fallido.
//     Y /api/recuperar permite a la app hacer lo mismo si se cortó entre la
//     app y este servidor.
//   · El permiso de ARCA (TA, dura 12 h) se guarda en la nube de la sucursal
//     y se reutiliza al reiniciar: antes cada deploy podía dejar sin
//     facturar hasta 12 h.
//   · Respuesta completa: fecha real, CUIT emisor, observaciones de ARCA y
//     lo que se envió, para que la app lo guarde con la factura.
//   · Logs sin datos personales; límite de pedidos por usuario; /api/health
//     mínimo (el detalle requiere autenticación); sin endpoint de prueba.
// ══════════════════════════════════════════════════════════════════

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const https = require('https');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execSync } = require('child_process');

const VERSION = 'v15-auditoria-b1';
const app = express();

// ── CORS ──
// Por defecto acepta cualquier origen (comportamiento histórico). Para
// restringirlo: ARCA_ALLOWED_ORIGINS="https://carboysapp.vercel.app,https://..."
const ALLOWED_ORIGINS = (process.env.ARCA_ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);
app.use(cors(ALLOWED_ORIGINS.length ? { origin: ALLOWED_ORIGINS } : {}));
app.use(express.json({ limit: '1mb' }));

// ══════════════════════════════════════════════════════════════════
// CONFIG
// ══════════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 3000;

// La clave compartida es OPCIONAL y ya no tiene valor por defecto. Si no
// está definida, el único camino es el token de Google. La clave vieja,
// que quedó publicada en el código, está prohibida.
const CLAVE_VIEJA_PROHIBIDA = 'carboys-arca-2026';
let API_KEY = process.env.ARCA_API_KEY || '';
if (API_KEY === CLAVE_VIEJA_PROHIBIDA) {
  // No se corta el arranque (dejaría la facturación caída): la clave vieja
  // simplemente deja de valer y queda sólo el camino de Google.
  console.error('[CONFIG] ⚠️  ARCA_API_KEY tiene la clave vieja publicada: se IGNORA. Borrá la variable o elegí otra.');
  API_KEY = '';
}

const ARCA_ENV = String(process.env.ARCA_ENV || '').trim().toLowerCase();
const IS_PRODUCTION = ARCA_ENV === 'production';
const ENV_VALIDO = ARCA_ENV === 'production' || ARCA_ENV === 'homologacion';

// Proyectos de Firebase cuyos usuarios pueden facturar (uno por sucursal).
const FIREBASE_PROJECTS = (process.env.FIREBASE_PROJECTS || 'carboys-6625b')
  .split(',').map(s => s.trim()).filter(Boolean);

// Lista opcional de emails habilitados. Vacía = cualquier usuario de un proyecto permitido.
const ALLOWED_EMAILS = (process.env.ARCA_ALLOWED_EMAILS || '')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

// Sólo para pruebas: ARCA_TLS_INSECURE=1 vuelve a aceptar cualquier certificado
// de AFIP (la v14 lo hacía siempre). En producción debe quedar sin definir.
const TLS_INSECURE = process.env.ARCA_TLS_INSECURE === '1';
if (TLS_INSECURE) console.warn('[CONFIG] ⚠️  ARCA_TLS_INSECURE=1: NO se valida el certificado de AFIP');

// Las URLs de AFIP y de Firestore se pueden reemplazar por variables de
// entorno ÚNICAMENTE para pruebas automáticas (servidores simulados).
// En Railway no deben definirse.
const WSAA_URL = process.env.ARCA_WSAA_URL || (IS_PRODUCTION
  ? 'https://wsaa.afip.gov.ar/ws/services/LoginCms'
  : 'https://wsaahomo.afip.gov.ar/ws/services/LoginCms');
const WSFE_URL = process.env.ARCA_WSFE_URL || (IS_PRODUCTION
  ? 'https://servicios1.afip.gov.ar/wsfev1/service.asmx'
  : 'https://wswhomo.afip.gov.ar/wsfev1/service.asmx');
const PADRON_URL = process.env.ARCA_PADRON_URL || (IS_PRODUCTION
  ? 'https://aws.afip.gov.ar/sr-padron/webservices/personaServiceA13'
  : 'https://awshomo.afip.gov.ar/sr-padron/webservices/personaServiceA13');
const CONSTANCIA_URL = process.env.ARCA_CONSTANCIA_URL || (IS_PRODUCTION
  ? 'https://aws.afip.gov.ar/sr-padron/webservices/personaServiceA5'
  : 'https://awshomo.afip.gov.ar/sr-padron/webservices/personaServiceA5');
const FIRESTORE_BASE_URL = process.env.FIRESTORE_BASE_URL || 'https://firestore.googleapis.com';
if (process.env.ARCA_WSAA_URL || process.env.ARCA_WSFE_URL || process.env.FIRESTORE_BASE_URL) {
  console.warn('[CONFIG] ⚠️  URLs de AFIP/Firestore reemplazadas por variables de entorno (sólo para pruebas)');
}

// ── Certificados (PEM en base64 en variables de entorno) ──
const decodeEnv = (v) => v ? Buffer.from(v, 'base64').toString('utf8') : '';

const ENTITIES = {
  '1': {
    name: 'CARBOYS S.A.S.',
    cuit: String(process.env.ENTITY1_CUIT || '30717454681').replace(/\D/g, ''),
    cert: decodeEnv(process.env.ENTITY1_CERT),
    key: decodeEnv(process.env.ENTITY1_KEY),
  },
  '2': {
    name: 'KARQUI VICTOR LISANDRO IGNACIO',
    cuit: String(process.env.ENTITY2_CUIT || '20344412171').replace(/\D/g, ''),
    cert: decodeEnv(process.env.ENTITY2_CERT),
    key: decodeEnv(process.env.ENTITY2_KEY),
  },
};
const entidadDisponible = (id) => !!(ENTITIES[id] && ENTITIES[id].cert && ENTITIES[id].key);

// Problemas de configuración que impiden emitir. Se informan en el arranque,
// en /api/health y en cada intento de emisión (503), en vez de emitir mal.
const CONFIG_ERRORES = [];
if (!ENV_VALIDO) CONFIG_ERRORES.push('ARCA_ENV debe ser "production" o "homologacion"');
if (!entidadDisponible('1') && !entidadDisponible('2')) CONFIG_ERRORES.push('Ninguna entidad tiene certificado y clave (ENTITY1_CERT/KEY, ENTITY2_CERT/KEY)');

// ══════════════════════════════════════════════════════════════════
// FECHAS — siempre en hora Argentina
// ══════════════════════════════════════════════════════════════════
const _fmtAR = new Intl.DateTimeFormat('en-CA', {
  timeZone: 'America/Argentina/Buenos_Aires', year: 'numeric', month: '2-digit', day: '2-digit',
});
const _fmtARHora = new Intl.DateTimeFormat('en-CA', {
  timeZone: 'America/Argentina/Buenos_Aires', year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
});
// "20261006" (formato que pide ARCA) para el instante dado, en hora Argentina.
const fechaArgentinaYmd = (d = new Date()) => _fmtAR.format(d).replace(/-/g, '');
// "20261006" → "2026-10-06"
const ymdAIso = (ymd) => /^\d{8}$/.test(String(ymd)) ? `${ymd.slice(0, 4)}-${ymd.slice(4, 6)}-${ymd.slice(6, 8)}` : '';
// acepta "20261006" o "2026-10-06" → "20261006"; '' si no es fecha
const aYmd = (v) => {
  const s = String(v || '').trim().replace(/-/g, '');
  return /^\d{8}$/.test(s) ? s : '';
};

// ══════════════════════════════════════════════════════════════════
// AUTENTICACIÓN — Google (Firebase) como única llave
// ══════════════════════════════════════════════════════════════════
const GOOGLE_CERTS_URL = process.env.GOOGLE_CERTS_URL ||
  'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';

let _certsCache = { keys: null, expiry: 0 };

function fetchGoogleCerts() {
  return new Promise((resolve, reject) => {
    const mod = GOOGLE_CERTS_URL.startsWith('http://') ? http : https;
    const req = mod.get(GOOGLE_CERTS_URL, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        if (res.statusCode !== 200) return reject(new Error(`certs HTTP ${res.statusCode}`));
        try {
          const keys = JSON.parse(data);
          const maxAge = /max-age=(\d+)/.exec(res.headers['cache-control'] || '');
          resolve({ keys, ttl: (maxAge ? parseInt(maxAge[1], 10) : 3600) * 1000 });
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.setTimeout(10000, () => req.destroy(new Error('timeout pidiendo certs a Google')));
  });
}

async function getGoogleCerts() {
  if (_certsCache.keys && _certsCache.expiry > Date.now()) return _certsCache.keys;
  const { keys, ttl } = await fetchGoogleCerts();
  _certsCache = { keys, expiry: Date.now() + ttl };
  return keys;
}

const b64url = (s) => Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');

async function verifyFirebaseToken(token) {
  const parts = String(token).split('.');
  if (parts.length !== 3) throw new Error('token mal formado');
  const header = JSON.parse(b64url(parts[0]).toString('utf8'));
  const payload = JSON.parse(b64url(parts[1]).toString('utf8'));
  if (header.alg !== 'RS256') throw new Error(`alg no soportado: ${header.alg}`);
  if (!header.kid) throw new Error('header sin kid');

  const certs = await getGoogleCerts();
  const certPem = certs[header.kid];
  if (!certPem) throw new Error('kid desconocido');
  const publicKey = new crypto.X509Certificate(certPem).publicKey;
  const firmaOk = crypto.createVerify('RSA-SHA256')
    .update(`${parts[0]}.${parts[1]}`)
    .verify(publicKey, b64url(parts[2]));
  if (!firmaOk) throw new Error('firma invalida');

  const now = Math.floor(Date.now() / 1000);
  if (!payload.exp || payload.exp <= now) throw new Error('token vencido');
  if (payload.iat && payload.iat > now + 300) throw new Error('iat en el futuro');
  if (!payload.sub) throw new Error('token sin sub');
  if (!FIREBASE_PROJECTS.includes(payload.aud)) throw new Error(`proyecto no autorizado: ${payload.aud}`);
  if (payload.iss !== `https://securetoken.google.com/${payload.aud}`) throw new Error(`emisor invalido: ${payload.iss}`);

  const email = String(payload.email || '').toLowerCase();
  if (ALLOWED_EMAILS.length && !ALLOWED_EMAILS.includes(email)) {
    throw new Error(`email no habilitado para facturar: ${email || '(sin email)'}`);
  }
  return payload;
}

// Un token de Google inválido se RECHAZA (401). Ya no cae a la clave: eso
// convertía la verificación en decorativa. La clave compartida sólo vale si
// está definida en ARCA_API_KEY y el pedido no trae token.
const auth = async (req, res, next) => {
  const bearer = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  if (bearer) {
    try {
      const payload = await verifyFirebaseToken(bearer[1]);
      req.authUser = { via: 'firebase', email: payload.email || null, uid: payload.sub, proyecto: payload.aud };
      // Contexto para leer/escribir en la nube de ESA sucursal con su propio token.
      req.fsCtx = { project: payload.aud, idToken: bearer[1] };
      return next();
    } catch (e) {
      console.warn(`[AUTH] token rechazado: ${e.message}`);
      return res.status(401).json({ success: false, error: 'Sesión de Google inválida o vencida. Cerrá sesión y volvé a entrar.', detalle: e.message });
    }
  }
  const key = req.headers['x-api-key'];
  if (API_KEY && key && key === API_KEY) {
    req.authUser = { via: 'api-key', email: null, uid: null, proyecto: null };
    req.fsCtx = null;
    return next();
  }
  return res.status(401).json({ success: false, error: 'No autenticado' });
};

const quien = (req) => {
  const u = req.authUser || {};
  const base = u.via === 'firebase' ? (u.email || u.uid) : 'api-key';
  return req.usuarioTablet ? `${base} / ${req.usuarioTablet}` : base;
};

// ══════════════════════════════════════════════════════════════════
// FIRESTORE (REST) — con el token del usuario, en el proyecto de su sucursal
// ══════════════════════════════════════════════════════════════════
function fsRequest(ctx, method, docPath, body, query) {
  return new Promise((resolve, reject) => {
    const qs = query ? '?' + query : '';
    const base = new URL(FIRESTORE_BASE_URL);
    const mod = base.protocol === 'http:' ? http : https;
    const options = {
      hostname: base.hostname, port: base.port || (base.protocol === 'http:' ? 80 : 443), method,
      path: `/v1/projects/${encodeURIComponent(ctx.project)}/databases/(default)/documents/${docPath}${qs}`,
      headers: { 'Authorization': `Bearer ${ctx.idToken}`, 'Content-Type': 'application/json' },
    };
    const req = mod.request(options, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        let json = null;
        try { json = data ? JSON.parse(data) : null; } catch (e) { /* respuesta no JSON */ }
        resolve({ status: res.statusCode, json });
      });
    });
    req.on('error', reject);
    req.setTimeout(8000, () => req.destroy(new Error('timeout Firestore')));
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// Lee un documento. Devuelve {fields} si existe, null si no existe (404), y
// LANZA ante cualquier otro error: no se confunde "no existe" con "falló".
async function fsGetDoc(ctx, docPath) {
  const r = await fsRequest(ctx, 'GET', docPath);
  if (r.status === 404) return null;
  if (r.status !== 200 || !r.json) throw new Error(`Firestore GET ${docPath} → ${r.status}`);
  return r.json.fields || {};
}

async function fsPatchDoc(ctx, docPath, fields) {
  const mask = Object.keys(fields).map(k => 'updateMask.fieldPaths=' + encodeURIComponent(k)).join('&');
  const r = await fsRequest(ctx, 'PATCH', docPath, { fields }, mask);
  if (r.status !== 200) throw new Error(`Firestore PATCH ${docPath} → ${r.status}`);
  return true;
}

// Decodificadores mínimos de valores de Firestore.
const fvStr = (f) => (f && (f.stringValue != null ? String(f.stringValue) : f.integerValue != null ? String(f.integerValue) : '')) || '';
const fvBool = (f) => !!(f && f.booleanValue === true);
const fvInt = (f) => (f && f.integerValue != null) ? parseInt(f.integerValue, 10) : (f && f.doubleValue != null ? Math.round(f.doubleValue) : 0);
const fvMap = (f) => (f && f.mapValue && f.mapValue.fields) || null;

// ══════════════════════════════════════════════════════════════════
// PERMISO "facturar" DEL USUARIO DE LA TABLET
// ══════════════════════════════════════════════════════════════════
// El token de Google identifica a la sucursal (su cuenta de Gmail). La
// persona concreta es el usuario de la tablet (users/{id}), que la app
// manda en X-Carboys-User. Acá se lee ese documento de la nube de la
// sucursal, con el mismo token, y se verifica que tenga permiso "facturar"
// (igual que la app: perms.facturar manda; si no, el rol; y el encargado
// puede si meta/config.encargadoPuedeFacturar está activo).
const ROL_FACTURA_POR_DEFECTO = {
  'dueño': true, 'dueno': true, 'gerente_sucursal': true, 'admin': true,
  'encargado': false, 'mecánico': false, 'mecanico': false,
};
const _permCache = new Map(); // `${project}/${userId}` → { ok, nombre, expiry }

async function usuarioPuedeFacturar(ctx, userId) {
  const key = `${ctx.project}/${userId}`;
  const hit = _permCache.get(key);
  if (hit && hit.expiry > Date.now()) return hit;

  const u = await fsGetDoc(ctx, `users/${encodeURIComponent(String(userId))}`);
  let out;
  if (!u) {
    out = { ok: false, nombre: '', motivo: 'usuario de la tablet desconocido' };
  } else {
    const rol = fvStr(u.role).toLowerCase();
    const nombre = fvStr(u.name);
    const perms = fvMap(u.perms);
    if (perms && perms.facturar !== undefined) {
      out = { ok: fvBool(perms.facturar), nombre, motivo: 'permiso explícito' };
    } else if (rol === 'encargado') {
      let puede = false;
      try { const cfg = await fsGetDoc(ctx, 'meta/config'); puede = !!(cfg && fvBool(cfg.encargadoPuedeFacturar)); } catch (e) { puede = false; }
      out = { ok: puede, nombre, motivo: puede ? 'encargado habilitado en configuración' : 'encargado sin habilitación' };
    } else {
      out = { ok: !!ROL_FACTURA_POR_DEFECTO[rol], nombre, motivo: `rol ${rol || '(sin rol)'}` };
    }
  }
  out.expiry = Date.now() + 60000;
  _permCache.set(key, out);
  return out;
}

// Middleware: exige el permiso. Con api-key (sin sucursal) no se puede
// verificar: se deja pasar y se anota.
const requierePermisoFacturar = async (req, res, next) => {
  if (!req.fsCtx) return next();   // api-key: sin sucursal, no hay usuario que verificar
  const userId = String(req.headers['x-carboys-user'] || '').trim();
  if (!userId) {
    return res.status(403).json({ success: false, error: 'La app no identificó al usuario de la tablet (actualizá la app).' });
  }
  try {
    const p = await usuarioPuedeFacturar(req.fsCtx, userId);
    if (!p.ok) {
      console.warn(`[PERM] facturar denegado a usuario ${userId} (${p.motivo}) — ${quien(req)}`);
      return res.status(403).json({ success: false, error: `El usuario ${p.nombre || userId} no tiene permiso para facturar.` });
    }
    req.usuarioTablet = p.nombre || userId;
    return next();
  } catch (e) {
    console.warn(`[PERM] no se pudo verificar el permiso: ${e.message}`);
    return res.status(503).json({ success: false, error: 'No se pudo verificar el permiso del usuario (nube no disponible). Reintentá.' });
  }
};

// ══════════════════════════════════════════════════════════════════
// LÍMITE DE PEDIDOS — en memoria, por usuario (o IP)
// ══════════════════════════════════════════════════════════════════
const _hits = new Map();
const rateLimit = (nombre, max, ventanaMs) => (req, res, next) => {
  const who = (req.authUser && (req.authUser.uid || req.authUser.email)) || req.ip || 'anon';
  const k = `${nombre}:${who}`;
  const now = Date.now();
  const arr = (_hits.get(k) || []).filter(t => now - t < ventanaMs);
  if (arr.length >= max) return res.status(429).json({ success: false, error: 'Demasiados pedidos seguidos. Esperá un momento.' });
  arr.push(now); _hits.set(k, arr);
  if (_hits.size > 5000) _hits.clear();
  next();
};

// ══════════════════════════════════════════════════════════════════
// SOAP hacia AFIP
// ══════════════════════════════════════════════════════════════════
// Devuelve el cuerpo; LANZA si HTTP no es 2xx (los SOAP Fault de AFIP
// vienen con 500 y se leen igual, pero el llamador decide).
function soapRequest(url, body, soapAction, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const mod = urlObj.protocol === 'http:' ? http : https;
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || (urlObj.protocol === 'http:' ? 80 : 443),
      path: urlObj.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'text/xml; charset=utf-8',
        'Content-Length': Buffer.byteLength(body),
        ...(soapAction !== undefined ? { 'SOAPAction': soapAction } : {}),
      },
      rejectUnauthorized: !TLS_INSECURE,
    };
    const req = mod.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) return resolve(data);
        const fault = /<faultstring>([^<]*)<\/faultstring>/.exec(data);
        const err = new Error(`AFIP HTTP ${res.statusCode}${fault ? ': ' + fault[1] : ''}`);
        err.afipBody = data; err.httpStatus = res.statusCode;
        reject(err);
      });
    });
    req.on('error', (e) => {
      const msg = /CERT|certificate|self signed|unable to verify/i.test(e.message)
        ? `Certificado de AFIP no confiable (${e.message}). Si es un problema de la cadena de AFIP, agregar la CA con NODE_EXTRA_CA_CERTS.`
        : e.message;
      const err = new Error(msg); err.transporte = true; reject(err);
    });
    req.setTimeout(timeoutMs, () => { req.destroy(); const err = new Error('Timeout esperando a AFIP'); err.transporte = true; reject(err); });
    req.write(body);
    req.end();
  });
}

// Errores y observaciones del WSFEv1 en forma de lista.
const parseErrores = (xml) => [...String(xml).matchAll(/<Err>[\s\S]*?<Code>(-?\d+)<\/Code>[\s\S]*?<Msg>([\s\S]*?)<\/Msg>[\s\S]*?<\/Err>/g)]
  .map(m => ({ codigo: parseInt(m[1], 10), mensaje: m[2].trim() }));
const parseObs = (xml) => [...String(xml).matchAll(/<Obs>[\s\S]*?<Code>(-?\d+)<\/Code>[\s\S]*?<Msg>([\s\S]*?)<\/Msg>[\s\S]*?<\/Obs>/g)]
  .map(m => ({ codigo: parseInt(m[1], 10), mensaje: m[2].trim() }));
const textoErrores = (lista) => lista.map(e => `${e.codigo}: ${e.mensaje}`).join(' | ');

// ══════════════════════════════════════════════════════════════════
// CANDADOS — una cosa por vez por clave
// ══════════════════════════════════════════════════════════════════
const _locks = new Map();
function conCandado(key, fn) {
  const prev = _locks.get(key) || Promise.resolve();
  const p = prev.catch(() => {}).then(fn);
  _locks.set(key, p);
  p.finally(() => { if (_locks.get(key) === p) _locks.delete(key); }).catch(() => {});
  return p;
}

// ══════════════════════════════════════════════════════════════════
// WSAA — permiso de ARCA (TA), cacheado en memoria y en la nube
// ══════════════════════════════════════════════════════════════════
const tokenCache = {};

function createCMS(certPem, keyPem, service) {
  const now = new Date();
  const expiry = new Date(now.getTime() + 600000);
  const tra = `<?xml version="1.0" encoding="UTF-8"?>
<loginTicketRequest version="1.0">
  <header>
    <uniqueId>${Math.floor(Date.now() / 1000)}</uniqueId>
    <generationTime>${now.toISOString()}</generationTime>
    <expirationTime>${expiry.toISOString()}</expirationTime>
  </header>
  <service>${service}</service>
</loginTicketRequest>`;

  // Carpeta temporal propia, sólo legible por este proceso. La clave privada
  // vive en disco el tiempo que tarda openssl en firmar y se borra siempre.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'arca-'));
  const traFile = path.join(dir, 'tra.xml');
  const cmsFile = path.join(dir, 'tra.cms');
  const certFile = path.join(dir, 'cert.pem');
  const keyFile = path.join(dir, 'key.pem');
  try {
    fs.writeFileSync(traFile, tra, { mode: 0o600 });
    fs.writeFileSync(certFile, certPem, { mode: 0o600 });
    fs.writeFileSync(keyFile, keyPem, { mode: 0o600 });
    execSync(`openssl cms -sign -in "${traFile}" -out "${cmsFile}" -signer "${certFile}" -inkey "${keyFile}" -outform DER -nodetach`, { stdio: 'pipe' });
    return fs.readFileSync(cmsFile).toString('base64');
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) { /* nada */ }
  }
}

const taDocPath = (entityId, service) => `meta/arca_ta_${entityId}_${service}`;

async function leerTAGuardado(ctx, entityId, service) {
  if (!ctx) return null;
  try {
    const f = await fsGetDoc(ctx, taDocPath(entityId, service));
    if (!f) return null;
    const ta = { token: fvStr(f.token), sign: fvStr(f.sign), cuit: fvStr(f.cuit), expiry: fvInt(f.expiry) };
    if (!ta.token || !ta.sign || !(ta.expiry > Date.now() + 60000)) return null;
    return ta;
  } catch (e) {
    console.warn(`[WSAA] no se pudo leer el TA guardado: ${e.message}`);
    return null;
  }
}

async function guardarTA(ctx, entityId, service, ta) {
  if (!ctx) return;
  try {
    await fsPatchDoc(ctx, taDocPath(entityId, service), {
      token: { stringValue: ta.token }, sign: { stringValue: ta.sign }, cuit: { stringValue: ta.cuit },
      expiry: { integerValue: String(ta.expiry) }, guardadoEn: { stringValue: new Date().toISOString() },
    });
  } catch (e) {
    console.warn(`[WSAA] no se pudo guardar el TA en la nube: ${e.message}`);
  }
}

async function getToken(entityId, service = 'wsfe', ctx = null) {
  const entity = ENTITIES[entityId];
  if (!entidadDisponible(entityId)) throw new Error(`Entidad ${entityId} sin certificado configurado`);
  const cacheKey = `${entityId}_${service}`;

  return conCandado(`ta:${cacheKey}`, async () => {
    if (tokenCache[cacheKey] && tokenCache[cacheKey].expiry > Date.now()) return tokenCache[cacheKey];

    // ¿Otro proceso (o este antes de reiniciar) ya consiguió un permiso vigente?
    const guardado = await leerTAGuardado(ctx, entityId, service);
    if (guardado && guardado.cuit === entity.cuit) {
      tokenCache[cacheKey] = guardado;
      console.log(`[WSAA] TA recuperado de la nube para entidad ${entityId} / ${service}`);
      return guardado;
    }

    console.log(`[WSAA] Pidiendo TA nuevo para entidad ${entityId} / ${service}`);
    const cms = createCMS(entity.cert, entity.key, service);
    const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsaa="http://wsaa.view.sua.dvadac.desein.afip.gov">
  <soapenv:Body>
    <wsaa:loginCms>
      <wsaa:in0>${cms}</wsaa:in0>
    </wsaa:loginCms>
  </soapenv:Body>
</soapenv:Envelope>`;

    let response;
    try {
      response = await soapRequest(WSAA_URL, soapBody, '');
    } catch (e) {
      const body = e.afipBody || '';
      if (/alreadyAuthenticated/i.test(body)) {
        const err = new Error('ARCA ya entregó un permiso vigente a otro proceso (alreadyAuthenticated). Volvé a intentar en unos minutos; si persiste, esperá a que venza (máx. 12 h).');
        err.alreadyAuthenticated = true; throw err;
      }
      throw e;
    }
    const match = response.match(/<loginCmsReturn>([\s\S]*?)<\/loginCmsReturn>/);
    const credXml = match ? match[1].replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&amp;/g, '&') : '';
    if (!credXml) throw new Error('WSAA: respuesta sin credenciales');
    const tokenMatch = credXml.match(/<token>([\s\S]*?)<\/token>/);
    const signMatch = credXml.match(/<sign>([\s\S]*?)<\/sign>/);
    const expiryMatch = credXml.match(/<expirationTime>([\s\S]*?)<\/expirationTime>/);
    if (!tokenMatch || !signMatch) throw new Error('WSAA: credenciales incompletas');

    const result = {
      token: tokenMatch[1].trim(),
      sign: signMatch[1].trim(),
      cuit: entity.cuit,
      expiry: expiryMatch ? new Date(expiryMatch[1].trim()).getTime() - 60000 : Date.now() + 36000000,
    };
    tokenCache[cacheKey] = result;
    await guardarTA(ctx, entityId, service, result);
    console.log(`[WSAA] TA OK entidad ${entityId} / ${service}, vence ${new Date(result.expiry).toISOString()}`);
    return result;
  });
}

// ══════════════════════════════════════════════════════════════════
// WSFEv1
// ══════════════════════════════════════════════════════════════════
const authXml = (a) => `<ar:Auth><ar:Token>${a.token}</ar:Token><ar:Sign>${a.sign}</ar:Sign><ar:Cuit>${a.cuit}</ar:Cuit></ar:Auth>`;

// Último número autorizado. LANZA si ARCA devuelve error o no trae número
// (antes devolvía 0 y la próxima emisión salía con número 1).
async function getLastInvoiceNum(entityId, puntoVenta, tipoComprobante, ctx) {
  const a = await getToken(entityId, 'wsfe', ctx);
  const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ar="http://ar.gov.afip.dif.FEV1/">
  <soapenv:Body>
    <ar:FECompUltimoAutorizado>
      ${authXml(a)}
      <ar:PtoVta>${puntoVenta}</ar:PtoVta>
      <ar:CbteTipo>${tipoComprobante}</ar:CbteTipo>
    </ar:FECompUltimoAutorizado>
  </soapenv:Body>
</soapenv:Envelope>`;
  const response = await soapRequest(WSFE_URL, soapBody, 'http://ar.gov.afip.dif.FEV1/FECompUltimoAutorizado');
  const errs = parseErrores(response);
  if (errs.length) throw new Error('ARCA (último autorizado): ' + textoErrores(errs));
  const m = response.match(/<CbteNro>(\d+)<\/CbteNro>/);
  if (!m) throw new Error('ARCA no informó el último número autorizado');
  return parseInt(m[1], 10);
}

// Consulta un comprobante ya emitido (FECompConsultar). null si no existe.
async function consultarComprobante(entityId, puntoVenta, tipoComprobante, nro, ctx) {
  const a = await getToken(entityId, 'wsfe', ctx);
  const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ar="http://ar.gov.afip.dif.FEV1/">
  <soapenv:Body>
    <ar:FECompConsultar>
      ${authXml(a)}
      <ar:FeCompConsReq><ar:CbteTipo>${tipoComprobante}</ar:CbteTipo><ar:CbteNro>${nro}</ar:CbteNro><ar:PtoVta>${puntoVenta}</ar:PtoVta></ar:FeCompConsReq>
    </ar:FECompConsultar>
  </soapenv:Body>
</soapenv:Envelope>`;
  const response = await soapRequest(WSFE_URL, soapBody, 'http://ar.gov.afip.dif.FEV1/FECompConsultar');
  const errs = parseErrores(response);
  if (errs.some(e => e.codigo === 602)) return null;            // 602: no existe
  if (errs.length) throw new Error('ARCA (consultar): ' + textoErrores(errs));
  const g = (tag) => { const m = response.match(new RegExp(`<${tag}>([^<]*)</${tag}>`)); return m ? m[1].trim() : ''; };
  if (!g('CbteDesde')) return null;
  return {
    cbteNro: parseInt(g('CbteDesde'), 10), cbteTipo: parseInt(g('CbteTipo') || tipoComprobante, 10), puntoVenta: parseInt(g('PtoVta') || puntoVenta, 10),
    cbteFch: g('CbteFch'), docTipo: parseInt(g('DocTipo') || '0', 10), docNro: g('DocNro'),
    importeTotal: parseFloat(g('ImpTotal') || '0'), cae: g('CodAutorizacion'), caeVto: g('FchVto'), resultado: g('Resultado'),
    fchProceso: g('FchProceso'),   // "AAAAMMDDHHMMSS" hora de ARCA (Argentina): cuándo se autorizó
    observaciones: parseObs(response),
  };
}

// Minutos transcurridos desde un FchProceso de ARCA ("AAAAMMDDHHMMSS", hora
// Argentina). null si no se puede leer.
function minutosDesdeProceso(fchProceso, ahora = new Date()) {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/.exec(String(fchProceso || '').trim());
  if (!m) return null;
  const partes = _fmtARHora.formatToParts(ahora).reduce((o, p) => (o[p.type] = p.value, o), {});
  const ahoraAR = Date.UTC(+partes.year, +partes.month - 1, +partes.day, +partes.hour % 24, +partes.minute, +partes.second);
  const proc = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  return (ahoraAR - proc) / 60000;
}

// ── Validación de lo que manda la app ──────────────────────────────
class ErrorValidacion extends Error { constructor(msg) { super(msg); this.validacion = true; } }

const TIPO_FC = { A: 1, B: 6, C: 11 };
const TIPO_NC = { A: 3, B: 8, C: 13 };
// Condición frente al IVA del receptor (FEParamGetCondicionIvaReceptor)
const COND_IVA_VALIDAS = new Set([1, 4, 5, 6, 7, 8, 9, 10, 13, 15, 16]);
const COND_IVA_PARA_A = new Set([1, 6, 13, 16]);   // RI y monotributistas (RG 5616)
const r2 = (n) => Math.round(n * 100) / 100;

function validarComprobante(body, { esNC = false } = {}) {
  const b = body || {};
  const entityId = String(b.entityId || '').trim();
  if (!ENTITIES[entityId]) throw new ErrorValidacion('Entidad inválida');

  const puntoVenta = Number(b.puntoVenta);
  if (!Number.isInteger(puntoVenta) || puntoVenta < 1 || puntoVenta > 99998) throw new ErrorValidacion('Punto de venta inválido o sin configurar');

  const letra = String(b.tipoFactura || '').toUpperCase();
  if (!TIPO_FC[letra]) throw new ErrorValidacion('Tipo de comprobante inválido (A, B o C)');
  const tipoComprobante = esNC ? TIPO_NC[letra] : TIPO_FC[letra];

  const docTipo = Number(b.docTipo);
  if (![80, 96, 99].includes(docTipo)) throw new ErrorValidacion('Tipo de documento del receptor inválido (80 CUIT, 96 DNI, 99 consumidor final)');
  const docNroStr = String(b.docNro == null ? '' : b.docNro).replace(/\D/g, '');
  const docNro = docNroStr ? parseInt(docNroStr, 10) : 0;
  if (docTipo === 80 && docNroStr.length !== 11) throw new ErrorValidacion('El CUIT del receptor debe tener 11 dígitos');
  if (docTipo === 96 && (docNroStr.length < 6 || docNroStr.length > 8)) throw new ErrorValidacion('El DNI del receptor debe tener entre 6 y 8 dígitos');
  if (docTipo === 99 && docNro !== 0) throw new ErrorValidacion('Consumidor final sin identificar lleva documento 0');
  if (letra === 'A' && docTipo !== 80) throw new ErrorValidacion('La factura A requiere CUIT del receptor');

  const importeTotal = r2(Number(b.importeTotal));
  if (!(importeTotal > 0)) throw new ErrorValidacion('El importe total debe ser mayor a cero');
  let importeNeto = r2(Number(b.importeNeto) || 0);
  let importeIva = r2(Number(b.importeIva) || 0);
  if (letra === 'C') {
    importeNeto = importeTotal; importeIva = 0;          // sin IVA discriminado
  } else {
    if (importeNeto <= 0) throw new ErrorValidacion('El importe neto debe ser mayor a cero');
    if (importeIva < 0) throw new ErrorValidacion('El IVA no puede ser negativo');
    if (Math.abs(importeNeto + importeIva - importeTotal) > 0.011) throw new ErrorValidacion(`Neto + IVA no suma el total (${importeNeto} + ${importeIva} ≠ ${importeTotal})`);
    if (importeIva > 0 && Math.abs(importeIva - importeNeto * 0.21) > 0.05) throw new ErrorValidacion('El IVA informado no corresponde al 21% del neto');
  }

  const concepto = Number(b.concepto);
  if (![1, 2, 3].includes(concepto)) throw new ErrorValidacion('Concepto inválido (1 productos, 2 servicios, 3 productos y servicios)');
  let fchServDesde = '', fchServHasta = '', fchVtoPago = '';
  if (concepto !== 1) {
    fchServDesde = aYmd(b.fchServDesde); fchServHasta = aYmd(b.fchServHasta); fchVtoPago = aYmd(b.fchVtoPago);
    if (!fchServDesde || !fchServHasta || !fchVtoPago) throw new ErrorValidacion('Faltan las fechas del servicio (desde, hasta, vencimiento de pago) en formato AAAAMMDD');
    if (fchServDesde > fchServHasta) throw new ErrorValidacion('La fecha "desde" del servicio es posterior a la "hasta"');
  }

  const actividad = b.actividad == null || b.actividad === '' ? null : Number(b.actividad);
  if (actividad != null && !Number.isInteger(actividad)) throw new ErrorValidacion('Actividad inválida');

  const condicionIVAReceptor = Number(b.condicionIVAReceptor);
  if (!COND_IVA_VALIDAS.has(condicionIVAReceptor)) throw new ErrorValidacion('Falta la condición frente al IVA del receptor (obligatoria desde 2025)');
  if (letra === 'A' && !COND_IVA_PARA_A.has(condicionIVAReceptor)) throw new ErrorValidacion('Una factura A sólo puede ir a Responsable Inscripto o Monotributista');
  if (letra !== 'A' && condicionIVAReceptor === 1) throw new ErrorValidacion('A un Responsable Inscripto corresponde factura A, no B ni C');

  let cbtesAsoc = null;
  if (esNC) {
    const fo = b.facturaOriginal || {};
    const tipoOrig = TIPO_FC[String(fo.tipo || '').toUpperCase()];
    const ptoVtaOrig = Number(fo.ptoVta); const nroOrig = Number(fo.nro); const fchOrig = aYmd(fo.fecha);
    if (!tipoOrig || !Number.isInteger(ptoVtaOrig) || !Number.isInteger(nroOrig) || nroOrig < 1) throw new ErrorValidacion('Faltan datos de la factura original (tipo, punto de venta, número)');
    if (!fchOrig) throw new ErrorValidacion('Falta la fecha de la factura original');
    if (String(fo.tipo).toUpperCase() !== letra) throw new ErrorValidacion('La nota de crédito debe ser de la misma letra que la factura original');
    cbtesAsoc = { tipo: tipoOrig, ptoVta: ptoVtaOrig, nro: nroOrig, cuit: ENTITIES[entityId].cuit, fch: fchOrig };
  }

  return { entityId, letra, puntoVenta, tipoComprobante, docTipo, docNro, importeTotal, importeNeto, importeIva, concepto, fchServDesde, fchServHasta, fchVtoPago, actividad, condicionIVAReceptor, cbtesAsoc };
}

// ¿El comprobante que ARCA tiene con ese número es el que intentamos emitir?
const esElNuestro = (cons, d, cbteFch) => !!(cons && cons.resultado === 'A' && cons.cae &&
  String(cons.docNro).replace(/\D/g, '') === String(d.docNro) && Math.abs(cons.importeTotal - d.importeTotal) < 0.011 &&
  (!cons.cbteFch || cons.cbteFch === cbteFch));

const respuestaExitosa = (d, extra) => ({
  success: true,
  cae: extra.cae, caeVto: extra.caeVto, cbteNro: extra.cbteNro, cbteTipo: d.tipoComprobante, puntoVenta: d.puntoVenta,
  cbteFch: extra.cbteFch, cbteFchIso: ymdAIso(extra.cbteFch), cuitEmisor: ENTITIES[d.entityId].cuit, entityId: d.entityId,
  observaciones: extra.observaciones || [], recuperada: !!extra.recuperada, resultado: 'A',
  enviado: {
    docTipo: d.docTipo, docNro: d.docNro, importeTotal: d.importeTotal, importeNeto: d.importeNeto, importeIva: d.importeIva,
    concepto: d.concepto, fchServDesde: d.fchServDesde, fchServHasta: d.fchServHasta, fchVtoPago: d.fchVtoPago,
    condicionIVAReceptor: d.condicionIVAReceptor, actividad: d.actividad, letra: d.letra,
  },
});

async function createInvoice(d, ctx) {
  const { entityId, puntoVenta, tipoComprobante } = d;
  return conCandado(`emision:${entityId}:${puntoVenta}:${tipoComprobante}`, async () => {
    const a = await getToken(entityId, 'wsfe', ctx);
    const emitirCon = async (nextNum) => {
      const cbteFch = fechaArgentinaYmd();
      const usesIva = [1, 6, 3, 8].includes(tipoComprobante);
      const impNeto = usesIva ? d.importeNeto : d.importeTotal;
      const impIVA = usesIva ? d.importeIva : 0;
      // Vencimiento de pago nunca anterior a la fecha del comprobante.
      const vtoPago = d.fchVtoPago && d.fchVtoPago < cbteFch ? cbteFch : d.fchVtoPago;
      d.fchVtoPago = vtoPago;   // lo que realmente se envía es lo que se informa

      const ivaXml = usesIva && impIVA > 0
        ? `<ar:Iva><ar:AlicIva><ar:Id>5</ar:Id><ar:BaseImp>${impNeto.toFixed(2)}</ar:BaseImp><ar:Importe>${impIVA.toFixed(2)}</ar:Importe></ar:AlicIva></ar:Iva>` : '';
      const actividadesXml = usesIva && d.actividad ? `<ar:Actividades><ar:Actividad><ar:Id>${d.actividad}</ar:Id></ar:Actividad></ar:Actividades>` : '';
      const asoc = d.cbtesAsoc;
      const cbtesAsocXml = asoc
        ? `<ar:CbtesAsoc><ar:CbteAsoc><ar:Tipo>${asoc.tipo}</ar:Tipo><ar:PtoVta>${asoc.ptoVta}</ar:PtoVta><ar:Nro>${asoc.nro}</ar:Nro><ar:Cuit>${asoc.cuit}</ar:Cuit><ar:CbteFch>${asoc.fch}</ar:CbteFch></ar:CbteAsoc></ar:CbtesAsoc>` : '';
      const fechasXml = d.concepto !== 1
        ? `<ar:FchServDesde>${d.fchServDesde}</ar:FchServDesde><ar:FchServHasta>${d.fchServHasta}</ar:FchServHasta><ar:FchVtoPago>${vtoPago}</ar:FchVtoPago>` : '';

      const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ar="http://ar.gov.afip.dif.FEV1/">
  <soapenv:Body>
    <ar:FECAESolicitar>
      ${authXml(a)}
      <ar:FeCAEReq>
        <ar:FeCabReq><ar:CantReg>1</ar:CantReg><ar:PtoVta>${puntoVenta}</ar:PtoVta><ar:CbteTipo>${tipoComprobante}</ar:CbteTipo></ar:FeCabReq>
        <ar:FeDetReq>
          <ar:FECAEDetRequest>
            <ar:Concepto>${d.concepto}</ar:Concepto>
            <ar:DocTipo>${d.docTipo}</ar:DocTipo>
            <ar:DocNro>${d.docNro}</ar:DocNro>
            <ar:CbteDesde>${nextNum}</ar:CbteDesde>
            <ar:CbteHasta>${nextNum}</ar:CbteHasta>
            <ar:CbteFch>${cbteFch}</ar:CbteFch>
            ${fechasXml}
            <ar:ImpTotal>${d.importeTotal.toFixed(2)}</ar:ImpTotal>
            <ar:ImpTotConc>0.00</ar:ImpTotConc>
            <ar:ImpNeto>${impNeto.toFixed(2)}</ar:ImpNeto>
            <ar:ImpOpEx>0.00</ar:ImpOpEx>
            <ar:ImpTrib>0.00</ar:ImpTrib>
            <ar:ImpIVA>${impIVA.toFixed(2)}</ar:ImpIVA>
            <ar:MonId>PES</ar:MonId>
            <ar:MonCotiz>1</ar:MonCotiz>
            <ar:CondicionIVAReceptorId>${d.condicionIVAReceptor}</ar:CondicionIVAReceptorId>
            ${ivaXml}
            ${actividadesXml}
            ${cbtesAsocXml}
          </ar:FECAEDetRequest>
        </ar:FeDetReq>
      </ar:FeCAEReq>
    </ar:FECAESolicitar>
  </soapenv:Body>
</soapenv:Envelope>`;

      console.log(`[WSFEv1] ${asoc ? 'NC' : 'FC'} ${d.letra} PV=${puntoVenta} Nro=${nextNum} Total=${d.importeTotal.toFixed(2)} Fch=${cbteFch}`);
      let response;
      try {
        response = await soapRequest(WSFE_URL, soapBody, 'http://ar.gov.afip.dif.FEV1/FECAESolicitar', 60000);
      } catch (e) {
        // Se cortó la conexión DESPUÉS de pedir el CAE: ¿salió igual?
        if (e.transporte) {
          try {
            const cons = await consultarComprobante(entityId, puntoVenta, tipoComprobante, nextNum, ctx);
            if (esElNuestro(cons, d, cbteFch)) {
              console.warn(`[WSFEv1] corte con AFIP pero el comprobante ${nextNum} SÍ salió: se recupera el CAE`);
              return { ok: true, res: respuestaExitosa(d, { cae: cons.cae, caeVto: cons.caeVto, cbteNro: nextNum, cbteFch: cons.cbteFch || cbteFch, observaciones: cons.observaciones, recuperada: true }) };
            }
          } catch (e2) { console.warn(`[WSFEv1] no se pudo verificar si salió: ${e2.message}`); }
        }
        throw e;
      }

      const resultado = (response.match(/<Resultado>(\w+)<\/Resultado>/) || [])[1];
      const cae = (response.match(/<CAE>(\d+)<\/CAE>/) || [])[1];
      const caeVto = (response.match(/<CAEFchVto>(\d+)<\/CAEFchVto>/) || [])[1] || '';
      const obs = parseObs(response);
      const errs = parseErrores(response);
      if (resultado === 'A' && cae) {
        return { ok: true, res: respuestaExitosa(d, { cae, caeVto, cbteNro: nextNum, cbteFch, observaciones: obs }) };
      }
      return { ok: false, errores: errs, observaciones: obs };
    };

    let nextNum = (await getLastInvoiceNum(entityId, puntoVenta, tipoComprobante, ctx)) + 1;
    let intento = await emitirCon(nextNum);
    // 10016: el número no es el próximo a autorizar (alguien emitió en el medio) → una vez más
    if (!intento.ok && intento.errores.some(e => e.codigo === 10016)) {
      console.warn('[WSFEv1] 10016: número ya usado, se reintenta con el siguiente');
      nextNum = (await getLastInvoiceNum(entityId, puntoVenta, tipoComprobante, ctx)) + 1;
      intento = await emitirCon(nextNum);
    }
    if (intento.ok) return intento.res;
    const texto = textoErrores(intento.errores) || textoErrores(intento.observaciones) || 'ARCA rechazó el comprobante sin detalle';
    return { success: false, error: texto, errores: intento.errores, observaciones: intento.observaciones };
  });
}

// ══════════════════════════════════════════════════════════════════
// PADRÓN
// ══════════════════════════════════════════════════════════════════
function extractPadronData(response, cleanCuit, source) {
  const g = (tag) => { const m = response.match(new RegExp(`<${tag}>([^<]*)</${tag}>`)); return m ? m[1] : ''; };
  const razonSocial = g('razonSocial'), apellido = g('apellido'), nombre = g('nombre'), tipoPersona = g('tipoPersona');
  if (!razonSocial && !apellido && !nombre) throw new Error(`sin datos en ${source}`);
  const isJuridica = tipoPersona === 'JURIDICA';
  const fullName = isJuridica ? razonSocial : `${apellido} ${nombre}`.trim();
  const domParts = [g('direccion'), g('localidad'), g('descripcionProvincia'), g('codPostal') ? `CP ${g('codPostal')}` : ''].filter(Boolean);
  const hasImp30 = response.includes('<idImpuesto>30</idImpuesto>');
  const hasImp32 = response.includes('<idImpuesto>32</idImpuesto>');
  const hasImp20 = response.includes('<idImpuesto>20</idImpuesto>');
  const condIva = hasImp32 ? 'IVA Exento' : hasImp30 ? 'Responsable Inscripto' : hasImp20 ? 'Monotributo' : 'Consumidor Final';
  // Id de condición IVA del receptor que corresponde (para CondicionIVAReceptorId)
  const condIvaId = hasImp32 ? 4 : hasImp30 ? 1 : hasImp20 ? 6 : 5;
  return {
    success: true, source, cuit: cleanCuit, tipoPersona, nombre: fullName, razonSocial, apellido, nombrePila: nombre,
    domicilioFiscal: domParts.join(', '), condIva, condIvaId,
  };
}

async function consultarPadronA13(entityId, cleanCuit, ctx) {
  const a = await getToken(entityId, 'ws_sr_padron_a13', ctx);
  const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:a13="http://a13.soap.ws.server.puc.sr/">
  <soapenv:Header/>
  <soapenv:Body>
    <a13:getPersona>
      <token>${a.token}</token><sign>${a.sign}</sign><cuitRepresentada>${a.cuit}</cuitRepresentada><idPersona>${cleanCuit}</idPersona>
    </a13:getPersona>
  </soapenv:Body>
</soapenv:Envelope>`;
  const response = await soapRequest(PADRON_URL, soapBody, '');
  return extractPadronData(response, cleanCuit, 'ws_sr_padron_a13');
}

async function consultarConstancia(entityId, cleanCuit, ctx) {
  const a = await getToken(entityId, 'ws_sr_constancia_inscripcion', ctx);
  const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:a5="http://a5.soap.ws.server.puc.sr/">
  <soapenv:Header/>
  <soapenv:Body>
    <a5:getPersona_v2>
      <token>${a.token}</token><sign>${a.sign}</sign><cuitRepresentada>${a.cuit}</cuitRepresentada><idPersona>${cleanCuit}</idPersona>
    </a5:getPersona_v2>
  </soapenv:Body>
</soapenv:Envelope>`;
  const response = await soapRequest(CONSTANCIA_URL, soapBody, '');
  return extractPadronData(response, cleanCuit, 'ws_sr_constancia_inscripcion');
}

// ══════════════════════════════════════════════════════════════════
// RUTAS
// ══════════════════════════════════════════════════════════════════
const sinConfig = (res) => res.status(503).json({ success: false, error: 'Servidor de facturación mal configurado: ' + CONFIG_ERRORES.join('; ') });
const errorHttp = (res, e, etiqueta) => {
  if (e && e.validacion) return res.status(400).json({ success: false, error: e.message });
  console.error(`[${etiqueta}] ${e && e.message}`);
  const status = e && e.alreadyAuthenticated ? 503 : (e && e.transporte ? 504 : 500);
  return res.status(status).json({ success: false, error: (e && e.message) || 'Error interno' });
};

// Salud pública: lo mínimo. El detalle requiere autenticación.
app.get('/api/health', (req, res) => {
  res.json({ status: CONFIG_ERRORES.length ? 'config-incompleta' : 'ok', version: VERSION, env: IS_PRODUCTION ? 'production' : (ARCA_ENV || 'sin-definir'), configuracionCompleta: CONFIG_ERRORES.length === 0 });
});

app.get('/api/health/detalle', auth, (req, res) => {
  res.json({
    status: 'ok', version: VERSION, env: IS_PRODUCTION ? 'production' : (ARCA_ENV || 'sin-definir'), configErrores: CONFIG_ERRORES,
    auth: { firebase: true, proyectos: FIREBASE_PROJECTS, emailsHabilitados: ALLOWED_EMAILS.length || 'todos', apiKeyAceptada: !!API_KEY, corsRestringido: ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS : false, tlsValidado: !TLS_INSECURE },
    entities: { '1': { name: ENTITIES['1'].name, disponible: entidadDisponible('1') }, '2': { name: ENTITIES['2'].name, disponible: entidadDisponible('2') } },
  });
});

app.post('/api/auth', auth, async (req, res) => {
  try {
    if (CONFIG_ERRORES.length) return sinConfig(res);
    const entityId = String(req.body.entityId || '1');
    const token = await getToken(entityId, 'wsfe', req.fsCtx);
    res.json({ success: true, message: 'Auth OK', cuit: token.cuit });
  } catch (e) { errorHttp(res, e, 'AUTH'); }
});

app.post('/api/ultimo-comprobante', auth, async (req, res) => {
  try {
    if (CONFIG_ERRORES.length) return sinConfig(res);
    const { entityId, puntoVenta, tipoComprobante } = req.body;
    if (!ENTITIES[String(entityId)] || !Number.isInteger(Number(puntoVenta)) || !Number.isInteger(Number(tipoComprobante))) {
      return res.status(400).json({ success: false, error: 'Faltan entidad, punto de venta o tipo' });
    }
    const num = await getLastInvoiceNum(String(entityId), Number(puntoVenta), Number(tipoComprobante), req.fsCtx);
    res.json({ success: true, lastNumber: num });
  } catch (e) { errorHttp(res, e, 'ULTIMO'); }
});

app.post('/api/facturar', auth, requierePermisoFacturar, rateLimit('facturar', 60, 60000), async (req, res) => {
  try {
    if (CONFIG_ERRORES.length) return sinConfig(res);
    const d = validarComprobante(req.body, { esNC: false });
    if (!entidadDisponible(d.entityId)) return res.status(503).json({ success: false, error: `La entidad ${d.entityId} no tiene certificado configurado en el servidor` });
    const result = await createInvoice(d, req.fsCtx);
    if (result.success) result.emitidoPor = quien(req);
    console.log(result.success
      ? `[FC] ✅ ${d.letra} ${d.puntoVenta}-${result.cbteNro} CAE ${result.cae}${result.recuperada ? ' (recuperada)' : ''} — ${quien(req)}`
      : `[FC] ❌ ${result.error} — ${quien(req)}`);
    res.json(result);
  } catch (e) { errorHttp(res, e, 'FACTURAR'); }
});

app.post('/api/nota-credito', auth, requierePermisoFacturar, rateLimit('nc', 60, 60000), async (req, res) => {
  try {
    if (CONFIG_ERRORES.length) return sinConfig(res);
    const d = validarComprobante(req.body, { esNC: true });
    if (!entidadDisponible(d.entityId)) return res.status(503).json({ success: false, error: `La entidad ${d.entityId} no tiene certificado configurado en el servidor` });
    const result = await createInvoice(d, req.fsCtx);
    if (result.success) result.emitidoPor = quien(req);
    console.log(result.success
      ? `[NC] ✅ ${d.letra} ${d.puntoVenta}-${result.cbteNro} CAE ${result.cae} (anula ${d.cbtesAsoc.ptoVta}-${d.cbtesAsoc.nro}) — ${quien(req)}`
      : `[NC] ❌ ${result.error} — ${quien(req)}`);
    res.json(result);
  } catch (e) { errorHttp(res, e, 'NOTA-CREDITO'); }
});

const RECUPERAR_MAX_MINUTOS = 20;
// ¿Salió un comprobante que la app no llegó a guardar? Busca el último
// autorizado y lo compara con lo que la app intentó emitir (documento,
// importe y fecha de hoy). Si coincide, devuelve el CAE para guardarlo.
app.post('/api/recuperar', auth, requierePermisoFacturar, rateLimit('recuperar', 60, 60000), async (req, res) => {
  try {
    if (CONFIG_ERRORES.length) return sinConfig(res);
    const d = validarComprobante(req.body, { esNC: !!req.body.facturaOriginal });
    const ultimo = await getLastInvoiceNum(d.entityId, d.puntoVenta, d.tipoComprobante, req.fsCtx);
    if (ultimo < 1) return res.json({ success: false, encontrado: false });
    const cons = await consultarComprobante(d.entityId, d.puntoVenta, d.tipoComprobante, ultimo, req.fsCtx);
    const hoy = fechaArgentinaYmd();
    if (!esElNuestro(cons, d, hoy)) return res.json({ success: false, encontrado: false, ultimoNumero: ultimo });
    // Protección contra falsos positivos: dos facturas iguales el mismo día
    // (mismo documento e importe) son posibles. Sólo se da por nuestro un
    // comprobante autorizado hace pocos minutos.
    const minutos = minutosDesdeProceso(cons.fchProceso);
    if (minutos != null && (minutos > RECUPERAR_MAX_MINUTOS || minutos < -5)) {
      console.warn(`[RECUPERAR] el último comprobante coincide pero fue autorizado hace ${Math.round(minutos)} min: no se adjudica`);
      return res.json({ success: false, encontrado: false, ultimoNumero: ultimo, motivo: 'coincide pero no es reciente' });
    }
    const out = respuestaExitosa(d, { cae: cons.cae, caeVto: cons.caeVto, cbteNro: ultimo, cbteFch: cons.cbteFch || hoy, observaciones: cons.observaciones, recuperada: true });
    out.emitidoPor = quien(req);
    console.log(`[RECUPERAR] ✅ ${d.letra} ${d.puntoVenta}-${ultimo} coincide con el intento — ${quien(req)}`);
    res.json(out);
  } catch (e) { errorHttp(res, e, 'RECUPERAR'); }
});

app.get('/api/padron', auth, rateLimit('padron', 30, 60000), async (req, res) => {
  try {
    if (CONFIG_ERRORES.length) return sinConfig(res);
    const cleanCuit = String(req.query.cuit || '').replace(/\D/g, '');
    const entityId = String(req.query.entity || '1');
    if (cleanCuit.length < 7 || cleanCuit.length > 11) return res.status(400).json({ success: false, error: 'CUIT inválido' });
    if (!entidadDisponible(entityId)) return res.status(503).json({ success: false, error: `La entidad ${entityId} no tiene certificado configurado` });
    const intentos = [['a13', consultarPadronA13], ['ci', consultarConstancia]];
    for (const [nombre, fn] of intentos) {
      try {
        const r = await fn(entityId, cleanCuit, req.fsCtx);
        console.log(`[PADRON] ${cleanCuit} ✅ ${nombre} (${r.condIva})`);   // sin nombre ni domicilio en el log
        return res.json(r);
      } catch (e) { console.log(`[PADRON] ${cleanCuit} ⚠ ${nombre}: ${e.message.substring(0, 120)}`); }
    }
    res.status(404).json({ success: false, error: 'No se pudieron obtener datos del padrón para ese CUIT' });
  } catch (e) { errorHttp(res, e, 'PADRON'); }
});

// ═══════════ START ═══════════
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n🧾 CarBoys ARCA Server ${VERSION}`);
    console.log(`  Port: ${PORT}`);
    console.log(`  Env: ${IS_PRODUCTION ? '🔴 PRODUCCION' : ENV_VALIDO ? '🟡 HOMOLOGACION' : '❌ ARCA_ENV SIN DEFINIR (no se emite)'}`);
    console.log(`  Auth: 🔑 Google/Firebase (proyectos: ${FIREBASE_PROJECTS.join(', ')}) + permiso "facturar" del usuario de la tablet`);
    console.log(`        ${ALLOWED_EMAILS.length ? `emails habilitados: ${ALLOWED_EMAILS.length}` : 'emails: todos los del proyecto'}`);
    console.log(`        x-api-key: ${API_KEY ? 'aceptada (ARCA_API_KEY definida)' : 'deshabilitada'}`);
    console.log(`  TLS AFIP: ${TLS_INSECURE ? '⚠️  sin validar' : 'validado'}`);
    console.log(`  CORS: ${ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS.join(', ') : '⚠️  abierto a cualquier origen (definir ARCA_ALLOWED_ORIGINS)'}`);
    console.log(`  Entity 1: ${ENTITIES['1'].name} Cert: ${entidadDisponible('1') ? '✅' : '❌'}`);
    console.log(`  Entity 2: ${ENTITIES['2'].name} Cert: ${entidadDisponible('2') ? '✅' : '❌'}`);
    if (CONFIG_ERRORES.length) console.error(`  ❌ CONFIG: ${CONFIG_ERRORES.join(' | ')}`);
    console.log(`\n  GET  /api/health · GET /api/health/detalle · GET /api/padron?cuit=&entity=`);
    console.log(`  POST /api/auth · /api/ultimo-comprobante · /api/facturar · /api/nota-credito · /api/recuperar\n`);
  });
}

module.exports = { app, validarComprobante, fechaArgentinaYmd, ymdAIso, aYmd, esElNuestro, parseErrores, parseObs, extractPadronData, ErrorValidacion, minutosDesdeProceso };
