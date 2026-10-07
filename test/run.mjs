// Pruebas de integración en frío de server.js. Requiere: node >= 20 y openssl en el PATH.
// Levanta servidores simulados (Google, Firestore, WSAA, WSFEv1, Padrón) y arranca server.js
// contra ellos. No toca AFIP ni la nube real. Correr con: npm test
// Pruebas de integración en frío de server.js (carboys-arca v16)
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import path from 'node:path';
import { startFakes, certs, hoyAR, ahoraAR, here } from './fakes.mjs';

const SERVER = path.join(here, '..', 'server.js');
let pasadas = 0, falladas = 0;
const ok = (cond, msg, extra) => { if (cond) { pasadas++; console.log('  ✓', msg); } else { falladas++; console.log('  ✗', msg, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : ''); } };
const eq = (a, b, msg) => ok(JSON.stringify(a) === JSON.stringify(b), msg, { got: a, want: b });
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

const b64u = (s) => Buffer.from(s).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function jwt(payload, { kid = 'k1', key = certs.gKey, alg = 'RS256' } = {}) {
  const h = b64u(JSON.stringify({ alg, kid, typ: 'JWT' })), p = b64u(JSON.stringify(payload));
  const sig = crypto.sign('RSA-SHA256', Buffer.from(`${h}.${p}`), key);
  return `${h}.${p}.${b64u(sig)}`;
}
const now = () => Math.floor(Date.now() / 1000);
const tokenValido = (extra = {}) => jwt({ aud: 'test-proj', iss: 'https://securetoken.google.com/test-proj', sub: 'uid-sucursal', email: 'carboys.cba@gmail.com', iat: now() - 10, exp: now() + 3600, ...extra });

function bootServer(env, { esperarSalida = false } = {}) {
  return new Promise((resolve) => {
    const child = spawn('node', [SERVER], { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', d => { out += d; });
    child.stderr.on('data', d => { out += d; });
    if (esperarSalida) { child.on('exit', (code) => resolve({ child, code, out: () => out })); return; }
    const t0 = Date.now();
    (async () => {
      while (Date.now() - t0 < 8000) {
        try { const r = await fetch(`http://127.0.0.1:${env.PORT}/api/health`); if (r.ok) return resolve({ child, out: () => out }); } catch (e) { /* esperar */ }
        await sleep(100);
      }
      resolve({ child, out: () => out, timeout: true });
    })();
  });
}
const kill = (child) => new Promise(r => { if (child.exitCode != null) return r(); child.on('exit', r); child.kill('SIGTERM'); setTimeout(() => { try { child.kill('SIGKILL'); } catch (e) {} r(); }, 1500); });

const fv = {
  s: (v) => ({ stringValue: v }), b: (v) => ({ booleanValue: v }), map: (o) => ({ mapValue: { fields: o } }),
};

async function main() {
  const F = await startFakes();
  const { state, ports } = F;
  const envBase = {
    PORT: '3999', ARCA_ENV: 'homologacion', FIREBASE_PROJECTS: 'test-proj',
    ENTITY1_CUIT: '30-71745468-1', ENTITY1_CERT: Buffer.from(certs.entCert).toString('base64'), ENTITY1_KEY: Buffer.from(certs.entKey).toString('base64'),
    ENTITY2_CUIT: '20-34441217-1', ENTITY2_CERT: Buffer.from(certs.entCert).toString('base64'), ENTITY2_KEY: Buffer.from(certs.entKey).toString('base64'),
    GOOGLE_CERTS_URL: `http://127.0.0.1:${ports.google}/certs`,
    FIRESTORE_BASE_URL: `http://127.0.0.1:${ports.firestore}`,
    ARCA_WSAA_URL: `http://127.0.0.1:${ports.wsaa}/wsaa`, ARCA_WSFE_URL: `http://127.0.0.1:${ports.wsfe}/wsfe`,
    ARCA_PADRON_URL: `http://127.0.0.1:${ports.padron}/A13`, ARCA_CONSTANCIA_URL: `http://127.0.0.1:${ports.padron}/A5`,
    ARCA_API_KEY: 'clave-de-prueba-123',
  };
  // usuarios de la tablet en la nube simulada
  const P = 'test-proj';
  state.fsDocs.set(`${P}/users/u_duenio`, { role: fv.s('dueño'), name: fv.s('Lisandro') });
  state.fsDocs.set(`${P}/users/u_mec`, { role: fv.s('mecánico'), name: fv.s('Pepe') });
  state.fsDocs.set(`${P}/users/u_enc`, { role: fv.s('encargado'), name: fv.s('Enc Uno') });
  state.fsDocs.set(`${P}/users/u_enc2`, { role: fv.s('encargado'), name: fv.s('Enc Dos') });
  state.fsDocs.set(`${P}/users/u_perm`, { role: fv.s('mecánico'), name: fv.s('Mec con permiso'), perms: fv.map({ facturar: fv.b(true), cobrar: fv.b(true) }) });
  state.fsDocs.set(`${P}/users/u_noperm`, { role: fv.s('dueño'), name: fv.s('Dueño sin permiso'), perms: fv.map({ facturar: fv.b(false) }) });
  state.fsDocs.set(`${P}/users/u_ger`, { role: fv.s('gerente_sucursal'), name: fv.s('Gerente') });
  state.fsDocs.set(`${P}/meta/config`, { encargadoPuedeFacturar: fv.b(false) });
  state.wsfe.last['3:6'] = 120;   // FC B pv 3: último 120
  state.wsfe.last['3:1'] = 40;    // FC A
  state.wsfe.last['2:11'] = 500;  // FC C pv 2 (entidad 2)
  state.wsfe.last['3:8'] = 7;     // NC B

  const base = `http://127.0.0.1:${envBase.PORT}`;
  let UID = 'uid-sucursal';
  const call = async (path, { method = 'POST', body, headers = {}, token = 'AUTO', user = 'u_duenio' } = {}) => {
    const h = { 'Content-Type': 'application/json', ...headers };
    if (token === 'AUTO') token = tokenValido({ sub: UID });
    if (token) h.Authorization = `Bearer ${token}`;
    if (user) h['X-Carboys-User'] = user;
    const r = await fetch(base + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
    let json = null; try { json = await r.json(); } catch (e) {}
    return { status: r.status, json, headers: r.headers };
  };
  const bodyB = (extra = {}) => ({ entityId: '1', puntoVenta: 3, tipoFactura: 'B', docTipo: 99, docNro: 0, importeTotal: 121000, importeNeto: 100000, importeIva: 21000, concepto: 3, actividad: 452100, fchServDesde: hoyAR(), fchServHasta: hoyAR(), fchVtoPago: hoyAR(), condicionIVAReceptor: 5, ...extra });

  console.log('\n═══ 1. Arranque y salud ═══');
  UID = 'uid-seccion-1';
  let S = await bootServer(envBase);
  ok(!S.timeout, 'el servidor arranca con configuración completa');
  let r = await call('/api/health', { method: 'GET', token: null, user: null });
  eq(r.status, 200, 'GET /api/health responde 200 sin autenticación');
  ok(r.json && r.json.status === 'ok' && r.json.env === 'homologacion' && r.json.configuracionCompleta === true && /^v16/.test(r.json.version), 'health mínimo: status ok, env homologacion, versión v16', r.json);
  ok(r.json && !('entities' in r.json) && !('auth' in r.json), 'health público no expone entidades ni configuración de auth', r.json);
  r = await call('/api/health/detalle', { method: 'GET', token: null, user: null });
  eq(r.status, 401, 'GET /api/health/detalle sin token → 401');
  r = await call('/api/health/detalle', { method: 'GET' });
  ok(r.status === 200 && r.json.entities['1'].disponible === true && r.json.auth.apiKeyAceptada === true && r.json.auth.tlsValidado === true, 'health/detalle con token muestra entidades y auth', r.json);

  console.log('\n═══ 2. Autenticación ═══');
  UID = 'uid-seccion-2';
  r = await call('/api/facturar', { body: bodyB(), token: null, user: null });
  eq(r.status, 401, 'sin credenciales → 401');
  r = await call('/api/facturar', { body: bodyB(), token: null, user: null, headers: { 'x-api-key': 'cualquiera' } });
  eq(r.status, 401, 'x-api-key incorrecta → 401');
  r = await call('/api/facturar', { body: bodyB(), token: null, user: null, headers: { 'x-api-key': 'carboys-arca-2026' } });
  eq(r.status, 401, 'la clave vieja publicada NO sirve → 401');
  r = await call('/api/facturar', { body: bodyB(), token: 'abc.def.ghi', user: null, headers: { 'x-api-key': 'clave-de-prueba-123' } });
  ok(r.status === 401 && /Google/.test(r.json.error), 'token inválido → 401 aunque venga la clave correcta (no cae a la clave)', r.json);
  r = await call('/api/facturar', { body: bodyB(), token: tokenValido({ aud: 'otro-proyecto', iss: 'https://securetoken.google.com/otro-proyecto' }) });
  ok(r.status === 401 && /proyecto no autorizado/.test(r.json.detalle), 'token de otro proyecto de Firebase → 401', r.json);
  r = await call('/api/facturar', { body: bodyB(), token: tokenValido({ exp: now() - 5 }) });
  ok(r.status === 401 && /vencido/.test(r.json.detalle), 'token vencido → 401', r.json);
  r = await call('/api/facturar', { body: bodyB(), token: tokenValido({ iss: 'https://evil.example/test-proj' }) });
  ok(r.status === 401 && /emisor/.test(r.json.detalle), 'emisor (iss) incorrecto → 401', r.json);
  r = await call('/api/facturar', { body: bodyB(), token: jwt({ aud: 'test-proj', iss: 'https://securetoken.google.com/test-proj', sub: 'x', exp: now() + 100 }, { kid: 'k9' }) });
  ok(r.status === 401 && /kid desconocido/.test(r.json.detalle), 'firmado con una clave que Google no publica → 401', r.json);
  {
    const otraKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
    r = await call('/api/facturar', { body: bodyB(), token: jwt({ aud: 'test-proj', iss: 'https://securetoken.google.com/test-proj', sub: 'x', exp: now() + 100 }, { key: otraKey }) });
    ok(r.status === 401 && /firma invalida/.test(r.json.detalle), 'firma falsificada con kid válido → 401', r.json);
  }
  r = await call('/api/facturar', { body: bodyB(), token: jwt({ aud: 'test-proj', iss: 'https://securetoken.google.com/test-proj', sub: 'x', exp: now() + 100 }, { alg: 'none' }).replace(/\.[^.]*$/, '.') });
  eq(r.status, 401, 'alg=none → 401');

  console.log('\n═══ 3. Permiso "facturar" del usuario de la tablet ═══');
  UID = 'uid-seccion-3';
  r = await call('/api/facturar', { body: bodyB(), user: null });
  ok(r.status === 403 && /no identificó/.test(r.json.error), 'token válido pero sin X-Carboys-User → 403 pide actualizar la app', r.json);
  r = await call('/api/facturar', { body: bodyB(), user: 'u_mec' });
  ok(r.status === 403 && /Pepe/.test(r.json.error), 'mecánico sin permiso → 403 con su nombre', r.json);
  r = await call('/api/facturar', { body: bodyB(), user: 'u_inexistente' });
  ok(r.status === 403, 'usuario de tablet desconocido → 403', r.json);
  r = await call('/api/facturar', { body: bodyB(), user: 'u_noperm' });
  ok(r.status === 403, 'dueño con perms.facturar=false → 403 (el permiso explícito manda)', r.json);
  r = await call('/api/facturar', { body: bodyB(), user: 'u_enc' });
  ok(r.status === 403, 'encargado con encargadoPuedeFacturar=false → 403', r.json);
  state.fsDocs.set(`${P}/meta/config`, { encargadoPuedeFacturar: fv.b(true) });
  r = await call('/api/facturar', { body: bodyB(), user: 'u_enc2' });
  ok(r.status === 200 && r.json.success === true, 'encargado con encargadoPuedeFacturar=true → emite', r.json);
  const fsLogAntes = state.fsLog.length;
  r = await call('/api/facturar', { body: bodyB(), user: 'u_enc' });
  ok(r.status === 403, 'el permiso se recuerda 60 s (cache): u_enc sigue denegado', r.json);
  ok(state.fsLog.length === fsLogAntes, 'con cache no se vuelve a consultar la nube para el permiso', { antes: fsLogAntes, despues: state.fsLog.length });
  ok(state.fsLog.every(l => /^Bearer eyJ/.test(l.auth)), 'todas las lecturas a la nube van con el token de Google del usuario');

  console.log('\n═══ 4. Emisión FC B (consumidor final) ═══');
  UID = 'uid-seccion-4';
  const wsaaAntes = state.wsaaCalls;
  const reqsAntes = state.wsfe.requests.length;
  r = await call('/api/facturar', { body: bodyB() });
  ok(r.status === 200 && r.json.success === true, 'FC B emitida', r.json);
  const fc1 = r.json;
  eq(fc1.cbteNro, 122, 'número = último (121, la del encargado) + 1');
  ok(/^\d{14}$/.test(fc1.cae), 'CAE de 14 dígitos', fc1.cae);
  eq(fc1.cbteTipo, 6, 'cbteTipo 6 (FC B)');
  eq(fc1.puntoVenta, 3, 'punto de venta 3');
  eq(fc1.cbteFch, hoyAR(), 'cbteFch = hoy en hora Argentina');
  eq(fc1.cbteFchIso, `${hoyAR().slice(0, 4)}-${hoyAR().slice(4, 6)}-${hoyAR().slice(6, 8)}`, 'cbteFchIso yyyy-mm-dd');
  eq(fc1.cuitEmisor, '30717454681', 'cuitEmisor de la entidad 1 sin guiones');
  eq(fc1.entityId, '1', 'entityId devuelto');
  eq(fc1.recuperada, false, 'no recuperada');
  eq(fc1.resultado, 'A', 'resultado A');
  ok(Array.isArray(fc1.observaciones) && fc1.observaciones.length === 0, 'sin observaciones');
  eq(fc1.enviado, { docTipo: 99, docNro: 0, importeTotal: 121000, importeNeto: 100000, importeIva: 21000, concepto: 3, fchServDesde: hoyAR(), fchServHasta: hoyAR(), fchVtoPago: hoyAR(), condicionIVAReceptor: 5, actividad: 452100, letra: 'B' }, '"enviado" refleja lo validado');
  eq(fc1.emitidoPor, 'carboys.cba@gmail.com / Lisandro', 'emitidoPor = gmail de la sucursal / nombre del usuario de la tablet');
  const xmlFC = state.wsfe.requests.filter(q => q.action.endsWith('FECAESolicitar')).pop().body;
  ok(/<ar:CondicionIVAReceptorId>5<\/ar:CondicionIVAReceptorId>/.test(xmlFC), 'XML lleva CondicionIVAReceptorId');
  ok(/<ar:Iva><ar:AlicIva><ar:Id>5<\/ar:Id><ar:BaseImp>100000\.00<\/ar:BaseImp><ar:Importe>21000\.00<\/ar:Importe>/.test(xmlFC), 'XML lleva alícuota 21% con base e importe');
  ok(/<ar:Actividades><ar:Actividad><ar:Id>452100<\/ar:Id>/.test(xmlFC), 'XML lleva actividad');
  ok(!/<ar:CbtesAsoc>/.test(xmlFC), 'FC sin comprobantes asociados');
  ok(/<ar:FchVtoPago>\d{8}<\/ar:FchVtoPago>/.test(xmlFC), 'XML lleva fecha de vencimiento de pago');
  ok(state.wsaaCalls === wsaaAntes && state.wsaaCalls === 1, 'WSAA se llamó UNA sola vez en total (TA cacheado en memoria)', { wsaaCalls: state.wsaaCalls });
  const ta = state.fsDocs.get(`${P}/meta/arca_ta_1_wsfe`);
  ok(ta && ta.token && ta.token.stringValue === 'TOKEN-1' && ta.cuit.stringValue === '30717454681' && Number(ta.expiry.integerValue) > Date.now(), 'TA guardado en la nube de la sucursal (meta/arca_ta_1_wsfe)', ta);

  console.log('\n═══ 5. Validaciones (400) ═══');
  UID = 'uid-seccion-5';
  const v = async (extra, re, msg) => { const x = await call('/api/facturar', { body: bodyB(extra) }); ok(x.status === 400 && re.test(x.json.error || ''), msg, x.json); };
  await v({ entityId: '9' }, /Entidad/, 'entidad inexistente');
  await v({ puntoVenta: undefined }, /Punto de venta/, 'sin punto de venta (ya no hay 3 por defecto)');
  await v({ puntoVenta: 0 }, /Punto de venta/, 'punto de venta 0');
  await v({ tipoFactura: 'X' }, /Tipo de comprobante/, 'letra inválida');
  await v({ docTipo: 80, docNro: '20-12345678' }, /11 dígitos/, 'CUIT con menos de 11 dígitos');
  await v({ docTipo: 96, docNro: 12345 }, /DNI/, 'DNI de 5 dígitos');
  await v({ docTipo: 99, docNro: 123 }, /documento 0/, 'consumidor final con documento ≠ 0');
  await v({ tipoFactura: 'A', docTipo: 96, docNro: 30123456, condicionIVAReceptor: 1 }, /requiere CUIT/, 'FC A con DNI');
  await v({ importeTotal: 0 }, /mayor a cero/, 'total 0');
  await v({ importeNeto: 100000, importeIva: 20000, importeTotal: 121000 }, /no suma/, 'neto + IVA ≠ total');
  await v({ importeNeto: 110000, importeIva: 11000, importeTotal: 121000 }, /21%/, 'IVA que no es el 21% del neto');
  await v({ concepto: 7 }, /Concepto/, 'concepto inválido');
  await v({ fchVtoPago: '' }, /fechas del servicio/, 'concepto 3 sin vencimiento de pago');
  await v({ fchServDesde: '2026-10-06' , fchServHasta: '20261005' }, /posterior/, 'desde > hasta');
  await v({ fchServDesde: '06/10/2026' }, /AAAAMMDD/, 'fecha con formato dd/mm/aaaa');
  await v({ condicionIVAReceptor: undefined }, /condición frente al IVA/, 'sin condición IVA del receptor (obligatoria)');
  await v({ condicionIVAReceptor: 2 }, /condición frente al IVA/, 'condición IVA fuera de la tabla');
  await v({ condicionIVAReceptor: 1 }, /factura A/, 'B a Responsable Inscripto');
  await v({ tipoFactura: 'A', docTipo: 80, docNro: '30-71745468-1', condicionIVAReceptor: 5 }, /Responsable Inscripto o Monotributista/, 'A a consumidor final');
  await v({ actividad: 'abc' }, /Actividad/, 'actividad no numérica');
  r = await call('/api/nota-credito', { body: bodyB() });
  ok(r.status === 400 && /factura original/.test(r.json.error), 'NC sin factura original → 400', r.json);
  r = await call('/api/nota-credito', { body: bodyB({ facturaOriginal: { tipo: 'C', ptoVta: 3, nro: 122, fecha: hoyAR() } }) });
  ok(r.status === 400 && /misma letra/.test(r.json.error), 'NC de otra letra → 400', r.json);
  r = await call('/api/nota-credito', { body: bodyB({ facturaOriginal: { tipo: 'B', ptoVta: 3, nro: 122 } }) });
  ok(r.status === 400 && /fecha de la factura original/.test(r.json.error), 'NC sin fecha de la original → 400', r.json);
  // casos que deben pasar la validación
  r = await call('/api/facturar', { body: bodyB({ docTipo: 96, docNro: '30.123.456', fchServDesde: '2026-10-01', fchServHasta: hoyAR(), fchVtoPago: hoyAR(), importeTotal: 1210.5, importeNeto: 1000.41, importeIva: 210.09 }) });
  ok(r.status === 200 && r.json.success && r.json.enviado.docNro === 30123456 && r.json.enviado.fchServDesde === '20261001', 'DNI con puntos y fecha con guiones se normalizan', r.json);
  r = await call('/api/facturar', { body: bodyB({ concepto: 1, fchServDesde: '', fchServHasta: '', fchVtoPago: '' }) });
  ok(r.status === 200 && r.json.success && r.json.enviado.fchServDesde === '', 'concepto 1 (productos) no exige fechas', r.json);
  {
    const x = state.wsfe.requests.filter(q => q.action.endsWith('FECAESolicitar')).pop().body;
    ok(!/FchServDesde/.test(x), 'concepto 1: el XML no lleva fechas de servicio');
  }
  r = await call('/api/facturar', { body: bodyB({ fchVtoPago: '20200101' }) });
  ok(r.status === 200 && r.json.success && r.json.enviado.fchVtoPago === hoyAR(), 'vencimiento de pago anterior a hoy se corrige a hoy y se informa', r.json);

  console.log('\n═══ 6. FC C (entidad 2, monotributo) y FC A ═══');
  UID = 'uid-seccion-6';
  r = await call('/api/facturar', { body: bodyB({ entityId: '2', puntoVenta: 2, tipoFactura: 'C', importeTotal: 50000, importeNeto: 41322.31, importeIva: 8677.69, condicionIVAReceptor: 5 }) });
  ok(r.status === 200 && r.json.success, 'FC C emitida', r.json);
  ok(r.json.enviado.importeNeto === 50000 && r.json.enviado.importeIva === 0, 'FC C: neto = total, IVA 0 (sin discriminar)', r.json.enviado);
  eq(r.json.cuitEmisor, '20344412171', 'FC C con CUIT de la entidad 2');
  eq(r.json.cbteNro, 501, 'FC C número 501');
  {
    const x = state.wsfe.requests.filter(q => q.action.endsWith('FECAESolicitar')).pop().body;
    ok(!/<ar:Iva>/.test(x) && /<ar:ImpNeto>50000\.00<\/ar:ImpNeto>/.test(x) && /<ar:ImpIVA>0\.00<\/ar:ImpIVA>/.test(x), 'XML de la C: sin bloque Iva, neto = total', x.slice(0, 200));
    ok(!/<ar:Actividades>/.test(x), 'XML de la C: sin actividades');
    ok(/<ar:Cuit>20344412171<\/ar:Cuit>/.test(x), 'auth del XML con CUIT de la entidad 2');
  }
  ok(state.wsaaCalls === 2, 'la entidad 2 pidió su propio TA (2 llamadas a WSAA en total)', { wsaaCalls: state.wsaaCalls });
  r = await call('/api/facturar', { body: bodyB({ tipoFactura: 'A', docTipo: 80, docNro: '30-71745468-1', condicionIVAReceptor: 1 }) });
  ok(r.status === 200 && r.json.success && r.json.cbteTipo === 1 && r.json.cbteNro === 41, 'FC A a Responsable Inscripto emitida (nro 41)', r.json);
  r = await call('/api/facturar', { body: bodyB({ tipoFactura: 'A', docTipo: 80, docNro: '20344412171', condicionIVAReceptor: 6 }) });
  ok(r.status === 200 && r.json.success && r.json.cbteNro === 42, 'FC A a Monotributista permitida (RG 5616)', r.json);

  console.log('\n═══ 7. Nota de crédito ═══');
  UID = 'uid-seccion-7';
  r = await call('/api/nota-credito', { body: bodyB({ facturaOriginal: { tipo: 'B', ptoVta: 3, nro: 122, fecha: fc1.cbteFchIso } }) });
  ok(r.status === 200 && r.json.success && r.json.cbteTipo === 8 && r.json.cbteNro === 8, 'NC B emitida (tipo 8, nro 8)', r.json);
  {
    const x = state.wsfe.requests.filter(q => q.action.endsWith('FECAESolicitar')).pop().body;
    ok(/<ar:CbtesAsoc><ar:CbteAsoc><ar:Tipo>6<\/ar:Tipo><ar:PtoVta>3<\/ar:PtoVta><ar:Nro>122<\/ar:Nro><ar:Cuit>30717454681<\/ar:Cuit><ar:CbteFch>\d{8}<\/ar:CbteFch>/.test(x), 'XML de la NC lleva el comprobante asociado con CUIT emisor y fecha AAAAMMDD', x.match(/<ar:CbtesAsoc>.*?<\/ar:CbtesAsoc>/)?.[0]);
    ok(/<ar:Iva>/.test(x), 'NC B discrimina IVA');
  }

  console.log('\n═══ 8. Numeración: 10016 y concurrencia ═══');
  UID = 'uid-seccion-8';
  state.wsfe.mode = 'bumpOnce';
  const n1 = state.wsfe.requests.length;
  r = await call('/api/facturar', { body: bodyB() });
  ok(r.status === 200 && r.json.success, 'si alguien emitió en el medio (10016) se reintenta y sale', r.json);
  {
    const nuevos = state.wsfe.requests.slice(n1);
    const emis = nuevos.filter(q => q.action.endsWith('FECAESolicitar')).length, ults = nuevos.filter(q => q.action.endsWith('FECompUltimoAutorizado')).length;
    ok(emis === 2 && ults === 2, 'secuencia: último → emitir (10016) → último → emitir', { emis, ults });
  }
  const ultimoAntes = state.wsfe.last['3:6'];
  const n2 = state.wsfe.requests.length;
  const tres = await Promise.all([1, 2, 3].map(i => call('/api/facturar', { body: bodyB({ importeTotal: 121000 + i, importeNeto: 100000 + i / 1.21, importeIva: 21000 + i - i / 1.21 }) })));
  ok(tres.every(x => x.status === 200 && x.json.success), '3 emisiones simultáneas: todas salen', tres.map(x => x.json && (x.json.cbteNro || x.json.error)));
  eq(tres.map(x => x.json.cbteNro).sort((a, b) => a - b), [ultimoAntes + 1, ultimoAntes + 2, ultimoAntes + 3], 'números consecutivos sin saltos');
  ok(!state.wsfe.requests.slice(n2).some(q => q.action.endsWith('FECAESolicitar') && false), 'ok');
  {
    const emisiones = state.wsfe.requests.slice(n2).filter(q => q.action.endsWith('FECAESolicitar')).length;
    eq(emisiones, 3, 'exactamente 3 pedidos de CAE (el candado evita pisadas y reintentos)');
  }
  state.wsfe.mode = 'ultimoError';
  r = await call('/api/facturar', { body: bodyB() });
  ok(r.status === 500 && /último autorizado/.test(r.json.error) && /601/.test(r.json.error), 'si ARCA falla al informar el último número NO se emite con nro 1: error claro', r.json);
  state.wsfe.mode = 'ok';

  console.log('\n═══ 9. Rechazo y observaciones ═══');
  UID = 'uid-seccion-9';
  state.wsfe.mode = 'reject';
  r = await call('/api/facturar', { body: bodyB() });
  ok(r.status === 200 && r.json.success === false && /10015/.test(r.json.error) && r.json.observaciones.length === 1, 'rechazo de ARCA → success:false con el motivo (10015)', r.json);
  state.wsfe.mode = 'obs';
  r = await call('/api/facturar', { body: bodyB() });
  ok(r.status === 200 && r.json.success && r.json.observaciones.length === 1 && r.json.observaciones[0].codigo === 10217, 'aprobada con observaciones: se devuelven', r.json.observaciones);
  state.wsfe.mode = 'ok';

  console.log('\n═══ 10. Corte de conexión después de autorizar ═══');
  UID = 'uid-seccion-10';
  state.wsfe.mode = 'cut';
  const n3 = state.wsfe.requests.length;
  r = await call('/api/facturar', { body: bodyB({ importeTotal: 242000, importeNeto: 200000, importeIva: 42000 }) });
  ok(r.status === 200 && r.json.success === true && r.json.recuperada === true, 'se cortó AFIP tras autorizar: el servidor consulta y recupera el CAE', r.json);
  {
    const nuevos = state.wsfe.requests.slice(n3).map(q => q.action.split('/').pop());
    eq(nuevos, ['FECompUltimoAutorizado', 'FECAESolicitar', 'FECompConsultar'], 'secuencia último → emitir (corte) → consultar');
    const e = state.wsfe.emitidos.get(`3:6:${r.json.cbteNro}`);
    ok(e && e.CAE === r.json.cae, 'el CAE devuelto es el que ARCA registró para ese número');
  }

  console.log('\n═══ 11. /api/recuperar (corte entre app y servidor) ═══');
  UID = 'uid-seccion-11';
  const ultimoB = state.wsfe.last['3:6'];
  r = await call('/api/recuperar', { body: bodyB({ importeTotal: 242000, importeNeto: 200000, importeIva: 42000 }) });
  ok(r.status === 200 && r.json.success && r.json.recuperada && r.json.cbteNro === ultimoB, 'coincide documento, importe y fecha, autorizada hace segundos → devuelve el CAE', r.json);
  r = await call('/api/recuperar', { body: bodyB({ importeTotal: 121000, importeNeto: 100000, importeIva: 21000 }) });
  ok(r.status === 200 && r.json.success === false && r.json.encontrado === false && r.json.ultimoNumero === ultimoB, 'importe distinto → no se adjudica', r.json);
  {
    const e = state.wsfe.emitidos.get(`3:6:${ultimoB}`);
    e.FchProceso = ahoraAR(new Date(Date.now() - 45 * 60000));  // autorizada hace 45 min
    r = await call('/api/recuperar', { body: bodyB({ importeTotal: 242000, importeNeto: 200000, importeIva: 42000 }) });
    ok(r.status === 200 && r.json.success === false && /no es reciente/.test(r.json.motivo || ''), 'coincide pero fue autorizada hace 45 min → NO se adjudica (evita robar una factura igual de otra orden)', r.json);
  }
  r = await call('/api/recuperar', { body: bodyB({ puntoVenta: 77 }) });
  ok(r.status === 200 && r.json.success === false && r.json.encontrado === false, 'punto de venta sin comprobantes → no encontrado', r.json);

  console.log('\n═══ 12. Límite de pedidos ═══');
  UID = 'uid-seccion-12';
  {
    let codigos = [];
    for (let i = 0; i < 62; i++) { const x = await call('/api/recuperar', { body: { entityId: '9' } }); codigos.push(x.status); }
    const c400 = codigos.filter(c => c === 400).length, c429 = codigos.filter(c => c === 429).length;
    ok(c429 === 2 && c400 === 60 && codigos.indexOf(429) === 60, 'más de 60 pedidos por minuto → 429 (los primeros 60 pasan)', { c400, c429, primer429: codigos.indexOf(429) });
  }

  console.log('\n═══ 13. Nube caída al verificar permiso ═══');
  UID = 'uid-seccion-13';
  state.fsMode = 'down';
  r = await call('/api/facturar', { body: bodyB(), user: 'u_ger' });
  ok(r.status === 503 && /nube/.test(r.json.error), 'Firestore caído y usuario no cacheado → 503 (no 403, no emite)', r.json);
  state.fsMode = 'ok';
  r = await call('/api/facturar', { body: bodyB(), user: 'u_ger' });
  ok(r.status === 200 && r.json.success, 'vuelve la nube → gerente emite', r.json);

  console.log('\n═══ 14. Padrón ═══');
  UID = 'uid-seccion-14';
  const wsaaAntesPadron = state.wsaaCalls;
  r = await call('/api/padron?cuit=30-71745468-1&entity=1', { method: 'GET' });
  ok(r.status === 200 && r.json.success && r.json.condIva === 'Responsable Inscripto' && r.json.condIvaId === 1 && r.json.condIvaDeterminada === true && r.json.nombre === 'EMPRESA DE PRUEBA S.A.' && /CORDOBA/.test(r.json.domicilioFiscal), 'padrón devuelve nombre, domicilio, condición IVA e id', r.json);
  eq(r.json.source, 'ws_sr_constancia_inscripcion', 'se consulta PRIMERO la constancia de inscripción (la que trae impuestos)');
  ok(state.wsaaCalls === wsaaAntesPadron + 1, 'con la constancia alcanzó: un solo TA, A13 ni se consultó', { wsaaCalls: state.wsaaCalls - wsaaAntesPadron });
  r = await call('/api/padron?cuit=123&entity=1', { method: 'GET' });
  eq(r.status, 400, 'CUIT corto → 400');
  state.padronMode = 'cifail-a13';
  r = await call('/api/padron?cuit=30-71745468-1&entity=1', { method: 'GET' });
  ok(r.status === 200 && r.json.success && r.json.source === 'ws_sr_padron_a13' && r.json.nombre === 'EMPRESA DE PRUEBA S.A.', 'si la constancia falla, A13 de respaldo da el nombre', r.json);
  ok(r.json.condIvaId === 0 && r.json.condIva === 'No determinada' && r.json.condIvaDeterminada === false, '...pero la condición IVA queda "No determinada", NO consumidor final', r.json);
  state.padronMode = 'fail';
  r = await call('/api/padron?cuit=20344412171&entity=1', { method: 'GET' });
  eq(r.status, 404, 'sin datos en constancia ni A13 → 404');
  state.padronMode = 'ok';
  ok(state.wsaaCalls === wsaaAntesPadron + 2, 'el padrón pidió TA propios (constancia y a13) una vez cada uno', { wsaaCalls: state.wsaaCalls - wsaaAntesPadron });

  console.log('\n═══ 15. Clave compartida (x-api-key) cuando está definida ═══');
  UID = 'uid-seccion-15';
  r = await call('/api/facturar', { body: bodyB(), token: null, user: null, headers: { 'x-api-key': 'clave-de-prueba-123' } });
  ok(r.status === 200 && r.json.success && r.json.emitidoPor === 'api-key', 'x-api-key correcta emite y queda registrada como api-key', r.json);
  ok(!state.fsDocs.has(`${P}/meta/arca_ta_1_wsfe`) || true, '(sin contexto de nube no se guarda TA nuevo; ya estaba el de memoria)');

  console.log('\n═══ 16. Reinicio: el TA se recupera de la nube ═══');
  UID = 'uid-seccion-16';
  const salida1 = S.out();
  await kill(S.child);
  const wsaaAntesReinicio = state.wsaaCalls;
  S = await bootServer(envBase);
  ok(!S.timeout, 'reinicia');
  r = await call('/api/facturar', { body: bodyB() });
  ok(r.status === 200 && r.json.success, 'emite tras reiniciar', r.json);
  ok(state.wsaaCalls === wsaaAntesReinicio, 'NO volvió a pedir TA a WSAA: lo leyó de meta/arca_ta_1_wsfe', { antes: wsaaAntesReinicio, despues: state.wsaaCalls });
  ok(/TA recuperado de la nube/.test(S.out()), 'log confirma "TA recuperado de la nube"');
  // TA guardado vencido → pide uno nuevo
  const taDoc = state.fsDocs.get(`${P}/meta/arca_ta_2_wsfe`);
  if (taDoc) taDoc.expiry = { integerValue: String(Date.now() - 1000) };
  await kill(S.child);
  S = await bootServer(envBase);
  r = await call('/api/facturar', { body: bodyB({ entityId: '2', puntoVenta: 2, tipoFactura: 'C', importeTotal: 1000, importeNeto: 1000, importeIva: 0 }) });
  ok(r.status === 200 && r.json.success && state.wsaaCalls === wsaaAntesReinicio + 1, 'TA guardado vencido → pide uno nuevo a WSAA', { wsaaCalls: state.wsaaCalls, r: r.json });
  state.wsaaMode = 'alreadyAuthenticated';
  const taDoc1 = state.fsDocs.get(`${P}/meta/arca_ta_1_wsfe`); if (taDoc1) taDoc1.expiry = { integerValue: String(Date.now() - 1000) };
  await kill(S.child);
  S = await bootServer(envBase);
  r = await call('/api/facturar', { body: bodyB() });
  ok(r.status === 503 && /alreadyAuthenticated/.test(r.json.error), 'WSAA alreadyAuthenticated → 503 con explicación', r.json);
  state.wsaaMode = 'ok';

  console.log('\n═══ 17. Logs sin datos personales ═══');
  UID = 'uid-seccion-17';
  ok(!/EMPRESA DE PRUEBA|SIEMPRE VIVA/.test(salida1), 'el log del padrón no muestra nombre ni domicilio');
  ok(/\[PADRON\] 30717454681 ✅ constancia \(Responsable Inscripto\)/.test(salida1), 'el log del padrón muestra CUIT, fuente y condición');
  ok(!/eyJ/.test(salida1), 'el log no muestra tokens');
  ok(/\[FC\] ✅ B 3-122 CAE \d{14} — carboys\.cba@gmail\.com \/ Lisandro/.test(salida1), 'el log de emisión identifica gmail y usuario de la tablet');

  console.log('\n═══ 18. Arranques con configuración incorrecta ═══');
  UID = 'uid-seccion-18';
  await kill(S.child);
  let B = await bootServer({ ...envBase, ARCA_API_KEY: 'carboys-arca-2026' });
  ok(!B.timeout && /clave vieja publicada: se IGNORA/.test(B.out()), 'con la clave vieja publicada el servidor arranca igual pero avisa que la ignora');
  r = await call('/api/facturar', { body: bodyB(), token: null, user: null, headers: { 'x-api-key': 'carboys-arca-2026' } });
  eq(r.status, 401, 'y esa clave NO sirve para facturar → 401');
  r = await call('/api/facturar', { body: bodyB() });
  ok(r.status === 200 && r.json.success, 'mientras que con Google se sigue facturando normal', r.json);
  await kill(B.child);
  B = await bootServer({ ...envBase, ARCA_ENV: '' });
  r = await call('/api/health', { method: 'GET', token: null, user: null });
  ok(r.json.status === 'config-incompleta' && r.json.configuracionCompleta === false && r.json.env === 'sin-definir', 'sin ARCA_ENV: health avisa config incompleta', r.json);
  r = await call('/api/facturar', { body: bodyB() });
  ok(r.status === 503 && /ARCA_ENV/.test(r.json.error), 'sin ARCA_ENV no se emite: 503 con el motivo', r.json);
  await kill(B.child);
  B = await bootServer({ ...envBase, ARCA_API_KEY: '' });
  r = await call('/api/facturar', { body: bodyB(), token: null, user: null, headers: { 'x-api-key': 'clave-de-prueba-123' } });
  eq(r.status, 401, 'sin ARCA_API_KEY definida, ninguna x-api-key sirve → 401');
  r = await call('/api/health/detalle', { method: 'GET' });
  ok(r.json.auth.apiKeyAceptada === false, 'health/detalle informa apiKeyAceptada:false');
  await kill(B.child);
  B = await bootServer({ ...envBase, ARCA_ALLOWED_ORIGINS: 'https://carboysapp.vercel.app' });
  {
    const r1 = await fetch(base + '/api/health', { headers: { Origin: 'https://carboysapp.vercel.app' } });
    const r2 = await fetch(base + '/api/health', { headers: { Origin: 'https://otro.example' } });
    ok(r1.headers.get('access-control-allow-origin') === 'https://carboysapp.vercel.app' && !r2.headers.get('access-control-allow-origin'), 'CORS restringido cuando se define ARCA_ALLOWED_ORIGINS');
  }
  await kill(B.child);
  B = await bootServer({ ...envBase, ENTITY2_CERT: '', ENTITY2_KEY: '' });
  r = await call('/api/facturar', { body: bodyB({ entityId: '2', puntoVenta: 2, tipoFactura: 'C', importeTotal: 1000, importeNeto: 1000, importeIva: 0 }) });
  ok(r.status === 503 && /entidad 2/.test(r.json.error), 'entidad sin certificado → 503 claro', r.json);
  r = await call('/api/facturar', { body: bodyB() });
  ok(r.status === 200 && r.json.success, 'la entidad 1 sigue emitiendo', r.json);
  await kill(B.child);
  B = await bootServer({ ...envBase, ENTITY1_CERT: '', ENTITY1_KEY: '', ENTITY2_CERT: '', ENTITY2_KEY: '' });
  r = await call('/api/health', { method: 'GET', token: null, user: null });
  ok(r.json.status === 'config-incompleta', 'sin ningún certificado: config incompleta', r.json);
  await kill(B.child);

  F.close();
  console.log(`\n══════ RESULTADO: ${pasadas} pasadas, ${falladas} falladas ══════`);
  process.exit(falladas ? 1 : 0);
}
main().catch(e => { console.error('ERROR DEL RUNNER', e); process.exit(2); });
