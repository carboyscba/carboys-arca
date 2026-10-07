// Servidores simulados para probar server.js en frío:
//  - Google certs (JSON kid → cert PEM)
//  - Firestore REST (GET/PATCH de documentos, en memoria)
//  - WSAA (loginCms)
//  - WSFEv1 (FECompUltimoAutorizado, FECAESolicitar, FECompConsultar)
//  - Padrón A13 / Constancia A5
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import os from 'node:os';
import { execSync } from 'node:child_process';

export const here = path.dirname(fileURLToPath(import.meta.url));

// Certificados autofirmados de prueba, generados al vuelo (no se guardan en el repo).
function generarCertificados() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'arca-test-certs-'));
  const par = (nombre, cn) => {
    execSync(`openssl req -x509 -newkey rsa:2048 -nodes -keyout "${dir}/${nombre}-key.pem" -out "${dir}/${nombre}-cert.pem" -subj "/CN=${cn}" -days 2`, { stdio: 'pipe' });
    return { cert: fs.readFileSync(`${dir}/${nombre}-cert.pem`, 'utf8'), key: fs.readFileSync(`${dir}/${nombre}-key.pem`, 'utf8') };
  };
  const ent = par('ent', 'carboys-test'), g = par('g', 'securetoken-test');
  fs.rmSync(dir, { recursive: true, force: true });
  return { entCert: ent.cert, entKey: ent.key, gCert: g.cert, gKey: g.key };
}
export const certs = generarCertificados();

const readBody = (req) => new Promise((res) => { let d = ''; req.on('data', c => d += c); req.on('end', () => res(d)); });
const listen = (srv) => new Promise((res) => srv.listen(0, '127.0.0.1', () => res(srv.address().port)));

const fmtAR = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Argentina/Buenos_Aires', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' });
export const ahoraAR = (d = new Date()) => { const p = fmtAR.formatToParts(d).reduce((o, x) => (o[x.type] = x.value, o), {}); return `${p.year}${p.month}${p.day}${p.hour}${p.minute}${p.second}`; };
export const hoyAR = (d = new Date()) => ahoraAR(d).slice(0, 8);

export async function startFakes() {
  const state = {
    wsaaCalls: 0, wsaaMode: 'ok',                 // ok | alreadyAuthenticated | http500
    fsMode: 'ok',                                 // ok | down
    fsDocs: new Map(),                            // `${project}/${path}` → fields
    fsLog: [],
    wsfe: {
      last: {},                                   // `${pv}:${tipo}` → último nro
      emitidos: new Map(),                        // `${pv}:${tipo}:${nro}` → {xml fields}
      mode: 'ok',                                 // ok | cut | reject | obs | bumpOnce | ultimoError
      requests: [],                               // {action, body}
      caeSeq: 70000000000000,
    },
    padronMode: 'ok',                             // ok | cifail-a13 (constancia falla, A13 responde) | a13fail-ci | fail
  };

  // ── Google certs ──
  const google = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=3600' });
    res.end(JSON.stringify({ k1: certs.gCert }));
  });

  // ── Firestore ──
  const firestore = http.createServer(async (req, res) => {
    const body = await readBody(req);
    const url = new URL(req.url, 'http://x');
    const m = /^\/v1\/projects\/([^/]+)\/databases\/\(default\)\/documents\/(.+)$/.exec(url.pathname);
    state.fsLog.push({ method: req.method, path: url.pathname, auth: req.headers.authorization || '', query: url.search });
    if (state.fsMode === 'down') { res.writeHead(500, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ error: { message: 'simulado: caído' } })); }
    if (!m) { res.writeHead(404); return res.end('{}'); }
    if (!/^Bearer .+/.test(req.headers.authorization || '')) { res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ error: { message: 'sin token' } })); }
    const key = `${decodeURIComponent(m[1])}/${decodeURIComponent(m[2])}`;
    if (req.method === 'GET') {
      const f = state.fsDocs.get(key);
      if (!f) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ error: { code: 404, message: 'Document not found' } })); }
      res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ name: key, fields: f }));
    }
    if (req.method === 'PATCH') {
      const j = JSON.parse(body || '{}');
      const prev = state.fsDocs.get(key) || {};
      const masks = url.searchParams.getAll('updateMask.fieldPaths');
      const next = { ...prev };
      for (const k of (masks.length ? masks : Object.keys(j.fields || {}))) { if (j.fields && j.fields[k] !== undefined) next[k] = j.fields[k]; }
      state.fsDocs.set(key, next);
      res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ name: key, fields: next }));
    }
    res.writeHead(405); res.end('{}');
  });

  // ── WSAA ──
  const wsaa = http.createServer(async (req, res) => {
    const body = await readBody(req);
    state.wsaaCalls++;
    if (!/<wsaa:in0>[A-Za-z0-9+/=\s]+<\/wsaa:in0>/.test(body)) { res.writeHead(500); return res.end('<faultstring>CMS invalido</faultstring>'); }
    if (state.wsaaMode === 'alreadyAuthenticated') {
      res.writeHead(500, { 'Content-Type': 'text/xml' });
      return res.end('<soapenv:Envelope><soapenv:Body><soapenv:Fault><faultcode>ns1:coe.alreadyAuthenticated</faultcode><faultstring>El CEE ya posee un TA valido para el acceso al WSN solicitado</faultstring></soapenv:Fault></soapenv:Body></soapenv:Envelope>');
    }
    if (state.wsaaMode === 'http500') { res.writeHead(500); return res.end('<faultstring>caido</faultstring>'); }
    const exp = new Date(Date.now() + 12 * 3600 * 1000).toISOString();
    const inner = `<loginTicketResponse><header><expirationTime>${exp}</expirationTime></header><credentials><token>TOKEN-${state.wsaaCalls}</token><sign>SIGN-${state.wsaaCalls}</sign></credentials></loginTicketResponse>`;
    const esc = inner.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    res.writeHead(200, { 'Content-Type': 'text/xml' });
    res.end(`<soapenv:Envelope><soapenv:Body><loginCmsResponse><loginCmsReturn>${esc}</loginCmsReturn></loginCmsResponse></soapenv:Body></soapenv:Envelope>`);
  });

  // ── WSFEv1 ──
  const g = (xml, tag) => { const m = xml.match(new RegExp(`<ar:${tag}>([^<]*)</ar:${tag}>`)); return m ? m[1] : ''; };
  const errXml = (code, msg) => `<Errors><Err><Code>${code}</Code><Msg>${msg}</Msg></Err></Errors>`;
  const wsfe = http.createServer(async (req, res) => {
    const body = await readBody(req);
    const action = String(req.headers.soapaction || '').replace(/"/g, '');
    const w = state.wsfe;
    w.requests.push({ action, body });
    const authOk = /<ar:Token>TOKEN-\d+<\/ar:Token><ar:Sign>SIGN-\d+<\/ar:Sign><ar:Cuit>\d{11}<\/ar:Cuit>/.test(body);
    const ok = (inner) => { res.writeHead(200, { 'Content-Type': 'text/xml' }); res.end(`<soap:Envelope><soap:Body>${inner}</soap:Body></soap:Envelope>`); };
    if (!authOk) return ok(`<FECAESolicitarResponse><FECAESolicitarResult>${errXml(600, 'ValidacionDeToken: sin token')}</FECAESolicitarResult></FECAESolicitarResponse>`);

    if (action.endsWith('FECompUltimoAutorizado')) {
      const pv = g(body, 'PtoVta'), tipo = g(body, 'CbteTipo');
      if (w.mode === 'ultimoError') return ok(`<FECompUltimoAutorizadoResponse><FECompUltimoAutorizadoResult>${errXml(601, 'CUIT representada no incluida en Token')}</FECompUltimoAutorizadoResult></FECompUltimoAutorizadoResponse>`);
      const last = w.last[`${pv}:${tipo}`] ?? 0;
      return ok(`<FECompUltimoAutorizadoResponse><FECompUltimoAutorizadoResult><PtoVta>${pv}</PtoVta><CbteTipo>${tipo}</CbteTipo><CbteNro>${last}</CbteNro></FECompUltimoAutorizadoResult></FECompUltimoAutorizadoResponse>`);
    }

    if (action.endsWith('FECAESolicitar')) {
      const pv = g(body, 'PtoVta'), tipo = g(body, 'CbteTipo'), nro = parseInt(g(body, 'CbteDesde'), 10);
      const k = `${pv}:${tipo}`;
      const last = w.last[k] ?? 0;
      // invariantes mínimas que ARCA exigiría
      const faltan = ['Concepto', 'DocTipo', 'DocNro', 'CbteFch', 'ImpTotal', 'ImpNeto', 'ImpIVA', 'MonId', 'MonCotiz', 'CondicionIVAReceptorId'].filter(t => g(body, t) === '');
      if (faltan.length) return ok(`<FECAESolicitarResponse><FECAESolicitarResult>${errXml(10000, 'Faltan campos: ' + faltan.join(','))}</FECAESolicitarResult></FECAESolicitarResponse>`);
      if (w.mode === 'bumpOnce') { w.last[k] = last + 1; w.emitidos.set(`${k}:${last + 1}`, { otro: true, DocNro: '0', ImpTotal: '1.00', CbteFch: hoyAR(), CAE: '11111111111111', FchProceso: ahoraAR() }); w.mode = 'ok'; }
      if (nro !== (w.last[k] ?? 0) + 1) return ok(`<FECAESolicitarResponse><FECAESolicitarResult><FeDetResp><FECAEDetResponse><Resultado>R</Resultado><Observaciones><Obs><Code>10016</Code><Msg>El numero o fecha del comprobante no se corresponde con el proximo a autorizar.</Msg></Obs></Observaciones></FECAEDetResponse></FeDetResp>${errXml(10016, 'El numero o fecha del comprobante no se corresponde con el proximo a autorizar. Consultar metodo FECompUltimoAutorizado.')}</FECAESolicitarResult></FECAESolicitarResponse>`);
      if (w.mode === 'reject') return ok(`<FECAESolicitarResponse><FECAESolicitarResult><FeDetResp><FECAEDetResponse><Resultado>R</Resultado><Observaciones><Obs><Code>10015</Code><Msg>Campo DocNro invalido para el DocTipo informado</Msg></Obs></Observaciones></FECAEDetResponse></FeDetResp></FECAESolicitarResult></FECAESolicitarResponse>`);
      // emisión aprobada
      const cae = String(w.caeSeq++);
      const caeVto = hoyAR(new Date(Date.now() + 10 * 86400000));
      w.last[k] = nro;
      w.emitidos.set(`${k}:${nro}`, { DocTipo: g(body, 'DocTipo'), DocNro: g(body, 'DocNro'), ImpTotal: g(body, 'ImpTotal'), ImpNeto: g(body, 'ImpNeto'), ImpIVA: g(body, 'ImpIVA'), CbteFch: g(body, 'CbteFch'), CAE: cae, CAEFchVto: caeVto, FchProceso: ahoraAR(), Cond: g(body, 'CondicionIVAReceptorId'), tieneAsoc: /<ar:CbtesAsoc>/.test(body), tieneIva: /<ar:Iva>/.test(body) });
      if (w.mode === 'cut') { w.mode = 'ok'; return req.socket.destroy(); }     // se corta DESPUÉS de autorizar
      const obs = w.mode === 'obs' ? `<Observaciones><Obs><Code>10217</Code><Msg>Observacion de prueba</Msg></Obs></Observaciones>` : '';
      return ok(`<FECAESolicitarResponse><FECAESolicitarResult><FeCabResp><Resultado>A</Resultado></FeCabResp><FeDetResp><FECAEDetResponse><Concepto>${g(body, 'Concepto')}</Concepto><DocTipo>${g(body, 'DocTipo')}</DocTipo><DocNro>${g(body, 'DocNro')}</DocNro><CbteDesde>${nro}</CbteDesde><CbteHasta>${nro}</CbteHasta><CbteFch>${g(body, 'CbteFch')}</CbteFch><Resultado>A</Resultado><CAE>${cae}</CAE><CAEFchVto>${caeVto}</CAEFchVto>${obs}</FECAEDetResponse></FeDetResp></FECAESolicitarResult></FECAESolicitarResponse>`);
    }

    if (action.endsWith('FECompConsultar')) {
      const pv = g(body, 'PtoVta'), tipo = g(body, 'CbteTipo'), nro = parseInt(g(body, 'CbteNro'), 10);
      const e = w.emitidos.get(`${pv}:${tipo}:${nro}`);
      if (!e) return ok(`<FECompConsultarResponse><FECompConsultarResult>${errXml(602, 'No existen datos en nuestros registros para los parametros ingresados.')}</FECompConsultarResult></FECompConsultarResponse>`);
      return ok(`<FECompConsultarResponse><FECompConsultarResult><ResultGet><Concepto>3</Concepto><DocTipo>${e.DocTipo || 99}</DocTipo><DocNro>${e.DocNro}</DocNro><CbteDesde>${nro}</CbteDesde><CbteHasta>${nro}</CbteHasta><CbteFch>${e.CbteFch}</CbteFch><ImpTotal>${e.ImpTotal}</ImpTotal><ImpNeto>${e.ImpNeto || e.ImpTotal}</ImpNeto><ImpIVA>${e.ImpIVA || '0.00'}</ImpIVA><Resultado>A</Resultado><CodAutorizacion>${e.CAE}</CodAutorizacion><EmisionTipo>CAE</EmisionTipo><FchVto>${e.CAEFchVto || ''}</FchVto><FchProceso>${e.FchProceso}</FchProceso><PtoVta>${pv}</PtoVta><CbteTipo>${tipo}</CbteTipo></ResultGet></FECompConsultarResult></FECompConsultarResponse>`);
    }
    res.writeHead(500); res.end('<faultstring>accion desconocida</faultstring>');
  });

  // ── Padrón ──
  // Realista: A13 devuelve solo nombre y domicilio (sin impuestos); la
  // constancia (A5) trae además <datosRegimenGeneral> con el IVA 30.
  const padron = http.createServer(async (req, res) => {
    await readBody(req);
    const esA13 = req.url.includes('A13');
    const falla = state.padronMode === 'fail' || (state.padronMode === 'cifail-a13' && !esA13) || (state.padronMode === 'a13fail-ci' && esA13);
    if (falla) { res.writeHead(500); return res.end('<faultstring>No existe persona con ese Id</faultstring>'); }
    res.writeHead(200, { 'Content-Type': 'text/xml' });
    const dom = '<direccion>AV SIEMPRE VIVA 123</direccion><localidad>CORDOBA</localidad><descripcionProvincia>CORDOBA</descripcionProvincia><codPostal>5000</codPostal>';
    if (esA13) return res.end(`<soap:Envelope><soap:Body><ns2:getPersonaResponse><personaReturn><persona><tipoPersona>JURIDICA</tipoPersona><razonSocial>EMPRESA DE PRUEBA S.A.</razonSocial><domicilio>${dom}</domicilio></persona></personaReturn></ns2:getPersonaResponse></soap:Body></soap:Envelope>`);
    res.end(`<soap:Envelope><soap:Body><ns2:getPersona_v2Response><personaReturn><datosGenerales><tipoPersona>JURIDICA</tipoPersona><razonSocial>EMPRESA DE PRUEBA S.A.</razonSocial><domicilioFiscal>${dom}</domicilioFiscal></datosGenerales><datosRegimenGeneral><impuesto><idImpuesto>30</idImpuesto><descripcionImpuesto>IVA</descripcionImpuesto></impuesto></datosRegimenGeneral></personaReturn></ns2:getPersona_v2Response></soap:Body></soap:Envelope>`);
  });

  const ports = {
    google: await listen(google), firestore: await listen(firestore), wsaa: await listen(wsaa), wsfe: await listen(wsfe), padron: await listen(padron),
  };
  const close = () => { for (const s of [google, firestore, wsaa, wsfe, padron]) s.close(); };
  return { state, ports, close };
}
