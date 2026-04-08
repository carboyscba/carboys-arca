const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const https = require('https');
const http = require('http');
const forge = require('node-forge');
const { parseString, Builder } = require('xml2js');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json({ limit: '5mb' }));

// ── Config ──
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.ARCA_API_KEY || 'carboys-arca-2026';
const IS_PRODUCTION = process.env.ARCA_ENV === 'production';

const WSAA_URL = IS_PRODUCTION
  ? 'https://wsaa.afip.gov.ar/ws/services/LoginCms'
  : 'https://wsaahomo.afip.gov.ar/ws/services/LoginCms';

const WSFE_URL = IS_PRODUCTION
  ? 'https://servicios1.afip.gov.ar/wsfev1/service.asmx'
  : 'https://wswhomo.afip.gov.ar/wsfev1/service.asmx';

const PADRON_URL = IS_PRODUCTION
  ? 'https://aws.afip.gov.ar/sr-padron/webservices/personaServiceA13'
  : 'https://awshomo.afip.gov.ar/sr-padron/webservices/personaServiceA13';

// ── Certificates ──
const decodeEnv = (v) => v ? Buffer.from(v, 'base64').toString('utf8') : '';

const ENTITIES = {
  '1': {
    name: 'CARBOYS S.A.S.',
    cuit: process.env.ENTITY1_CUIT || '30717454681',
    cert: decodeEnv(process.env.ENTITY1_CERT),
    key: decodeEnv(process.env.ENTITY1_KEY),
  },
  '2': {
    name: 'KARQUI VICTOR LISANDRO IGNACIO',
    cuit: process.env.ENTITY2_CUIT || '20344412171',
    cert: decodeEnv(process.env.ENTITY2_CERT),
    key: decodeEnv(process.env.ENTITY2_KEY),
  }
};

const tokenCache = {};

const auth = (req, res, next) => {
  const key = req.headers['x-api-key'];
  if (key !== API_KEY) return res.status(401).json({ error: 'Unauthorized' });
  next();
};

function soapRequest(url, body, soapAction) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || 443,
      path: urlObj.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'text/xml; charset=utf-8',
        'Content-Length': Buffer.byteLength(body),
        ...(soapAction !== undefined ? { 'SOAPAction': soapAction } : {})
      },
      rejectUnauthorized: false
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
    req.setTimeout(15000, () => { req.destroy(); reject(new Error('Timeout')); });
    req.write(body);
    req.end();
  });
}

function parseXml(xml) {
  return new Promise((resolve, reject) => {
    parseString(xml, { explicitArray: false, ignoreAttrs: false }, (err, result) => {
      err ? reject(err) : resolve(result);
    });
  });
}

function createCMS(certPem, keyPem, service) {
  const { execSync } = require('child_process');
  const os = require('os');
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

  const tmpDir = os.tmpdir();
  const ts = Date.now();
  const traFile = `${tmpDir}/tra_${ts}.xml`;
  const cmsFile = `${tmpDir}/cms_${ts}.cms`;
  const certFile = `${tmpDir}/cert_${ts}.pem`;
  const keyFile = `${tmpDir}/key_${ts}.pem`;

  fs.writeFileSync(traFile, tra);
  fs.writeFileSync(certFile, certPem);
  fs.writeFileSync(keyFile, keyPem);

  try {
    execSync(`openssl cms -sign -in "${traFile}" -out "${cmsFile}" -signer "${certFile}" -inkey "${keyFile}" -outform DER -nodetach`, { stdio: 'pipe' });
    const cms = fs.readFileSync(cmsFile);
    return cms.toString('base64');
  } finally {
    try { fs.unlinkSync(traFile); } catch(e) {}
    try { fs.unlinkSync(cmsFile); } catch(e) {}
    try { fs.unlinkSync(certFile); } catch(e) {}
    try { fs.unlinkSync(keyFile); } catch(e) {}
  }
}

async function getToken(entityId, service = 'wsfe') {
  const entity = ENTITIES[entityId];
  if (!entity || !entity.cert || !entity.key) throw new Error(`Entity ${entityId} not configured`);

  const cacheKey = `${entityId}_${service}`;
  if (tokenCache[cacheKey] && tokenCache[cacheKey].expiry > Date.now()) {
    console.log(`[WSAA] Cached token for entity ${entityId} service ${service}`);
    return tokenCache[cacheKey];
  }

  console.log(`[WSAA] New token for entity ${entityId} (${entity.name}) service ${service}`);
  const cms = createCMS(entity.cert, entity.key, service);

  const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsaa="http://wsaa.view.sua.dvadac.desein.afip.gov">
  <soapenv:Body>
    <wsaa:loginCms>
      <wsaa:in0>${cms}</wsaa:in0>
    </wsaa:loginCms>
  </soapenv:Body>
</soapenv:Envelope>`;

  const response = await soapRequest(WSAA_URL, soapBody, '');
  let credXml = '';
  const match = response.match(/<loginCmsReturn>([\s\S]*?)<\/loginCmsReturn>/);
  if (match) {
    credXml = match[1].replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&amp;/g, '&');
  }
  if (!credXml) throw new Error('WSAA: No loginCmsReturn: ' + response.substring(0, 500));

  const tokenMatch = credXml.match(/<token>([\s\S]*?)<\/token>/);
  const signMatch = credXml.match(/<sign>([\s\S]*?)<\/sign>/);
  const expiryMatch = credXml.match(/<expirationTime>([\s\S]*?)<\/expirationTime>/);
  if (!tokenMatch || !signMatch) throw new Error('WSAA: No credentials: ' + credXml.substring(0, 300));

  const result = {
    token: tokenMatch[1].trim(),
    sign: signMatch[1].trim(),
    cuit: entity.cuit,
    expiry: expiryMatch ? new Date(expiryMatch[1].trim()).getTime() - 60000 : Date.now() + 36000000
  };
  tokenCache[cacheKey] = result;
  console.log(`[WSAA] Token OK for ${entity.name} service ${service}`);
  return result;
}

async function getLastInvoiceNum(entityId, puntoVenta, tipoComprobante) {
  const authObj = await getToken(entityId);
  const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ar="http://ar.gov.afip.dif.FEV1/">
  <soapenv:Body>
    <ar:FECompUltimoAutorizado>
      <ar:Auth><ar:Token>${authObj.token}</ar:Token><ar:Sign>${authObj.sign}</ar:Sign><ar:Cuit>${authObj.cuit}</ar:Cuit></ar:Auth>
      <ar:PtoVta>${puntoVenta}</ar:PtoVta>
      <ar:CbteTipo>${tipoComprobante}</ar:CbteTipo>
    </ar:FECompUltimoAutorizado>
  </soapenv:Body>
</soapenv:Envelope>`;
  const response = await soapRequest(WSFE_URL, soapBody, 'http://ar.gov.afip.dif.FEV1/FECompUltimoAutorizado');
  const matchNum = response.match(/<CbteNro>([\d]+)<\/CbteNro>/);
  return matchNum ? parseInt(matchNum[1]) : 0;
}

async function createInvoice(entityId, invoiceData) {
  const authData = await getToken(entityId);
  const { puntoVenta, tipoComprobante, concepto, docTipo, docNro, importeTotal, importeNeto, importeIva, fchServDesde, fchServHasta, fchVtoPago, actividad } = invoiceData;
  const lastNum = await getLastInvoiceNum(entityId, puntoVenta, tipoComprobante);
  const nextNum = lastNum + 1;
  const today = new Date().toISOString().split('T')[0].replace(/-/g, '');

  const isFCA = tipoComprobante === 1;
  const isFCB = tipoComprobante === 6;
  const isFCC = tipoComprobante === 11;

  // FC A (1): IVA discriminado → ImpNeto + ImpIVA = ImpTotal
  // FC B (6): IVA incluido, alicuota 21% → ImpNeto + ImpIVA = ImpTotal
  // FC C (11): Monotributo, sin IVA → ImpNeto = total
  const impTotConc = 0;
  const impNeto = (isFCA || isFCB) ? importeNeto : (isFCC ? importeTotal : 0);
  const impIVA = (isFCA || isFCB) ? (importeIva || 0) : 0;

  let ivaXml = '';
  if ((isFCA || isFCB) && importeIva > 0) {
    ivaXml = `<ar:Iva><ar:AlicIva><ar:Id>5</ar:Id><ar:BaseImp>${impNeto.toFixed(2)}</ar:BaseImp><ar:Importe>${impIVA.toFixed(2)}</ar:Importe></ar:AlicIva></ar:Iva>`;
  }

  // Actividades asociadas al comprobante (solo FC A/B de CARBOYS S.A.S.)
  let actividadesXml = '';
  if ((isFCA || isFCB) && actividad) {
    actividadesXml = `<ar:Actividades><ar:Actividad><ar:Id>${actividad}</ar:Id></ar:Actividad></ar:Actividades>`;
  }

  // Fechas de servicio obligatorias para concepto 2 (Servicios) y 3 (Productos y Servicios)
  const cpto = concepto || 1;
  let fechasXml = '';
  if (cpto === 2 || cpto === 3) {
    const desde = fchServDesde || today;
    const hasta = fchServHasta || today;
    const vtoPago = fchVtoPago || today;
    fechasXml = `
            <ar:FchServDesde>${desde}</ar:FchServDesde>
            <ar:FchServHasta>${hasta}</ar:FchServHasta>
            <ar:FchVtoPago>${vtoPago}</ar:FchVtoPago>`;
  }

  const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ar="http://ar.gov.afip.dif.FEV1/">
  <soapenv:Body>
    <ar:FECAESolicitar>
      <ar:Auth><ar:Token>${authData.token}</ar:Token><ar:Sign>${authData.sign}</ar:Sign><ar:Cuit>${authData.cuit}</ar:Cuit></ar:Auth>
      <ar:FeCAEReq>
        <ar:FeCabReq><ar:CantReg>1</ar:CantReg><ar:PtoVta>${puntoVenta}</ar:PtoVta><ar:CbteTipo>${tipoComprobante}</ar:CbteTipo></ar:FeCabReq>
        <ar:FeDetReq>
          <ar:FECAEDetRequest>
            <ar:Concepto>${cpto}</ar:Concepto>
            <ar:DocTipo>${docTipo}</ar:DocTipo>
            <ar:DocNro>${docNro}</ar:DocNro>
            <ar:CbteDesde>${nextNum}</ar:CbteDesde>
            <ar:CbteHasta>${nextNum}</ar:CbteHasta>
            <ar:CbteFch>${today}</ar:CbteFch>${fechasXml}
            <ar:ImpTotal>${importeTotal.toFixed(2)}</ar:ImpTotal>
            <ar:ImpTotConc>${impTotConc.toFixed(2)}</ar:ImpTotConc>
            <ar:ImpNeto>${impNeto.toFixed(2)}</ar:ImpNeto>
            <ar:ImpOpEx>0.00</ar:ImpOpEx>
            <ar:ImpTrib>0.00</ar:ImpTrib>
            <ar:ImpIVA>${impIVA.toFixed(2)}</ar:ImpIVA>
            <ar:MonId>PES</ar:MonId>
            <ar:MonCotiz>1</ar:MonCotiz>
            ${ivaXml}
            ${actividadesXml}
          </ar:FECAEDetRequest>
        </ar:FeDetReq>
      </ar:FeCAEReq>
    </ar:FECAESolicitar>
  </soapenv:Body>
</soapenv:Envelope>`;

  console.log(`[WSFEv1] Invoice: PV=${puntoVenta} Tipo=${tipoComprobante} Nro=${nextNum} Total=${importeTotal}${actividad ? ' Actividad=' + actividad : ''}`);
  const response = await soapRequest(WSFE_URL, soapBody, 'http://ar.gov.afip.dif.FEV1/FECAESolicitar');

  const caeMatch = response.match(/<CAE>([\d]+)<\/CAE>/);
  const vtoMatch = response.match(/<CAEFchVto>([\d]+)<\/CAEFchVto>/);
  const resultMatch = response.match(/<Resultado>(\w+)<\/Resultado>/);
  const errMatch = response.match(/<Err>.*?<Code>(\d+)<\/Code>.*?<Msg>(.*?)<\/Msg>/s);

  if (resultMatch && resultMatch[1] === 'A' && caeMatch) {
    return { success: true, cae: caeMatch[1], caeVto: vtoMatch ? vtoMatch[1] : '', cbteNro: nextNum, cbteTipo: tipoComprobante, puntoVenta, resultado: 'A' };
  } else {
    const obsMatches = [...response.matchAll(/<Obs>[\s\S]*?<Code>(\d+)<\/Code>[\s\S]*?<Msg>([\s\S]*?)<\/Msg>[\s\S]*?<\/Obs>/g)];
    const obsMsg = obsMatches.map(m => `${m[1]}: ${m[2]}`).join(' | ');
    const errMsg = errMatch ? `${errMatch[1]}: ${errMatch[2]}` : '';
    return { success: false, error: errMsg || obsMsg || 'Error desconocido', rawResponse: response.substring(0, 2000) };
  }
}

// ════════════════════════════════════════════════════════════════════
// PADRON A13 — Namespace CORRECTO: http://a13.soap.ws.server.puc.sr/
// ════════════════════════════════════════════════════════════════════
async function consultarPadronAuth(entityId, cuitConsulta) {
  const cleanCuit = String(cuitConsulta).replace(/[^0-9]/g, '');
  if (!cleanCuit || cleanCuit.length < 7) throw new Error('CUIT invalido');

  const authData = await getToken(entityId, 'ws_sr_padron_a13');

  const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:a13="http://a13.soap.ws.server.puc.sr/">
  <soapenv:Header/>
  <soapenv:Body>
    <a13:getPersona>
      <token>${authData.token}</token>
      <sign>${authData.sign}</sign>
      <cuitRepresentada>${authData.cuit}</cuitRepresentada>
      <idPersona>${cleanCuit}</idPersona>
    </a13:getPersona>
  </soapenv:Body>
</soapenv:Envelope>`;

  console.log(`[PADRON-A13] Query CUIT ${cleanCuit} via entity ${entityId}`);
  const response = await soapRequest(PADRON_URL, soapBody, '');
  console.log(`[PADRON-A13] Response (500): ${response.substring(0, 500)}`);

  const faultMatch = response.match(/<faultstring>([^<]*)<\/faultstring>/);
  if (faultMatch) throw new Error('A13 fault: ' + faultMatch[1]);

  return extractPadronData(response, cleanCuit, 'ws_sr_padron_a13');
}

// ── Constancia de inscripcion fallback ──
async function consultarConstancia(entityId, cuitConsulta) {
  const cleanCuit = String(cuitConsulta).replace(/[^0-9]/g, '');
  const CONSTANCIA_URL = IS_PRODUCTION
    ? 'https://aws.afip.gov.ar/sr-padron/webservices/personaServiceA5'
    : 'https://awshomo.afip.gov.ar/sr-padron/webservices/personaServiceA5';

  const authData = await getToken(entityId, 'ws_sr_constancia_inscripcion');

  const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:a5="http://a5.soap.ws.server.puc.sr/">
  <soapenv:Header/>
  <soapenv:Body>
    <a5:getPersona_v2>
      <token>${authData.token}</token>
      <sign>${authData.sign}</sign>
      <cuitRepresentada>${authData.cuit}</cuitRepresentada>
      <idPersona>${cleanCuit}</idPersona>
    </a5:getPersona_v2>
  </soapenv:Body>
</soapenv:Envelope>`;

  console.log(`[PADRON-CI] Query CUIT ${cleanCuit}`);
  const response = await soapRequest(CONSTANCIA_URL, soapBody, '');
  console.log(`[PADRON-CI] Response (500): ${response.substring(0, 500)}`);

  const faultMatch = response.match(/<faultstring>([^<]*)<\/faultstring>/);
  if (faultMatch) throw new Error('Constancia fault: ' + faultMatch[1]);

  return extractPadronData(response, cleanCuit, 'ws_sr_constancia_inscripcion');
}

// ── Shared extraction logic ──
function extractPadronData(response, cleanCuit, source) {
  const razonSocial = response.match(/<razonSocial>([^<]*)<\/razonSocial>/);
  const apellido = response.match(/<apellido>([^<]*)<\/apellido>/);
  const nombre = response.match(/<nombre>([^<]*)<\/nombre>/);
  const tipoPersona = response.match(/<tipoPersona>([^<]*)<\/tipoPersona>/);
  const direccion = response.match(/<direccion>([^<]*)<\/direccion>/);
  const localidad = response.match(/<localidad>([^<]*)<\/localidad>/);
  const provincia = response.match(/<descripcionProvincia>([^<]*)<\/descripcionProvincia>/);
  const codPostal = response.match(/<codPostal>([^<]*)<\/codPostal>/);

  if (!razonSocial && !apellido && !nombre) {
    throw new Error('No data in ' + source + ' response: ' + response.substring(0, 300));
  }

  const isJuridica = tipoPersona && tipoPersona[1] === 'JURIDICA';
  const fullName = isJuridica
    ? (razonSocial ? razonSocial[1] : '')
    : `${apellido ? apellido[1] : ''} ${nombre ? nombre[1] : ''}`.trim();

  const domParts = [
    direccion ? direccion[1] : '',
    localidad ? localidad[1] : '',
    provincia ? provincia[1] : '',
    codPostal ? `CP ${codPostal[1]}` : '',
  ].filter(Boolean);

  const hasImp30 = response.includes('<idImpuesto>30</idImpuesto>');
  const hasImp32 = response.includes('<idImpuesto>32</idImpuesto>');
  const hasImp20 = response.includes('<idImpuesto>20</idImpuesto>');
  const condIva = hasImp32 ? 'IVA Exento'
    : hasImp30 ? 'Responsable Inscripto'
    : hasImp20 ? 'Monotributo'
    : 'Consumidor Final';

  return {
    success: true,
    source,
    cuit: cleanCuit,
    tipoPersona: tipoPersona ? tipoPersona[1] : '',
    nombre: fullName,
    razonSocial: razonSocial ? razonSocial[1] : '',
    apellido: apellido ? apellido[1] : '',
    nombrePila: nombre ? nombre[1] : '',
    domicilioFiscal: domParts.join(', '),
    condIva,
  };
}


// ═══════════════════ API ROUTES ═══════════════════

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok', version: 'v11',
    env: IS_PRODUCTION ? 'production' : 'homologacion',
    wsaaUrl: WSAA_URL, wsfeUrl: WSFE_URL, padronUrl: PADRON_URL,
    entities: {
      '1': { name: ENTITIES['1'].name, cuit: ENTITIES['1'].cuit, hasCert: !!ENTITIES['1'].cert },
      '2': { name: ENTITIES['2'].name, cuit: ENTITIES['2'].cuit, hasCert: !!ENTITIES['2'].cert },
    }
  });
});

app.post('/api/auth', auth, async (req, res) => {
  try {
    const { entityId } = req.body;
    const token = await getToken(entityId || '1');
    res.json({ success: true, message: 'Auth OK', cuit: token.cuit });
  } catch (e) { console.error('[AUTH]', e.message); res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/ultimo-comprobante', auth, async (req, res) => {
  try {
    const { entityId, puntoVenta, tipoComprobante } = req.body;
    const num = await getLastInvoiceNum(entityId || '1', puntoVenta || 1, tipoComprobante || 1);
    res.json({ success: true, lastNumber: num });
  } catch (e) { console.error('[ULTIMO]', e.message); res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/facturar', auth, async (req, res) => {
  try {
    const { entityId, puntoVenta, tipoFactura, docTipo, docNro, importeTotal, importeNeto, importeIva, concepto, actividad, fchServDesde, fchServHasta, fchVtoPago } = req.body;
    const tipoMap = { 'A': 1, 'B': 6, 'C': 11 };
    const result = await createInvoice(entityId || '1', {
      puntoVenta: parseInt(puntoVenta) || 1,
      tipoComprobante: tipoMap[tipoFactura] || 6,
      concepto: concepto || 1,
      docTipo: parseInt(docTipo) || 99,
      docNro: parseInt(docNro) || 0,
      importeTotal: parseFloat(importeTotal) || 0,
      importeNeto: parseFloat(importeNeto) || 0,
      importeIva: parseFloat(importeIva) || 0,
      actividad: actividad ? parseInt(actividad) : null,
      fchServDesde: fchServDesde || '',
      fchServHasta: fchServHasta || '',
      fchVtoPago: fchVtoPago || '',
    });
    console.log(result.success ? `[FC] ✅ CAE: ${result.cae} Nro: ${result.cbteNro}` : `[FC] ❌ ${result.error}`);
    res.json(result);
  } catch (e) { console.error('[FACTURAR]', e.message); res.status(500).json({ success: false, error: e.message }); }
});

// ══════════════════════════════════════════
// PADRON — 2 metodos autenticados con fallback
// ══════════════════════════════════════════
app.get('/api/padron', auth, async (req, res) => {
  try {
    const cuit = req.query.cuit;
    const entityId = req.query.entity || '1';
    if (!cuit) return res.status(400).json({ success: false, error: 'Falta cuit' });

    const cleanCuit = String(cuit).replace(/[^0-9]/g, '');
    console.log(`[PADRON] ══ Lookup ${cleanCuit} entity ${entityId} ══`);

    // Method 1: ws_sr_padron_a13
    try {
      const r = await consultarPadronAuth(entityId, cleanCuit);
      console.log(`[PADRON] ✅ A13: ${r.nombre} | ${r.condIva}`);
      return res.json(r);
    } catch(e) { console.log(`[PADRON] ⚠ A13: ${e.message}`); }

    // Method 2: ws_sr_constancia_inscripcion
    try {
      const r = await consultarConstancia(entityId, cleanCuit);
      console.log(`[PADRON] ✅ CI: ${r.nombre} | ${r.condIva}`);
      return res.json(r);
    } catch(e) { console.log(`[PADRON] ⚠ CI: ${e.message}`); }

    console.log(`[PADRON] ❌ All failed for ${cleanCuit}`);
    res.status(404).json({
      success: false,
      error: 'No se pudieron obtener datos para CUIT: ' + cleanCuit,
      hint: 'Verifica que ws_sr_padron_a13 y/o ws_sr_constancia_inscripcion esten habilitados en AFIP para el certificado digital'
    });
  } catch(e) {
    console.error('[PADRON]', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── Debug endpoint ──
app.get('/api/padron-test', auth, async (req, res) => {
  const entityId = req.query.entity || '1';
  const results = {};

  try { await getToken(entityId, 'ws_sr_padron_a13'); results.a13_token = 'OK'; } catch(e) { results.a13_token = e.message; }
  try { await getToken(entityId, 'ws_sr_constancia_inscripcion'); results.ci_token = 'OK'; } catch(e) { results.ci_token = e.message; }

  try {
    const dummyBody = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:a13="http://a13.soap.ws.server.puc.sr/">
  <soapenv:Header/><soapenv:Body><a13:dummy/></soapenv:Body>
</soapenv:Envelope>`;
    const resp = await soapRequest(PADRON_URL, dummyBody, '');
    results.a13_dummy = resp.includes('<appserver>OK') ? 'OK' : resp.substring(0, 300);
  } catch(e) { results.a13_dummy = e.message; }

  res.json({ entity: entityId, name: ENTITIES[entityId]?.name, tests: results });
});


// ═══════════ START ═══════════
app.listen(PORT, () => {
  console.log(`\n🧾 CarBoys ARCA Server v12`);
  console.log(`  Port: ${PORT}`);
  console.log(`  Env: ${IS_PRODUCTION ? '🔴 PRODUCCION' : '🟡 HOMOLOGACION'}`);
  console.log(`  Entity 1: ${ENTITIES['1'].name} (${ENTITIES['1'].cuit}) Cert: ${ENTITIES['1'].cert ? '✅' : '❌'}`);
  console.log(`  Entity 2: ${ENTITIES['2'].name} (${ENTITIES['2'].cuit}) Cert: ${ENTITIES['2'].cert ? '✅' : '❌'}`);
  console.log(`\n  GET  /api/health`);
  console.log(`  GET  /api/padron?cuit=XXXX&entity=1`);
  console.log(`  GET  /api/padron-test?entity=1`);
  console.log(`  POST /api/auth`);
  console.log(`  POST /api/ultimo-comprobante`);
  console.log(`  POST /api/facturar\n`);
});
