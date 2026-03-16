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
 
// ── Certificates (loaded from base64 env vars) ──
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
 
// ── Token cache (tokens last 12h) ──
const tokenCache = {};
 
// ── Auth middleware ──
const auth = (req, res, next) => {
  const key = req.headers['x-api-key'];
  if (key !== API_KEY) return res.status(401).json({ error: 'Unauthorized' });
  next();
};
 
// ── SOAP request helper ──
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
      rejectUnauthorized: false // AFIP certs can be tricky
    };
    
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}
 
// ── Parse XML helper ──
function parseXml(xml) {
  return new Promise((resolve, reject) => {
    parseString(xml, { explicitArray: false, ignoreAttrs: false }, (err, result) => {
      err ? reject(err) : resolve(result);
    });
  });
}
 
// ── Create CMS (signed token request for WSAA) using OpenSSL ──
function createCMS(certPem, keyPem, service) {
  const { execSync } = require('child_process');
  const os = require('os');
  const now = new Date();
  const expiry = new Date(now.getTime() + 600000); // 10 min
 
  const tra = `<?xml version="1.0" encoding="UTF-8"?>
<loginTicketRequest version="1.0">
  <header>
    <uniqueId>${Math.floor(Date.now() / 1000)}</uniqueId>
    <generationTime>${now.toISOString()}</generationTime>
    <expirationTime>${expiry.toISOString()}</expirationTime>
  </header>
  <service>${service}</service>
</loginTicketRequest>`;
 
  // Write temp files
  const tmpDir = os.tmpdir();
  const traFile = `${tmpDir}/tra_${Date.now()}.xml`;
  const cmsFile = `${tmpDir}/cms_${Date.now()}.cms`;
  const certFile = `${tmpDir}/cert_${Date.now()}.pem`;
  const keyFile = `${tmpDir}/key_${Date.now()}.pem`;
  
  fs.writeFileSync(traFile, tra);
  fs.writeFileSync(certFile, certPem);
  fs.writeFileSync(keyFile, keyPem);
  
  try {
    // Use OpenSSL to create PKCS#7 CMS signature (ARCA compatible)
    execSync(`openssl cms -sign -in "${traFile}" -out "${cmsFile}" -signer "${certFile}" -inkey "${keyFile}" -outform DER -nodetach`, { stdio: 'pipe' });
    const cms = fs.readFileSync(cmsFile);
    return cms.toString('base64');
  } finally {
    // Cleanup temp files
    try { fs.unlinkSync(traFile); } catch(e) {}
    try { fs.unlinkSync(cmsFile); } catch(e) {}
    try { fs.unlinkSync(certFile); } catch(e) {}
    try { fs.unlinkSync(keyFile); } catch(e) {}
  }
}
 
// ── WSAA: Get auth token ──
async function getToken(entityId, service = 'wsfe') {
  const entity = ENTITIES[entityId];
  if (!entity || !entity.cert || !entity.key) {
    throw new Error(`Entity ${entityId} not configured`);
  }
  
  // Check cache
  const cacheKey = `${entityId}_${service}`;
  if (tokenCache[cacheKey] && tokenCache[cacheKey].expiry > Date.now()) {
    console.log(`[WSAA] Using cached token for entity ${entityId}`);
    return tokenCache[cacheKey];
  }
  
  console.log(`[WSAA] Requesting new token for entity ${entityId} (${entity.name})`);
  
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
  
  // Extract loginCmsReturn - try multiple approaches
  let credXml = '';
  
  // Method 1: regex on raw response
  const match = response.match(/<loginCmsReturn>([\s\S]*?)<\/loginCmsReturn>/);
  if (match) {
    credXml = match[1].replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&amp;/g, '&');
  }
  
  if (!credXml) throw new Error('WSAA: Could not find loginCmsReturn: ' + response.substring(0, 500));
  
  // Extract token and sign using regex (more robust than XML parsing)
  const tokenMatch = credXml.match(/<token>([\s\S]*?)<\/token>/);
  const signMatch = credXml.match(/<sign>([\s\S]*?)<\/sign>/);
  const expiryMatch = credXml.match(/<expirationTime>([\s\S]*?)<\/expirationTime>/);
  
  if (!tokenMatch || !signMatch) throw new Error('WSAA: No credentials in response: ' + credXml.substring(0, 300));
  
  const result = {
    token: tokenMatch[1].trim(),
    sign: signMatch[1].trim(),
    cuit: entity.cuit,
    expiry: expiryMatch ? new Date(expiryMatch[1].trim()).getTime() - 60000 : Date.now() + 36000000
  };
  tokenCache[cacheKey] = result;
  console.log(`[WSAA] Token obtained for ${entity.name}, expires in ~12h`);
  return result;
}
 
// ── WSFEv1: Get last invoice number ──
async function getLastInvoiceNum(entityId, puntoVenta, tipoComprobante) {
  const auth = await getToken(entityId);
  
  const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ar="http://ar.gov.afip.dif.FEV1/">
  <soapenv:Body>
    <ar:FECompUltimoAutorizado>
      <ar:Auth>
        <ar:Token>${auth.token}</ar:Token>
        <ar:Sign>${auth.sign}</ar:Sign>
        <ar:Cuit>${auth.cuit}</ar:Cuit>
      </ar:Auth>
      <ar:PtoVta>${puntoVenta}</ar:PtoVta>
      <ar:CbteTipo>${tipoComprobante}</ar:CbteTipo>
    </ar:FECompUltimoAutorizado>
  </soapenv:Body>
</soapenv:Envelope>`;
 
  const response = await soapRequest(WSFE_URL, soapBody, 'http://ar.gov.afip.dif.FEV1/FECompUltimoAutorizado');
  const match = response.match(/<CbteNro>([\d]+)<\/CbteNro>/);
  return match ? parseInt(match[1]) : 0;
}
 
// ── WSFEv1: Create invoice (FECAESolicitar) ──
async function createInvoice(entityId, invoiceData) {
  const authData = await getToken(entityId);
  const { puntoVenta, tipoComprobante, concepto, docTipo, docNro, importeTotal, importeNeto, importeIva, items } = invoiceData;
  
  // Get last number
  const lastNum = await getLastInvoiceNum(entityId, puntoVenta, tipoComprobante);
  const nextNum = lastNum + 1;
  
  const today = new Date().toISOString().split('T')[0].replace(/-/g, '');
  
  // Build IVA array if needed
  let ivaXml = '';
  if (importeIva > 0) {
    ivaXml = `<ar:Iva>
        <ar:AlicIva>
          <ar:Id>5</ar:Id>
          <ar:BaseImp>${importeNeto.toFixed(2)}</ar:BaseImp>
          <ar:Importe>${importeIva.toFixed(2)}</ar:Importe>
        </ar:AlicIva>
      </ar:Iva>`;
  }
  
  const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ar="http://ar.gov.afip.dif.FEV1/">
  <soapenv:Body>
    <ar:FECAESolicitar>
      <ar:Auth>
        <ar:Token>${authData.token}</ar:Token>
        <ar:Sign>${authData.sign}</ar:Sign>
        <ar:Cuit>${authData.cuit}</ar:Cuit>
      </ar:Auth>
      <ar:FeCAEReq>
        <ar:FeCabReq>
          <ar:CantReg>1</ar:CantReg>
          <ar:PtoVta>${puntoVenta}</ar:PtoVta>
          <ar:CbteTipo>${tipoComprobante}</ar:CbteTipo>
        </ar:FeCabReq>
        <ar:FeDetReq>
          <ar:FECAEDetRequest>
            <ar:Concepto>${concepto || 1}</ar:Concepto>
            <ar:DocTipo>${docTipo}</ar:DocTipo>
            <ar:DocNro>${docNro}</ar:DocNro>
            <ar:CbteDesde>${nextNum}</ar:CbteDesde>
            <ar:CbteHasta>${nextNum}</ar:CbteHasta>
            <ar:CbteFch>${today}</ar:CbteFch>
            <ar:ImpTotal>${importeTotal.toFixed(2)}</ar:ImpTotal>
            <ar:ImpTotConc>0.00</ar:ImpTotConc>
            <ar:ImpNeto>${importeNeto.toFixed(2)}</ar:ImpNeto>
            <ar:ImpOpEx>0.00</ar:ImpOpEx>
            <ar:ImpTrib>0.00</ar:ImpTrib>
            <ar:ImpIVA>${(importeIva || 0).toFixed(2)}</ar:ImpIVA>
            <ar:MonId>PES</ar:MonId>
            <ar:MonCotiz>1</ar:MonCotiz>
            ${ivaXml}
          </ar:FECAEDetRequest>
        </ar:FeDetReq>
      </ar:FeCAEReq>
    </ar:FECAESolicitar>
  </soapenv:Body>
</soapenv:Envelope>`;
 
  console.log(`[WSFEv1] Creating invoice: PV=${puntoVenta} Tipo=${tipoComprobante} Nro=${nextNum} Total=${importeTotal}`);
  
  const response = await soapRequest(WSFE_URL, soapBody, 'http://ar.gov.afip.dif.FEV1/FECAESolicitar');
  
  // Parse response
  const caeMatch = response.match(/<CAE>([\d]+)<\/CAE>/);
  const vtoMatch = response.match(/<CAEFchVto>([\d]+)<\/CAEFchVto>/);
  const resultMatch = response.match(/<Resultado>(\w+)<\/Resultado>/);
  const errMatch = response.match(/<Err>.*?<Code>(\d+)<\/Code>.*?<Msg>(.*?)<\/Msg>/s);
  
  if (resultMatch && resultMatch[1] === 'A' && caeMatch) {
    return {
      success: true,
      cae: caeMatch[1],
      caeVto: vtoMatch ? vtoMatch[1] : '',
      cbteNro: nextNum,
      cbteTipo: tipoComprobante,
      puntoVenta: puntoVenta,
      resultado: 'A'
    };
  } else {
    return {
      success: false,
      error: errMatch ? `${errMatch[1]}: ${errMatch[2]}` : 'Error desconocido',
      rawResponse: response.substring(0, 1000)
    };
  }
}
 
// ═══════════ API ROUTES ═══════════
 
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok',
    version: 'v3', 
    env: IS_PRODUCTION ? 'production' : 'homologacion',
    wsaaUrl: WSAA_URL,
    wsfeUrl: WSFE_URL,
    entities: {
      '1': { name: ENTITIES['1'].name, cuit: ENTITIES['1'].cuit, hasCert: !!ENTITIES['1'].cert },
      '2': { name: ENTITIES['2'].name, cuit: ENTITIES['2'].cuit, hasCert: !!ENTITIES['2'].cert },
    }
  });
});
 
// Get auth token (test connectivity)
app.post('/api/auth', auth, async (req, res) => {
  try {
    const { entityId } = req.body;
    const token = await getToken(entityId || '1');
    res.json({ success: true, message: 'Autenticación exitosa', cuit: token.cuit });
  } catch (e) {
    console.error('[AUTH]', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});
 
// Get last invoice number
app.post('/api/ultimo-comprobante', auth, async (req, res) => {
  try {
    const { entityId, puntoVenta, tipoComprobante } = req.body;
    const num = await getLastInvoiceNum(entityId || '1', puntoVenta || 1, tipoComprobante || 1);
    res.json({ success: true, lastNumber: num });
  } catch (e) {
    console.error('[ULTIMO]', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});
 
// Create invoice
app.post('/api/facturar', auth, async (req, res) => {
  try {
    const { entityId, puntoVenta, tipoFactura, docTipo, docNro, importeTotal, importeNeto, importeIva, concepto, cliente, detalle } = req.body;
    
    // Map FC type to AFIP code
    // FC A = 1, FC B = 6, FC C = 11
    const tipoMap = { 'A': 1, 'B': 6, 'C': 11 };
    const tipoComprobante = tipoMap[tipoFactura] || 6;
    
    // DocTipo: 80=CUIT, 96=DNI, 99=Consumidor Final
    const result = await createInvoice(entityId || '1', {
      puntoVenta: parseInt(puntoVenta) || 1,
      tipoComprobante,
      concepto: concepto || 1, // 1=Productos, 2=Servicios, 3=Ambos
      docTipo: parseInt(docTipo) || 99,
      docNro: parseInt(docNro) || 0,
      importeTotal: parseFloat(importeTotal) || 0,
      importeNeto: parseFloat(importeNeto) || 0,
      importeIva: parseFloat(importeIva) || 0,
    });
    
    if (result.success) {
      console.log(`[FACTURA] ✅ CAE: ${result.cae} | Nro: ${result.cbteNro}`);
    } else {
      console.log(`[FACTURA] ❌ Error: ${result.error}`);
    }
    
    res.json(result);
  } catch (e) {
    console.error('[FACTURAR]', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});
 
// ═══════════ START ═══════════
app.listen(PORT, () => {
  console.log(`\n🧾 CarBoys ARCA Server`);
  console.log(`   Port: ${PORT}`);
  console.log(`   Env: ${IS_PRODUCTION ? '🔴 PRODUCCION' : '🟡 HOMOLOGACION (testing)'}`);
  console.log(`   Entity 1: ${ENTITIES['1'].name} (${ENTITIES['1'].cuit}) — Cert: ${ENTITIES['1'].cert ? '✅' : '❌'}`);
  console.log(`   Entity 2: ${ENTITIES['2'].name} (${ENTITIES['2'].cuit}) — Cert: ${ENTITIES['2'].cert ? '✅' : '❌'}`);
  console.log(`\n   Endpoints:`);
  console.log(`   GET  /api/health`);
  console.log(`   POST /api/auth`);
  console.log(`   POST /api/ultimo-comprobante`);
  console.log(`   POST /api/facturar\n`);
});
