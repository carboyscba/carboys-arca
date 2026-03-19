// ── PADRON: Consulta datos fiscales del contribuyente via AFIP ──
async function consultarPadron(cuit) {
  const cleanCuit = String(cuit).replace(/[^0-9]/g, '');
  if (!cleanCuit || cleanCuit.length < 7) throw new Error('CUIT/DNI inválido');
  
  const urls = [
    `https://soa.afip.gob.ar/sr-padron/v2/persona/${cleanCuit}`,
    `https://soa.afip.gob.ar/sr-padron/v1/persona/${cleanCuit}`,
  ];
  
  for (const url of urls) {
    try {
      const data = await new Promise((resolve, reject) => {
        const req = https.get(url, { rejectUnauthorized: false, timeout: 8000 }, (res) => {
          let body = '';
          res.on('data', chunk => body += chunk);
          res.on('end', () => {
            try { resolve(JSON.parse(body)); } catch(e) { reject(new Error('Invalid JSON')); }
          });
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
      });
      
      if (data.success !== false && (data.data || data.persona)) {
        const p = data.data || data.persona || {};
        const isTipoJuridica = p.tipoClave === 'CUIT' && p.tipoPersona === 'JURIDICA';
        return {
          success: true,
          cuit: cleanCuit,
          tipoPersona: p.tipoPersona || '',
          nombre: isTipoJuridica ? (p.razonSocial || '') : `${p.apellido || ''} ${p.nombre || ''}`.trim(),
          razonSocial: p.razonSocial || '',
          apellido: p.apellido || '',
          nombrePila: p.nombre || '',
          domicilioFiscal: p.domicilioFiscal ? `${p.domicilioFiscal.direccion || ''}, ${p.domicilioFiscal.localidad || ''}, ${p.domicilioFiscal.descripcionProvincia || ''}`.replace(/, ,/g, ',').replace(/^, |, $/g, '') : '',
          condIva: (() => {
            const imp = (p.impuestos || []).find(i => i.idImpuesto === 32);
            if (imp) return 'IVA Exento';
            const iva = (p.impuestos || []).find(i => i.idImpuesto === 30);
            if (iva) return 'Responsable Inscripto';
            const mt = (p.impuestos || []).find(i => i.idImpuesto === 20);
            if (mt) return 'Monotributo';
            return 'Consumidor Final';
          })(),
        };
      }
    } catch(e) {
      console.log(`[PADRON] ${url} failed:`, e.message);
    }
  }
  
  throw new Error('No se pudo consultar el padrón de AFIP para CUIT: ' + cleanCuit);
}

// Padron lookup
app.get('/api/padron', auth, async (req, res) => {
  try {
    const cuit = req.query.cuit;
    if (!cuit) return res.status(400).json({ success: false, error: 'Falta parámetro cuit' });
    const result = await consultarPadron(cuit);
    res.json(result);
  } catch(e) {
    console.error('[PADRON]', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});
