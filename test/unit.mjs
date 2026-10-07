// Pruebas unitarias de las funciones puras exportadas por server.js
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
process.env.ARCA_ENV = 'homologacion';
process.env.ENTITY1_CERT = 'eA=='; process.env.ENTITY1_KEY = 'eA==';   // sólo para que no se queje al cargar
const require = createRequire(import.meta.url);
const S = require(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'server.js'));
let pasadas = 0, falladas = 0;
const ok = (c, m, x) => { if (c) { pasadas++; console.log('  ✓', m); } else { falladas++; console.log('  ✗', m, x !== undefined ? JSON.stringify(x) : ''); } };
const eq = (a, b, m) => ok(JSON.stringify(a) === JSON.stringify(b), m, { got: a, want: b });

console.log('═══ Fechas en hora Argentina ═══');
// 2026-10-07 01:30 UTC = 2026-10-06 22:30 Argentina (UTC-3)
eq(S.fechaArgentinaYmd(new Date('2026-10-07T01:30:00Z')), '20261006', 'a la 1:30 UTC todavía es 6/10 en Argentina (antes salía 7/10)');
eq(S.fechaArgentinaYmd(new Date('2026-10-07T03:00:00Z')), '20261007', 'a las 3:00 UTC ya es 7/10 en Argentina');
eq(S.fechaArgentinaYmd(new Date('2026-10-07T02:59:59Z')), '20261006', 'un segundo antes de las 3:00 UTC sigue siendo 6/10');
eq(S.fechaArgentinaYmd(new Date('2026-01-01T02:00:00Z')), '20251231', 'cambio de año: 1/1 02:00 UTC es 31/12 en Argentina');
eq(S.ymdAIso('20261006'), '2026-10-06', 'ymdAIso');
eq(S.ymdAIso('2026-10-06'), '', 'ymdAIso rechaza lo que no sea 8 dígitos');
eq(S.aYmd('2026-10-06'), '20261006', 'aYmd acepta con guiones');
eq(S.aYmd(' 20261006 '), '20261006', 'aYmd recorta espacios');
eq(S.aYmd('06/10/2026'), '', 'aYmd rechaza dd/mm/aaaa');
eq(S.aYmd(undefined), '', 'aYmd undefined');

console.log('═══ minutosDesdeProceso ═══');
{
  const ahora = new Date('2026-10-06T15:00:00Z');   // 12:00 Argentina
  eq(S.minutosDesdeProceso('20261006115500', ahora), 5, 'autorizada a las 11:55 AR, ahora 12:00 AR → 5 min');
  eq(S.minutosDesdeProceso('20261006110000', ahora), 60, 'una hora antes → 60');
  eq(S.minutosDesdeProceso('20261005120000', ahora), 1440, 'un día antes → 1440');
  eq(S.minutosDesdeProceso('20261006120230', ahora), -2.5, 'reloj de ARCA adelantado 2,5 min → negativo (se tolera hasta -5)');
  eq(S.minutosDesdeProceso('', ahora), null, 'vacío → null (no se puede juzgar)');
  eq(S.minutosDesdeProceso('2026-10-06', ahora), null, 'formato raro → null');
}

console.log('═══ esElNuestro ═══');
{
  const d = { docNro: 20123456789, importeTotal: 121000 };
  const cons = { resultado: 'A', cae: '70000000000001', docNro: '20123456789', importeTotal: 121000, cbteFch: '20261006' };
  ok(S.esElNuestro(cons, d, '20261006') === true, 'coincide todo → es nuestro');
  ok(S.esElNuestro({ ...cons, importeTotal: 121000.01 }, d, '20261006') === true, 'diferencia de 1 centavo se tolera');
  ok(S.esElNuestro({ ...cons, importeTotal: 121001 }, d, '20261006') === false, 'importe distinto → no');
  ok(S.esElNuestro({ ...cons, docNro: '0' }, d, '20261006') === false, 'documento distinto → no');
  ok(S.esElNuestro({ ...cons, cbteFch: '20261005' }, d, '20261006') === false, 'fecha distinta → no');
  ok(S.esElNuestro({ ...cons, cbteFch: '' }, d, '20261006') === true, 'sin fecha informada → se compara el resto');
  ok(S.esElNuestro({ ...cons, resultado: 'R' }, d, '20261006') === false, 'rechazado → no');
  ok(S.esElNuestro({ ...cons, cae: '' }, d, '20261006') === false, 'sin CAE → no');
  ok(S.esElNuestro(null, d, '20261006') === false, 'null → no');
  ok(S.esElNuestro({ ...cons, docNro: '20-12345678-9' }, d, '20261006') === true, 'documento con guiones se normaliza');
}

console.log('═══ parseErrores / parseObs ═══');
{
  const xml = '<Errors><Err><Code>10016</Code><Msg>El numero no corresponde</Msg></Err><Err><Code>600</Code><Msg>Token invalido</Msg></Err></Errors><Observaciones><Obs><Code>10217</Code><Msg>Obs uno</Msg></Obs></Observaciones>';
  eq(S.parseErrores(xml), [{ codigo: 10016, mensaje: 'El numero no corresponde' }, { codigo: 600, mensaje: 'Token invalido' }], 'dos errores');
  eq(S.parseObs(xml), [{ codigo: 10217, mensaje: 'Obs uno' }], 'una observación (no confunde Err con Obs)');
  eq(S.parseErrores('<x/>'), [], 'sin errores → []');
  eq(S.parseErrores(''), [], 'vacío → []');
}

console.log('═══ validarComprobante (redondeos y bordes) ═══');
{
  const base = { entityId: '1', puntoVenta: 3, tipoFactura: 'B', docTipo: 99, docNro: 0, importeTotal: 121000, importeNeto: 100000, importeIva: 21000, concepto: 3, fchServDesde: '20261006', fchServHasta: '20261006', fchVtoPago: '20261006', condicionIVAReceptor: 5 };
  const v = (extra) => { try { return S.validarComprobante({ ...base, ...extra }); } catch (e) { return { error: e.message, validacion: e.validacion }; } };
  ok(!v({}).error, 'caso base válido');
  const r1 = v({ importeTotal: 1210.5, importeNeto: 1000.41, importeIva: 210.09 });
  ok(!r1.error && r1.importeNeto === 1000.41 && r1.importeIva === 210.09, 'centavos: 1000.41 + 210.09 = 1210.50', r1);
  const r2 = v({ importeTotal: 100, importeNeto: 82.64, importeIva: 17.36 });
  ok(!r2.error, '100 = 82.64 + 17.36 (IVA 17.35 teórico, tolerancia 5 centavos)', r2);
  const r3 = v({ importeTotal: 100, importeNeto: 82.65, importeIva: 17.35 });
  ok(!r3.error, '82.65 + 17.35 = 100, IVA 17.3565 teórico → dentro de tolerancia', r3);
  const r3b = v({ importeTotal: 100, importeNeto: 82.6, importeIva: 17.4 });
  ok(/21%/.test(r3b.error || ''), '82.60 + 17.40: IVA 17.346 teórico, se aparta 5,4 centavos → rechazado', r3b);
  const r4 = v({ importeTotal: 100, importeNeto: 82, importeIva: 18 });
  ok(/21%/.test(r4.error || ''), '82 + 18: el IVA (17.22 teórico) se aparta más de 5 centavos → rechazado', r4);
  const r5 = v({ importeTotal: '121000', importeNeto: '100000', importeIva: '21000', puntoVenta: '3', docTipo: '99', concepto: '3', condicionIVAReceptor: '5' });
  ok(!r5.error && r5.puntoVenta === 3 && r5.docTipo === 99 && r5.condicionIVAReceptor === 5, 'acepta números como texto y los convierte', r5);
  const r6 = v({ puntoVenta: 3.5 });
  ok(/Punto de venta/.test(r6.error || ''), 'punto de venta decimal → error');
  const r7 = v({ importeIva: 0, importeNeto: 121000 });
  ok(!r7.error && r7.importeIva === 0, 'B con IVA 0 (exento) pasa: neto = total', r7);
  const r8 = v({ tipoFactura: 'b' });
  ok(!r8.error && r8.letra === 'B' && r8.tipoComprobante === 6, 'letra en minúscula se acepta');
  const r9 = v({ entityId: 1 });
  ok(!r9.error && r9.entityId === '1', 'entityId numérico se acepta');
  const r10 = v({ docTipo: 80, docNro: '30-71745468-1', condicionIVAReceptor: 4 });
  ok(!r10.error && r10.docNro === 30717454681, 'B a exento con CUIT: documento 11 dígitos');
  const r11 = v({ docTipo: 80, docNro: '30-71745468-1', condicionIVAReceptor: 6 });
  ok(!r11.error, 'B a monotributista permitida');
  const r12 = v({ docTipo: 99, docNro: '', importeTotal: 0.01, importeNeto: 0.01, importeIva: 0 });
  ok(!r12.error, 'total mínimo 0.01 pasa');
  const r13 = v({ importeTotal: -5 });
  ok(/mayor a cero/.test(r13.error || ''), 'total negativo → error');
  const r14 = v({ importeTotal: 'abc' });
  ok(/mayor a cero/.test(r14.error || ''), 'total no numérico → error');
  const nc = (() => { try { return S.validarComprobante({ ...base, facturaOriginal: { tipo: 'B', ptoVta: '3', nro: '122', fecha: '2026-10-06' } }, { esNC: true }); } catch (e) { return { error: e.message }; } })();
  ok(!nc.error && nc.tipoComprobante === 8 && nc.cbtesAsoc && nc.cbtesAsoc.tipo === 6 && nc.cbtesAsoc.nro === 122 && nc.cbtesAsoc.fch === '20261006' && nc.cbtesAsoc.cuit === '30717454681', 'NC: asociado completo con CUIT emisor', nc);
  const ncC = (() => { try { return S.validarComprobante({ ...base, entityId: '2', tipoFactura: 'C', facturaOriginal: { tipo: 'C', ptoVta: 2, nro: 5, fecha: '20261001' } }, { esNC: true }); } catch (e) { return { error: e.message }; } })();
  ok(!ncC.error && ncC.tipoComprobante === 13 && ncC.cbtesAsoc.cuit === '20344412171' && ncC.importeIva === 0, 'NC C de la entidad 2: tipo 13, CUIT entidad 2, sin IVA', ncC);
  ok(v({ condicionIVAReceptor: 5 }).validacion === undefined, 'resultado válido no trae marca de validación');
  ok(v({ entityId: '' }).validacion === true, 'los errores llevan la marca validacion=true (→ HTTP 400)');
}

console.log('═══ extractPadronData ═══');
{
  const CI = 'ws_sr_constancia_inscripcion', A13 = 'ws_sr_padron_a13';
  // Constancia de inscripción (A5): trae impuestos
  const fis = '<persona><tipoPersona>FISICA</tipoPersona><apellido>PEREZ</apellido><nombre>JUAN</nombre><domicilio><direccion>CALLE 1</direccion><localidad>CORDOBA</localidad><codPostal>5000</codPostal></domicilio><impuesto><idImpuesto>20</idImpuesto></impuesto></persona>';
  const r = S.extractPadronData(fis, '20123456789', CI);
  ok(r.nombre === 'PEREZ JUAN' && r.condIva === 'Monotributo' && r.condIvaId === 6 && r.condIvaDeterminada === true && r.domicilioFiscal === 'CALLE 1, CORDOBA, CP 5000', 'constancia: persona física monotributista', r);
  const ex = S.extractPadronData(fis.replace('<idImpuesto>20</idImpuesto>', '<idImpuesto>32</idImpuesto>'), '20123456789', CI);
  ok(ex.condIva === 'IVA Exento' && ex.condIvaId === 4, 'constancia: exento → 4');
  const cf = S.extractPadronData(fis.replace('<impuesto><idImpuesto>20</idImpuesto></impuesto>', ''), '20123456789', CI);
  ok(cf.condIva === 'Consumidor Final' && cf.condIvaId === 5 && cf.condIvaDeterminada === true, 'constancia: persona física sin impuestos → consumidor final 5');
  const ri = S.extractPadronData(fis.replace('<idImpuesto>20</idImpuesto>', '<idImpuesto>30</idImpuesto>'), '20123456789', CI);
  ok(ri.condIva === 'Responsable Inscripto' && ri.condIvaId === 1, 'constancia: IVA 30 → RI 1');
  // Constancia v2 real: el monotributo viene en <datosMonotributo> (con o sin idImpuesto 20)
  const monoV2 = '<personaReturn><datosGenerales><tipoPersona>FISICA</tipoPersona><apellido>GOMEZ</apellido><nombre>ANA</nombre></datosGenerales><datosMonotributo><categoriaMonotributo><descripcionCategoria>B</descripcionCategoria></categoriaMonotributo></datosMonotributo></personaReturn>';
  const m2 = S.extractPadronData(monoV2, '27123456789', CI);
  ok(m2.condIvaId === 6, 'constancia v2: <datosMonotributo> → Monotributo', m2);
  // Empresa RI: lo normal (impuesto 30 dentro de datosRegimenGeneral)
  const empRI = '<personaReturn><datosGenerales><tipoPersona>JURIDICA</tipoPersona><razonSocial>RDA RENTING S.A.</razonSocial></datosGenerales><datosRegimenGeneral><impuesto><idImpuesto>30</idImpuesto><descripcionImpuesto>IVA</descripcionImpuesto></impuesto><impuesto><idImpuesto>10</idImpuesto></impuesto></datosRegimenGeneral></personaReturn>';
  const e1 = S.extractPadronData(empRI, '30123456789', CI);
  ok(e1.nombre === 'RDA RENTING S.A.' && e1.condIvaId === 1 && e1.condIva === 'Responsable Inscripto', 'constancia: empresa con IVA 30 → RI (Factura A)', e1);
  // Empresa SIN impuesto de IVA en la constancia: nunca "consumidor final"
  const empSin = empRI.replace('<impuesto><idImpuesto>30</idImpuesto><descripcionImpuesto>IVA</descripcionImpuesto></impuesto>', '');
  const e2 = S.extractPadronData(empSin, '30123456789', CI);
  ok(e2.condIvaId === 0 && e2.condIva === 'No determinada' && e2.condIvaDeterminada === false, 'constancia: empresa sin IVA → "No determinada", nunca consumidor final', e2);
  // Padrón A13: NO trae impuestos → la condición no se inventa
  const a13 = '<persona><tipoPersona>JURIDICA</tipoPersona><razonSocial>RDA RENTING S.A.</razonSocial><domicilio><direccion>AV 1</direccion><localidad>CORDOBA</localidad></domicilio></persona>';
  const r13 = S.extractPadronData(a13, '30123456789', A13);
  ok(r13.nombre === 'RDA RENTING S.A.' && r13.condIvaId === 0 && r13.condIva === 'No determinada' && r13.condIvaDeterminada === false, 'A13 (sin impuestos): nombre sí, condición "No determinada" (antes salía Consumidor Final)', r13);
  const f13 = S.extractPadronData('<persona><tipoPersona>FISICA</tipoPersona><apellido>PEREZ</apellido><nombre>JUAN</nombre></persona>', '20123456789', A13);
  ok(f13.condIvaId === 0, 'A13 persona física: tampoco se asume consumidor final', f13);
  const a13con = S.extractPadronData(a13.replace('</persona>', '<impuesto><idImpuesto>30</idImpuesto></impuesto></persona>'), '30123456789', A13);
  ok(a13con.condIvaId === 1, 'si A13 algún día trae impuestos, se usan', a13con);
  let lanzo = false; try { S.extractPadronData('<persona/>', '1', CI); } catch (e) { lanzo = true; }
  ok(lanzo, 'sin datos → lanza');
}
console.log(`\n══════ UNITARIAS: ${pasadas} pasadas, ${falladas} falladas ══════`);
process.exit(falladas ? 1 : 0);
