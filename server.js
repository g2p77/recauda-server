/**
 * RECAUDA — servidor propio (Node.js puro, sin dependencias externas)
 * ---------------------------------------------------------------
 * Sirve la app web (carpeta /public) y una API REST en /api/*.
 * Guarda todo en data/db.json (sin necesidad de instalar una base de datos).
 *
 * Uso:
 *   node server.js
 *
 * Variables de entorno opcionales:
 *   PORT=3000            Puerto donde escucha el servidor
 *
 * Usuario administrador por defecto la primera vez que se ejecuta:
 *   Usuario: Administrador
 *   PIN:     1234
 *   (cámbialo apenas entres, desde "Más -> Equipo")
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

// web-push es la única dependencia externa: hace posible enviar notificaciones
// aunque el celular tenga la app cerrada. Se carga de forma segura: si por
// alguna razón no está instalada, el resto de la app sigue funcionando normal
// y las notificaciones simplemente quedan desactivadas.
let webpush = null;
try { webpush = require('web-push'); }
catch(e){ console.warn('[ZaJu Tech] "web-push" no está instalado todavía (ejecuta "npm install"). Las notificaciones programadas quedarán desactivadas hasta entonces; el resto de la app funciona con normalidad.'); }

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const SECRET_FILE = path.join(DATA_DIR, 'secret.txt');
const VAPID_FILE = path.join(DATA_DIR, 'vapid.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
const TOKEN_TTL_MS = 30 * 24 * 3600 * 1000; // 30 días

// Notificaciones diarias de "clientes pendientes por pagar"
const NOTIFY_TIMES = [{ h: 12, m: 0 }, { h: 16, m: 0 }]; // 12:00 m. y 4:00 p.m.
const NOTIFY_TIMEZONE = 'America/Bogota'; // cámbialo aquí si tu negocio está en otro país/huso horario

if(!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

/* ---------------------------------------------------------------
   Secreto de firma de tokens (se genera una sola vez por instalación)
   --------------------------------------------------------------- */
let SECRET;
if(fs.existsSync(SECRET_FILE)){
  SECRET = fs.readFileSync(SECRET_FILE, 'utf8').trim();
} else {
  SECRET = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(SECRET_FILE, SECRET);
}

/* ---------------------------------------------------------------
   Claves VAPID para notificaciones push (se generan una sola vez)
   --------------------------------------------------------------- */
let VAPID = null;
function loadVapid(){
  if(fs.existsSync(VAPID_FILE)){
    try { VAPID = JSON.parse(fs.readFileSync(VAPID_FILE, 'utf8')); } catch(e){ VAPID = null; }
  }
  if(!VAPID && webpush){
    const keys = webpush.generateVAPIDKeys();
    VAPID = { publicKey: keys.publicKey, privateKey: keys.privateKey };
    fs.writeFileSync(VAPID_FILE, JSON.stringify(VAPID));
  }
  if(webpush && VAPID){
    webpush.setVapidDetails('mailto:soporte@example.com', VAPID.publicKey, VAPID.privateKey);
  }
}
loadVapid();

/* ---------------------------------------------------------------
   Base de datos en archivo JSON
   --------------------------------------------------------------- */
function uid(prefix){ return prefix + '_' + crypto.randomBytes(6).toString('hex'); }
function todayISO(){ return new Date().toISOString().slice(0,10); }

function seedDB(){
  const salt = crypto.randomBytes(16).toString('hex');
  return {
    negocio: { nombre: 'Mi Negocio de Cobranza', moneda: 'COP', logo: 'R', plan: 'premium', recordatorios: false, zonas: [] },
    usuarios: [
      { id: 'u1', nombre: 'Administrador', rol: 'admin', pinSalt: salt, pinHash: hashPin('1234', salt) }
    ],
    clientes: [],
    prestamos: [],
    cobros: [],
    visitas: [],
    gastos: [],
    ubicaciones: {},
    pushSubs: {}
  };
}

let DB;
function loadDB(){
  if(fs.existsSync(DB_FILE)){
    DB = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } else {
    DB = seedDB();
    saveDB();
    console.log('Base de datos creada. Usuario: Administrador / PIN: 1234 (cámbialo pronto).');
  }
  // compatibilidad con instalaciones ya existentes (agrega lo que falte sin borrar nada)
  if(!DB.pushSubs) DB.pushSubs = {};
  if(!DB.visitas) DB.visitas = [];
  if(!DB.gastos) DB.gastos = [];
  if(!DB.ubicaciones) DB.ubicaciones = {};
  if(!DB.negocio.zonas) DB.negocio.zonas = [];
}
function saveDB(){
  fs.writeFileSync(DB_FILE, JSON.stringify(DB, null, 2));
}
loadDB();

/* ---------------------------------------------------------------
   Utilidades de seguridad
   --------------------------------------------------------------- */
function hashPin(pin, salt){
  return crypto.scryptSync(String(pin), salt, 64).toString('hex');
}
function signToken(payloadObj){
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  return payload + '.' + sig;
}
function verifyToken(token){
  if(!token) return null;
  const parts = token.split('.');
  if(parts.length !== 2) return null;
  const [payload, sig] = parts;
  const expected = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if(a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let data;
  try { data = JSON.parse(Buffer.from(payload, 'base64url').toString()); } catch(e){ return null; }
  if(!data.exp || Date.now() > data.exp) return null;
  return data;
}

// Límite simple de intentos de login por IP
const loginAttempts = new Map();
function tooManyAttempts(ip){
  const rec = loginAttempts.get(ip);
  if(!rec) return false;
  if(Date.now() > rec.resetAt){ loginAttempts.delete(ip); return false; }
  return rec.count >= 20;
}
function registerAttempt(ip){
  const rec = loginAttempts.get(ip);
  if(!rec || Date.now() > rec.resetAt){
    loginAttempts.set(ip, { count: 1, resetAt: Date.now() + 15*60*1000 });
  } else {
    rec.count++;
  }
}

/* ---------------------------------------------------------------
   Cálculo de préstamos (misma lógica que la app: tasa mensual,
   prorrateada según frecuencia de cobro)
   --------------------------------------------------------------- */
const PERIOD_DAYS = { diario: 1, semanal: 7, quincenal: 15, mensual: 30 };
// Reparte el total en cuotas redondeadas a múltiplos de mil (más fáciles de cobrar en
// efectivo); la última cuota absorbe el residuo del redondeo para que la suma cuadre
// exacta con el total. Puede quedar más grande o más chica que las demás.
function construirCuotas(total, numCuotas){
  if(numCuotas <= 1) return { total, cuota: total, cuotaFinal: total };
  let cuota = Math.max(1000, Math.round((total/numCuotas)/1000)*1000);
  let cuotaFinal = total - cuota*(numCuotas-1);
  if(cuotaFinal <= 0){
    // Préstamo muy pequeño para el número de cuotas: no alcanza a redondear a miles
    // sin quedar en negativo, se reparte exacto sin redondear.
    cuota = Math.round(total/numCuotas);
    cuotaFinal = total - cuota*(numCuotas-1);
  }
  return { total, cuota, cuotaFinal };
}
function calcularPrestamo(monto, tasaMensualPct, numCuotas, modo, frecuencia){
  const dias = PERIOD_DAYS[frecuencia] || 1;
  const r = (tasaMensualPct/100) * (dias/30);
  let total;
  if(modo === 'fijo'){
    total = monto * (1 + r*numCuotas);
  } else if(modo === 'recalculado'){
    if(r === 0){ total = monto; }
    else { const cuotaExacta = monto*r/(1-Math.pow(1+r,-numCuotas)); total = cuotaExacta*numCuotas; }
  } else {
    total = monto * Math.pow(1+r, numCuotas);
  }
  return construirCuotas(Math.round(total), numCuotas);
}
// Cuenta los domingos entre dos fechas (sin contar el propio día de "desde"): los domingos
// no se cobran a menos que el cliente pague voluntariamente, así que no deben sumar mora.
function contarDomingosEntre(desde, hasta){
  let count = 0;
  const d = new Date(desde);
  d.setHours(0,0,0,0);
  d.setDate(d.getDate()+1);
  const fin = new Date(hasta);
  fin.setHours(0,0,0,0);
  while(d <= fin){
    if(d.getDay() === 0) count++;
    d.setDate(d.getDate()+1);
  }
  return count;
}
function diasEnMora(prestamo){
  const cobrosPrestamo = DB.cobros.filter(c=>c.prestamoId===prestamo.id).sort((a,b)=>b.fecha.localeCompare(a.fecha));
  const ultima = cobrosPrestamo[0] ? new Date(cobrosPrestamo[0].fecha) : new Date(prestamo.fechaInicio);
  const ahora = new Date();
  const diasCiclo = PERIOD_DAYS[prestamo.frecuencia] || 1;
  const dias = Math.floor((ahora.getTime() - ultima.getTime())/(1000*3600*24));
  const domingos = contarDomingosEntre(ultima, ahora);
  return Math.max(0, dias - domingos - diasCiclo);
}

// Normaliza fotos enviadas desde el cliente: acepta el campo singular (compatibilidad con
// versiones viejas de la app) o el nuevo campo plural (varias fotos), y siempre guarda ambos.
function normalizePhotos(body, singular, plural){
  const arr = Array.isArray(body[plural]) ? body[plural].filter(Boolean) : (body[singular] ? [body[singular]] : []);
  return { [singular]: arr[0] || null, [plural]: arr };
}

/* ---------------------------------------------------------------
   Helpers HTTP
   --------------------------------------------------------------- */
function send(res, status, data){
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS'
  });
  res.end(body);
}
function readBody(req){
  return new Promise((resolve, reject)=>{
    let chunks = [];
    let size = 0;
    let rejected = false;
    req.on('data', c=>{
      if(rejected) return;
      size += c.length;
      if(size > 10*1024*1024){
        rejected = true;
        const err = new Error('El archivo o los datos enviados son demasiado grandes (máximo 10MB)');
        err.tooLarge = true;
        reject(err);
        return;
      }
      chunks.push(c);
    });
    req.on('end', ()=>{
      if(rejected) return;
      if(!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch(e){ reject(new Error('JSON inválido')); }
    });
    req.on('error', reject);
  });
}
function getAuth(req){
  const h = req.headers['authorization'] || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  const data = verifyToken(token);
  if(!data) return null;
  const user = DB.usuarios.find(u=>u.id===data.uid);
  if(!user) return null;
  return { id: user.id, nombre: user.nombre, rol: user.rol };
}
function publicUser(u){ return { id: u.id, nombre: u.nombre, rol: u.rol, tienePin: !!u.pinHash }; }

function clientesVisibles(user){
  if(user.rol === 'admin') return DB.clientes;
  return DB.clientes.filter(c => c.cobradorId === user.id);
}
function prestamosVisibles(user){
  const ids = new Set(clientesVisibles(user).map(c=>c.id));
  return DB.prestamos.filter(p => ids.has(p.clienteId));
}
function cobrosVisibles(user){
  const ids = new Set(clientesVisibles(user).map(c=>c.id));
  return DB.cobros.filter(c => ids.has(c.clienteId));
}
function visitasVisibles(user){
  if(user.rol === 'admin') return DB.visitas;
  return DB.visitas.filter(v => v.cobradorId === user.id);
}
function gastosVisibles(user){
  if(user.rol === 'admin') return DB.gastos;
  return DB.gastos.filter(g => g.cobradorId === user.id);
}
function stateFor(user){
  return {
    negocio: DB.negocio,
    usuarios: DB.usuarios.map(publicUser),
    clientes: clientesVisibles(user),
    prestamos: prestamosVisibles(user),
    cobros: cobrosVisibles(user),
    visitas: visitasVisibles(user),
    gastos: gastosVisibles(user),
    yo: user
  };
}

/* ---------------------------------------------------------------
   Servidor de archivos estáticos (la app)
   --------------------------------------------------------------- */
const MIME = { '.html':'text/html; charset=utf-8', '.js':'text/javascript', '.css':'text/css', '.json':'application/json', '.svg':'image/svg+xml', '.png':'image/png' };
function serveStatic(req, res, pathname){
  let file = pathname === '/' ? '/index.html' : pathname;
  const filePath = path.join(PUBLIC_DIR, file);
  if(!filePath.startsWith(PUBLIC_DIR)){ res.writeHead(403); return res.end('Prohibido'); }
  fs.readFile(filePath, (err, content)=>{
    if(err){
      fs.readFile(path.join(PUBLIC_DIR, 'index.html'), (err2, indexContent)=>{
        if(err2){ res.writeHead(404); return res.end('No encontrado'); }
        res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'});
        res.end(indexContent);
      });
      return;
    }
    const ext = path.extname(filePath);
    res.writeHead(200, {'Content-Type': MIME[ext] || 'application/octet-stream'});
    res.end(content);
  });
}

/* ---------------------------------------------------------------
   Rutas de la API
   --------------------------------------------------------------- */
async function api(req, res, pathname, method){
  // Público: marca del negocio para la pantalla de inicio de sesión
  if(pathname === '/api/branding' && method === 'GET'){
    return send(res, 200, { nombre: DB.negocio.nombre, logo: DB.negocio.logo });
  }

  // Público: lista de perfiles para la pantalla de inicio de sesión
  if(pathname === '/api/team' && method === 'GET'){
    return send(res, 200, DB.usuarios.map(publicUser));
  }

  // Público: llave pública para poder suscribirse a notificaciones
  if(pathname === '/api/push/vapid-public-key' && method === 'GET'){
    if(!VAPID) return send(res, 503, { error: 'Las notificaciones no están disponibles en este servidor todavía' });
    return send(res, 200, { publicKey: VAPID.publicKey });
  }

  if(pathname === '/api/login' && method === 'POST'){
    const ip = req.socket.remoteAddress || 'ip';
    if(tooManyAttempts(ip)) return send(res, 429, { error: 'Demasiados intentos. Espera unos minutos.' });
    const body = await readBody(req);
    const user = DB.usuarios.find(u=>u.id === body.userId);
    if(!user){ registerAttempt(ip); return send(res, 401, { error: 'Usuario no encontrado' }); }
    if(user.pinHash){
      const attemptHash = hashPin(body.pin || '', user.pinSalt);
      const ok = attemptHash.length===user.pinHash.length && crypto.timingSafeEqual(Buffer.from(attemptHash), Buffer.from(user.pinHash));
      if(!ok){ registerAttempt(ip); return send(res, 401, { error: 'PIN incorrecto' }); }
    }
    const token = signToken({ uid: user.id, exp: Date.now() + TOKEN_TTL_MS });
    return send(res, 200, { token, user: publicUser(user) });
  }

  // A partir de aquí, todo requiere sesión
  const me = getAuth(req);
  if(!me) return send(res, 401, { error: 'Sesión inválida o expirada' });

  if(pathname === '/api/push/subscribe' && method === 'POST'){
    if(!webpush) return send(res, 503, { error: 'Las notificaciones no están disponibles en este servidor todavía' });
    const body = await readBody(req);
    if(!body.subscription || !body.subscription.endpoint) return send(res, 400, { error: 'Falta la suscripción' });
    if(!DB.pushSubs[me.id]) DB.pushSubs[me.id] = [];
    DB.pushSubs[me.id] = DB.pushSubs[me.id].filter(s=>s.endpoint !== body.subscription.endpoint);
    DB.pushSubs[me.id].push(body.subscription);
    saveDB();
    return send(res, 200, { ok: true });
  }

  if(pathname === '/api/push/unsubscribe' && method === 'POST'){
    const body = await readBody(req);
    if(DB.pushSubs[me.id]){
      DB.pushSubs[me.id] = DB.pushSubs[me.id].filter(s=>s.endpoint !== body.endpoint);
      saveDB();
    }
    return send(res, 200, { ok: true });
  }

  if(pathname === '/api/state' && method === 'GET'){
    return send(res, 200, stateFor(me));
  }

  if(pathname === '/api/usuarios' && method === 'POST'){
    if(me.rol !== 'admin') return send(res, 403, { error: 'Solo un administrador puede agregar cobradores' });
    const body = await readBody(req);
    if(!body.nombre) return send(res, 400, { error: 'Falta el nombre' });
    const salt = crypto.randomBytes(16).toString('hex');
    const nuevo = {
      id: uid('u'), nombre: String(body.nombre).trim(), rol: body.rol === 'admin' ? 'admin' : 'cobrador',
      pinSalt: salt, pinHash: body.pin ? hashPin(body.pin, salt) : null
    };
    DB.usuarios.push(nuevo); saveDB();
    return send(res, 200, { usuarios: DB.usuarios.map(publicUser) });
  }

  if(pathname.startsWith('/api/usuarios/') && method === 'PUT'){
    const id = pathname.split('/')[3];
    const usuario = DB.usuarios.find(u=>u.id===id);
    if(!usuario) return send(res, 404, { error: 'Usuario no encontrado' });
    if(me.rol !== 'admin' && me.id !== id) return send(res, 403, { error: 'Solo puedes cambiar tu propio PIN' });
    const body = await readBody(req);
    if(body.nombre && me.rol === 'admin') usuario.nombre = String(body.nombre).trim();
    if(typeof body.pin === 'string'){
      if(body.pin && body.pin.length < 4) return send(res, 400, { error: 'El PIN debe tener al menos 4 dígitos' });
      const salt = crypto.randomBytes(16).toString('hex');
      usuario.pinSalt = salt;
      usuario.pinHash = body.pin ? hashPin(body.pin, salt) : null;
    }
    saveDB();
    return send(res, 200, { usuarios: DB.usuarios.map(publicUser) });
  }

  if(pathname.startsWith('/api/usuarios/') && method === 'DELETE'){
    if(me.rol !== 'admin') return send(res, 403, { error: 'Solo un administrador puede eliminar cobradores' });
    const id = pathname.split('/')[3];
    if(id === me.id) return send(res, 400, { error: 'No puedes eliminar tu propio usuario mientras tienes la sesión abierta' });
    const usuario = DB.usuarios.find(u=>u.id===id);
    if(!usuario) return send(res, 404, { error: 'Usuario no encontrado' });
    if(usuario.rol === 'admin' && DB.usuarios.filter(u=>u.rol==='admin').length <= 1){
      return send(res, 400, { error: 'Debe quedar al menos un administrador' });
    }
    DB.usuarios = DB.usuarios.filter(u=>u.id!==id);
    // sus clientes no se eliminan: quedan reasignados a quien borra el cobrador
    DB.clientes.forEach(c=>{ if(c.cobradorId === id) c.cobradorId = me.id; });
    delete DB.ubicaciones[id];
    delete DB.pushSubs[id];
    saveDB();
    return send(res, 200, { usuarios: DB.usuarios.map(publicUser) });
  }

  if(pathname === '/api/clientes' && method === 'POST'){
    const body = await readBody(req);
    if(!body.nombre) return send(res, 400, { error: 'Falta el nombre del cliente' });
    const cliente = {
      id: uid('cl'), nombre: String(body.nombre).trim(),
      cedula: body.cedula ? String(body.cedula).trim() : '',
      telefono: body.telefono || '', direccion: body.direccion || '', zona: body.zona || '',
      cobradorId: body.cobradorId || me.id
    };
    DB.clientes.push(cliente); saveDB();
    return send(res, 200, { cliente });
  }

  // Importación masiva de clientes que el negocio ya tenía antes de usar Recauda
  // (desde una plantilla CSV). Agrega clientes nuevos y, si traen datos de préstamo,
  // su préstamo activo actual — nunca borra ni reemplaza lo que ya existe.
  if(pathname === '/api/clientes/importar' && method === 'POST'){
    if(me.rol !== 'admin') return send(res, 403, { error: 'Solo un administrador puede importar clientes' });
    const body = await readBody(req);
    const filas = Array.isArray(body.filas) ? body.filas : [];
    const zonas = new Set(DB.negocio.zonas || []);
    const FRECUENCIAS = ['diario', 'semanal', 'quincenal', 'mensual'];
    const resultados = filas.map((fila, idx) => {
      const numFila = idx + 2; // la fila 1 del CSV es el encabezado
      const nombre = String(fila.nombre || '').trim();
      if (!nombre) return { fila: numFila, ok: false, error: 'Falta el nombre' };

      let cobradorId = me.id;
      const nombreCobrador = String(fila.cobrador || '').trim();
      if (nombreCobrador) {
        const encontrado = DB.usuarios.find(u => u.nombre.toLowerCase() === nombreCobrador.toLowerCase());
        if (encontrado) cobradorId = encontrado.id;
      }

      const zona = String(fila.zona || '').trim();
      const cliente = {
        id: uid('cl'), nombre,
        cedula: String(fila.cedula || '').trim(),
        telefono: String(fila.telefono || '').trim(),
        direccion: String(fila.direccion || '').trim(),
        zona, cobradorId
      };
      if (zona) zonas.add(zona);
      DB.clientes.push(cliente);

      const monto = Number(fila.monto) || 0;
      const total = Number(fila.total) || 0;
      const cuota = Number(fila.cuota) || 0;
      const numCuotas = Number(fila.numCuotas) || 0;
      let prestamoCreado = false;
      if (monto > 0 && total > 0 && cuota > 0 && numCuotas > 0) {
        const saldoIngresado = Number(fila.saldo);
        const saldo = Math.min(Number.isFinite(saldoIngresado) && saldoIngresado >= 0 ? saldoIngresado : total, total);
        const frecuencia = FRECUENCIAS.includes(String(fila.frecuencia || '').toLowerCase()) ? String(fila.frecuencia).toLowerCase() : 'diario';
        const cuotaFinal = numCuotas > 1 ? Math.max(0, total - cuota * (numCuotas - 1)) : total;
        DB.prestamos.push({
          id: uid('p'), clienteId: cliente.id, monto, tasa: 0, modoInteres: 'fijo', frecuencia,
          numCuotas, cuota, cuotaFinal, total, saldo,
          cuotasPagadas: Math.min(numCuotas, Math.round((total - saldo) / cuota)),
          fechaInicio: fila.fechaInicio || todayISO(), estado: 'activo',
          entregadoPor: me.id, tarjetaFirma: null, fotosTarjeta: [],
          esPrenda: false, prendaDescripcion: '', fotosPrenda: []
        });
        prestamoCreado = true;
      }
      return { fila: numFila, ok: true, nombre, prestamoCreado };
    });
    DB.negocio.zonas = [...zonas];
    saveDB();
    return send(res, 200, {
      resultados,
      creados: resultados.filter(r => r.ok).length,
      errores: resultados.filter(r => !r.ok)
    });
  }

  if(pathname.startsWith('/api/clientes/') && (method === 'PUT' || method === 'DELETE')){
    if(me.rol !== 'admin') return send(res, 403, { error: 'Solo un administrador puede editar o eliminar clientes' });
    const id = pathname.split('/')[3];
    const cliente = DB.clientes.find(c=>c.id===id);
    if(!cliente) return send(res, 404, { error: 'Cliente no encontrado' });
    if(method === 'DELETE'){
      DB.clientes = DB.clientes.filter(c=>c.id!==id);
      DB.prestamos = DB.prestamos.filter(p=>p.clienteId!==id);
      DB.cobros = DB.cobros.filter(c=>c.clienteId!==id);
      saveDB();
      return send(res, 200, { ok: true });
    } else {
      const body = await readBody(req);
      Object.assign(cliente, {
        nombre: body.nombre ?? cliente.nombre, cedula: body.cedula ?? cliente.cedula,
        telefono: body.telefono ?? cliente.telefono,
        direccion: body.direccion ?? cliente.direccion, zona: body.zona ?? cliente.zona,
        cobradorId: body.cobradorId ?? cliente.cobradorId
      });
      saveDB();
      return send(res, 200, { cliente });
    }
  }

  if(pathname === '/api/prestamos' && method === 'POST'){
    const body = await readBody(req);
    const cliente = DB.clientes.find(c=>c.id===body.clienteId);
    if(!cliente) return send(res, 404, { error: 'Cliente no encontrado' });
    if(me.rol !== 'admin' && cliente.cobradorId !== me.id) return send(res, 403, { error: 'No autorizado' });
    const monto = Number(body.monto), tasa = Number(body.tasa)||0, numCuotas = Number(body.numCuotas);
    if(!monto || !numCuotas) return send(res, 400, { error: 'Monto y número de cuotas son obligatorios' });
    const { total, cuota, cuotaFinal } = calcularPrestamo(monto, tasa, numCuotas, body.modo, body.frecuencia);
    const prestamo = {
      id: uid('p'), clienteId: cliente.id, monto, tasa, modoInteres: body.modo, frecuencia: body.frecuencia,
      numCuotas, cuota, cuotaFinal, total, saldo: total, cuotasPagadas: 0, fechaInicio: new Date().toISOString().slice(0,10), estado: 'activo',
      entregadoPor: me.id, ...normalizePhotos(body, 'tarjetaFirma', 'fotosTarjeta'),
      esPrenda: !!body.esPrenda, prendaDescripcion: body.esPrenda ? String(body.prendaDescripcion||'').trim() : '',
      fotosPrenda: body.esPrenda && Array.isArray(body.fotosPrenda) ? body.fotosPrenda.filter(Boolean) : [],
      ubicacionEntrega: (body.lat!=null && body.lng!=null) ? { lat: Number(body.lat), lng: Number(body.lng) } : null
    };
    DB.prestamos.push(prestamo); saveDB();
    return send(res, 200, { prestamo });
  }

  if(pathname.startsWith('/api/prestamos/') && pathname.endsWith('/perdida') && method === 'PUT'){
    if(me.rol !== 'admin') return send(res, 403, { error: 'Solo un administrador puede marcar un préstamo como pérdida' });
    const id = pathname.split('/')[3];
    const prestamo = DB.prestamos.find(p=>p.id===id);
    if(!prestamo) return send(res, 404, { error: 'Préstamo no encontrado' });
    prestamo.estado = 'perdida';
    saveDB();
    return send(res, 200, { prestamo });
  }

  // Renovar un préstamo activo: crea uno nuevo y descuenta el saldo pendiente del anterior.
  // El saldo trasladado NO se registra como cobro (no infla efectivo/transferencia/recuperado en Reportes).
  if(pathname.startsWith('/api/prestamos/') && pathname.endsWith('/renovar') && method === 'PUT'){
    const id = pathname.split('/')[3];
    const prestamoViejo = DB.prestamos.find(p=>p.id===id);
    if(!prestamoViejo) return send(res, 404, { error: 'Préstamo no encontrado' });
    const cliente = DB.clientes.find(c=>c.id===prestamoViejo.clienteId);
    if(me.rol !== 'admin' && cliente.cobradorId !== me.id) return send(res, 403, { error: 'No autorizado' });
    if(prestamoViejo.estado !== 'activo') return send(res, 400, { error: 'Este préstamo ya no está activo' });
    const body = await readBody(req);
    const monto = Number(body.monto), tasa = Number(body.tasa)||0, numCuotas = Number(body.numCuotas);
    if(!monto || !numCuotas) return send(res, 400, { error: 'Monto y número de cuotas son obligatorios' });
    if(monto < prestamoViejo.saldo) return send(res, 400, { error: `El nuevo monto debe ser al menos ${prestamoViejo.saldo} (el saldo pendiente)` });
    const montoEntregado = monto - prestamoViejo.saldo;
    const { total, cuota, cuotaFinal } = calcularPrestamo(monto, tasa, numCuotas, body.modo, body.frecuencia);
    const prestamoNuevo = {
      id: uid('p'), clienteId: cliente.id, monto, tasa, modoInteres: body.modo, frecuencia: body.frecuencia,
      numCuotas, cuota, cuotaFinal, total, saldo: total, cuotasPagadas: 0, fechaInicio: new Date().toISOString().slice(0,10), estado: 'activo',
      entregadoPor: me.id, montoEntregado, prestamoAnteriorId: prestamoViejo.id, ...normalizePhotos(body, 'tarjetaFirma', 'fotosTarjeta'),
      esPrenda: !!body.esPrenda, prendaDescripcion: body.esPrenda ? String(body.prendaDescripcion||'').trim() : '',
      fotosPrenda: body.esPrenda && Array.isArray(body.fotosPrenda) ? body.fotosPrenda.filter(Boolean) : []
    };
    prestamoViejo.estado = 'renovado';
    prestamoViejo.renovadoEn = new Date().toISOString();
    prestamoViejo.renovadoPorPrestamoId = prestamoNuevo.id;
    DB.prestamos.push(prestamoNuevo);
    saveDB();
    return send(res, 200, { prestamoAnterior: prestamoViejo, prestamoNuevo, montoEntregado });
  }

  if(pathname === '/api/cobros' && method === 'POST'){
    const body = await readBody(req);
    const prestamo = DB.prestamos.find(p=>p.id===body.prestamoId);
    if(!prestamo) return send(res, 404, { error: 'Préstamo no encontrado' });
    const cliente = DB.clientes.find(c=>c.id===prestamo.clienteId);
    if(me.rol !== 'admin' && cliente.cobradorId !== me.id) return send(res, 403, { error: 'No autorizado' });
    const monto = Number(body.monto);
    if(!monto || monto<=0) return send(res, 400, { error: 'Monto inválido' });
    const cobro = {
      id: uid('c'), prestamoId: prestamo.id, clienteId: prestamo.clienteId, monto,
      fecha: new Date().toISOString(), cobradorId: me.id, metodo: body.metodo || 'efectivo',
      firma: body.firma || null, ...normalizePhotos(body, 'comprobante', 'comprobantes')
    };
    DB.cobros.push(cobro);
    prestamo.saldo = Math.max(0, prestamo.saldo - monto);
    // Las cuotas pagadas se derivan de cuánto se ha recuperado del total, no de un conteo fijo por cobro:
    // un abono parcial avanza menos de una cuota, y un adelanto puede saltar varias de una vez.
    prestamo.cuotasPagadas = Math.min(prestamo.numCuotas, Math.round((prestamo.total - prestamo.saldo) / prestamo.cuota));
    if(prestamo.saldo <= 0) prestamo.estado = 'pagado';
    saveDB();
    return send(res, 200, { cobro, prestamo });
  }

  // Registro de visita (con o sin cobro) para el checklist de ruta, con geolocalización opcional
  if(pathname === '/api/visitas' && method === 'POST'){
    const body = await readBody(req);
    const cliente = DB.clientes.find(c=>c.id===body.clienteId);
    if(!cliente) return send(res, 404, { error: 'Cliente no encontrado' });
    if(me.rol !== 'admin' && cliente.cobradorId !== me.id) return send(res, 403, { error: 'No autorizado' });
    const visita = {
      id: uid('v'), clienteId: cliente.id, cobradorId: me.id,
      fecha: new Date().toISOString(),
      resultado: body.resultado === 'cobrado' ? 'cobrado' : 'sin_cobro',
      motivo: body.motivo || null,
      cobroId: body.cobroId || null,
      lat: body.lat!=null ? Number(body.lat) : null,
      lng: body.lng!=null ? Number(body.lng) : null
    };
    DB.visitas.push(visita); saveDB();
    return send(res, 200, { visita });
  }

  // Gastos del negocio o de un cobrador en particular
  if(pathname === '/api/gastos' && method === 'POST'){
    const body = await readBody(req);
    const monto = Number(body.monto);
    if(!monto || monto<=0) return send(res, 400, { error: 'Monto inválido' });
    if(!body.concepto) return send(res, 400, { error: 'Falta el concepto del gasto' });
    const cobradorId = body.cobradorId || me.id;
    if(me.rol !== 'admin' && cobradorId !== me.id) return send(res, 403, { error: 'Solo puedes registrar gastos propios' });
    const gasto = {
      id: uid('g'), concepto: String(body.concepto).trim(), monto,
      categoria: body.categoria || 'otro', cobradorId,
      comprobantes: Array.isArray(body.comprobantes) ? body.comprobantes : [],
      fecha: new Date().toISOString()
    };
    DB.gastos.push(gasto); saveDB();
    return send(res, 200, { gasto });
  }

  if(pathname.startsWith('/api/gastos/') && method === 'DELETE'){
    const id = pathname.split('/')[3];
    const gasto = DB.gastos.find(g=>g.id===id);
    if(!gasto) return send(res, 404, { error: 'Gasto no encontrado' });
    if(me.rol !== 'admin' && gasto.cobradorId !== me.id) return send(res, 403, { error: 'No autorizado' });
    DB.gastos = DB.gastos.filter(g=>g.id!==id);
    saveDB();
    return send(res, 200, { ok: true });
  }

  // Ubicación en tiempo real (mientras el cobrador tiene la app abierta)
  if(pathname === '/api/ubicacion' && method === 'POST'){
    const body = await readBody(req);
    if(body.lat==null || body.lng==null) return send(res, 400, { error: 'Faltan coordenadas' });
    if(!DB.ubicaciones[me.id]) DB.ubicaciones[me.id] = [];
    const hoy = todayISO();
    DB.ubicaciones[me.id] = DB.ubicaciones[me.id].filter(p=>p.fecha.slice(0,10)===hoy);
    DB.ubicaciones[me.id].push({ lat: Number(body.lat), lng: Number(body.lng), fecha: new Date().toISOString() });
    if(DB.ubicaciones[me.id].length > 500) DB.ubicaciones[me.id] = DB.ubicaciones[me.id].slice(-500);
    saveDB();
    return send(res, 200, { ok: true });
  }

  if(pathname === '/api/ubicaciones' && method === 'GET'){
    if(me.rol !== 'admin') return send(res, 403, { error: 'Solo un administrador puede ver el mapa del equipo' });
    return send(res, 200, DB.ubicaciones);
  }

  if(pathname === '/api/negocio' && method === 'PUT'){
    if(me.rol !== 'admin') return send(res, 403, { error: 'Solo un administrador puede cambiar esto' });
    const body = await readBody(req);
    Object.assign(DB.negocio, body);
    saveDB();
    return send(res, 200, { negocio: DB.negocio });
  }

  if(pathname === '/api/export' && method === 'GET'){
    if(me.rol !== 'admin') return send(res, 403, { error: 'Solo un administrador puede exportar' });
    return send(res, 200, DB);
  }

  if(pathname === '/api/import' && method === 'POST'){
    if(me.rol !== 'admin') return send(res, 403, { error: 'Solo un administrador puede importar' });
    const body = await readBody(req);
    if(!body || !Array.isArray(body.clientes)) return send(res, 400, { error: 'Archivo inválido' });
    const usuariosImportados = (body.usuarios || []).map(u=>{
      if(u.pinHash && u.pinSalt) return { id: u.id || uid('u'), nombre: u.nombre, rol: u.rol || 'cobrador', pinHash: u.pinHash, pinSalt: u.pinSalt };
      const salt = crypto.randomBytes(16).toString('hex');
      // compatibilidad con el formato antiguo (solo local) que guardaba el PIN en texto plano
      return { id: u.id || uid('u'), nombre: u.nombre, rol: u.rol || 'cobrador', pinSalt: salt, pinHash: u.pin ? hashPin(u.pin, salt) : null };
    });
    if(!usuariosImportados.some(u=>u.rol==='admin')){
      return send(res, 400, { error: 'El archivo debe incluir al menos un usuario administrador' });
    }
    DB = {
      negocio: Object.assign(seedDB().negocio, body.negocio || {}),
      usuarios: usuariosImportados,
      clientes: body.clientes || [],
      prestamos: body.prestamos || [],
      cobros: body.cobros || []
    };
    saveDB();
    return send(res, 200, { ok: true });
  }

  if(pathname === '/api/reset' && method === 'DELETE'){
    if(me.rol !== 'admin') return send(res, 403, { error: 'Solo un administrador puede borrar todo' });
    const url = new URL(req.url, 'http://x');
    if(url.searchParams.get('confirm') !== 'BORRAR') return send(res, 400, { error: 'Confirmación requerida' });
    DB = seedDB();
    saveDB();
    return send(res, 200, { ok: true });
  }

  return send(res, 404, { error: 'Ruta no encontrada' });
}

/* ---------------------------------------------------------------
   Servidor HTTP
   --------------------------------------------------------------- */
/* ---------------------------------------------------------------
   NOTIFICACIONES PROGRAMADAS — clientes pendientes por pagar
   Se revisa cada 30 segundos si es la hora configurada (por defecto
   12:00 m. y 4:00 p.m., hora de Colombia) y, si es así, se le avisa
   a cada usuario cuántos clientes activos tiene sin pagar hoy.
   --------------------------------------------------------------- */
function pendingCountFor(usuario){
  const misClientes = usuario.rol === 'admin' ? DB.clientes : DB.clientes.filter(c=>c.cobradorId===usuario.id);
  const ids = new Set(misClientes.map(c=>c.id));
  const misPrestamos = DB.prestamos.filter(p=>p.estado==='activo' && ids.has(p.clienteId));
  return misPrestamos.filter(p=>diasEnMora(p) > 0).length;
}

function horaActualEn(timezone, now){
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: timezone, hourCycle:'h23', hour:'2-digit', minute:'2-digit',
    year:'numeric', month:'2-digit', day:'2-digit'
  }).formatToParts(now || new Date());
  const map = {};
  parts.forEach(p=>{ map[p.type] = p.value; });
  return { hour: Number(map.hour), minute: Number(map.minute), dateKey: `${map.year}-${map.month}-${map.day}` };
}

let lastNotifySlot = null;
async function runNotificationScheduler(){
  if(!webpush) return;
  const { hour, minute, dateKey } = horaActualEn(NOTIFY_TIMEZONE);
  const match = NOTIFY_TIMES.find(t=>t.h===hour && t.m===minute);
  if(!match) return;
  const slotKey = `${dateKey}-${match.h}:${match.m}`;
  if(lastNotifySlot === slotKey) return; // ya se envió en este mismo minuto/franja
  lastNotifySlot = slotKey;

  let cambios = false;
  for(const usuario of DB.usuarios){
    const subs = DB.pushSubs[usuario.id] || [];
    if(!subs.length) continue;
    const count = pendingCountFor(usuario);
    if(count === 0) continue;
    const payload = JSON.stringify({
      title: DB.negocio.nombre,
      body: `Tienes ${count} cliente${count===1?'':'s'} pendiente${count===1?'':'s'} por pagar hoy.`
    });
    for(const sub of subs.slice()){
      try{ await webpush.sendNotification(sub, payload); }
      catch(err){
        if(err && (err.statusCode === 404 || err.statusCode === 410)){
          DB.pushSubs[usuario.id] = DB.pushSubs[usuario.id].filter(s=>s.endpoint !== sub.endpoint);
          cambios = true;
        } else {
          console.error('Error enviando notificación a', usuario.nombre, ':', err && err.message);
        }
      }
    }
  }
  if(cambios) saveDB();
}
setInterval(runNotificationScheduler, 30*1000);

const server = http.createServer(async (req, res)=>{
  const url = new URL(req.url, 'http://x');
  const pathname = url.pathname;

  if(req.method === 'OPTIONS'){
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS'
    });
    return res.end();
  }

  if(pathname.startsWith('/api/')){
    try {
      await api(req, res, pathname, req.method);
    } catch(err){
      if(err.tooLarge){ send(res, 413, { error: err.message }); return; }
      console.error(err);
      send(res, 500, { error: 'Error interno del servidor' });
    }
    return;
  }

  serveStatic(req, res, pathname);
});

server.listen(PORT, ()=>{
  console.log(`Recauda escuchando en http://localhost:${PORT}`);
});
