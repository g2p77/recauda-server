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

function seedDB(){
  const salt = crypto.randomBytes(16).toString('hex');
  return {
    negocio: { nombre: 'Mi Negocio de Cobranza', moneda: 'COP', logo: 'R', plan: 'premium', recordatorios: false },
    usuarios: [
      { id: 'u1', nombre: 'Administrador', rol: 'admin', pinSalt: salt, pinHash: hashPin('1234', salt) }
    ],
    clientes: [],
    prestamos: [],
    cobros: [],
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
  if(!DB.pushSubs) DB.pushSubs = {}; // compatibilidad con instalaciones ya existentes
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
function calcularPrestamo(monto, tasaMensualPct, numCuotas, modo, frecuencia){
  const dias = PERIOD_DAYS[frecuencia] || 1;
  const r = (tasaMensualPct/100) * (dias/30);
  let total, cuota;
  if(modo === 'fijo'){
    total = monto * (1 + r*numCuotas);
    cuota = total/numCuotas;
  } else if(modo === 'recalculado'){
    if(r === 0){ total = monto; cuota = monto/numCuotas; }
    else { cuota = monto*r/(1-Math.pow(1+r,-numCuotas)); total = cuota*numCuotas; }
  } else {
    total = monto * Math.pow(1+r, numCuotas);
    cuota = total/numCuotas;
  }
  return { total: Math.round(total), cuota: Math.round(cuota) };
}
function diasEnMora(prestamo){
  const cobrosPrestamo = DB.cobros.filter(c=>c.prestamoId===prestamo.id).sort((a,b)=>b.fecha.localeCompare(a.fecha));
  const ultima = cobrosPrestamo[0] ? new Date(cobrosPrestamo[0].fecha) : new Date(prestamo.fechaInicio);
  const diasCiclo = PERIOD_DAYS[prestamo.frecuencia] || 1;
  const dias = Math.floor((Date.now() - ultima.getTime())/(1000*3600*24));
  return Math.max(0, dias - diasCiclo);
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
function stateFor(user){
  return {
    negocio: DB.negocio,
    usuarios: DB.usuarios.map(publicUser),
    clientes: clientesVisibles(user),
    prestamos: prestamosVisibles(user),
    cobros: cobrosVisibles(user),
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
    saveDB();
    return send(res, 200, { usuarios: DB.usuarios.map(publicUser) });
  }

  if(pathname === '/api/clientes' && method === 'POST'){
    const body = await readBody(req);
    if(!body.nombre) return send(res, 400, { error: 'Falta el nombre del cliente' });
    const cliente = {
      id: uid('cl'), nombre: String(body.nombre).trim(),
      telefono: body.telefono || '', direccion: body.direccion || '', zona: body.zona || '',
      cobradorId: body.cobradorId || me.id
    };
    DB.clientes.push(cliente); saveDB();
    return send(res, 200, { cliente });
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
        nombre: body.nombre ?? cliente.nombre, telefono: body.telefono ?? cliente.telefono,
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
    const { total, cuota } = calcularPrestamo(monto, tasa, numCuotas, body.modo, body.frecuencia);
    const prestamo = {
      id: uid('p'), clienteId: cliente.id, monto, tasa, modoInteres: body.modo, frecuencia: body.frecuencia,
      numCuotas, cuota, total, saldo: total, cuotasPagadas: 0, fechaInicio: new Date().toISOString().slice(0,10), estado: 'activo'
    };
    DB.prestamos.push(prestamo); saveDB();
    return send(res, 200, { prestamo });
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
      firma: body.firma || null, comprobante: body.comprobante || null
    };
    DB.cobros.push(cobro);
    prestamo.saldo = Math.max(0, prestamo.saldo - monto);
    prestamo.cuotasPagadas += 1;
    if(prestamo.saldo <= 0) prestamo.estado = 'pagado';
    saveDB();
    return send(res, 200, { cobro, prestamo });
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
