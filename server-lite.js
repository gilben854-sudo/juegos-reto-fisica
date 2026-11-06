/**
 * Servidor ligero sin dependencias npm (solo Node)
 * Para probar UI + control básico de licencias
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = process.env.PORT || 3780;
function findPublic() {
  const candidates = [
    path.join(__dirname, 'public'),
    path.join(process.cwd(), 'public'),
    path.join(__dirname, 'saas-platform', 'public'),
    path.join(process.cwd(), 'saas-platform', 'public'),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c) && fs.existsSync(path.join(c, 'catalogo.html'))) return c;
  }
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return path.join(__dirname, 'public');
}
const PUBLIC = findPublic();
const DB_PATH = path.join(__dirname, 'data', 'db.json');

function loadDb() {
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}
function saveDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}
function hashPw(pw, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(pw), salt, 64).toString('hex');
  return 'scrypt:' + salt + ':' + hash;
}
function verifyPw(pw, stored) {
  if (!stored) return false;
  const parts = stored.split(':');
  try {
    if (parts.length === 3 && parts[0] === 'scrypt') {
      const actual = crypto.scryptSync(String(pw), parts[1], 64);
      const expected = Buffer.from(parts[2], 'hex');
      return expected.length === actual.length && crypto.timingSafeEqual(actual, expected);
    }
    // Accept legacy salted SHA-256 hashes only to migrate existing accounts on login.
    if (parts.length === 2) {
      const actual = crypto.createHash('sha256').update(parts[0] + String(pw)).digest('hex');
      const expected = Buffer.from(parts[1], 'hex');
      const actualBuf = Buffer.from(actual, 'hex');
      return expected.length === actualBuf.length && crypto.timingSafeEqual(actualBuf, expected);
    }
  } catch (_) {}
  return false;
}
function needsRehash(stored) { return !String(stored || '').startsWith('scrypt:'); }
function token() { return crypto.randomBytes(32).toString('hex'); }
const loginAttempts = new Map();
function loginAllowed(key) {
  const now = Date.now();
  const item = loginAttempts.get(key) || { count: 0, reset: now + 15 * 60 * 1000 };
  if (item.reset <= now) { item.count = 0; item.reset = now + 15 * 60 * 1000; }
  item.count += 1; loginAttempts.set(key, item);
  return item.count <= 10;
}
function clearLoginAttempts(key) { loginAttempts.delete(key); }
function publicTeacher(t) {
  return {
    id: t.id, name: t.name, email: t.email, school: t.school || '',
    certificateEmail: t.certificateEmail || t.email, active: !!t.active,
    validUntil: t.validUntil, plan: t.plan || 'trial', classCode: t.classCode,
    licenseOk: licenseActive(t)
  };
}
function uuid() {
  return crypto.randomBytes(8).toString('hex') + '-' + crypto.randomBytes(4).toString('hex');
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 1e6) reject(new Error('too big')); });
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); } catch (e) { resolve({}); }
    });
  });
}
function send(res, code, obj) {
  const body = typeof obj === 'string' ? obj : JSON.stringify(obj);
  res.writeHead(code, {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'self' 'unsafe-inline' https://api.qrserver.com https://formsubmit.co; img-src 'self' data: https://api.qrserver.com; connect-src 'self' https://formsubmit.co; frame-ancestors 'none'",
    'Content-Type': typeof obj === 'string' ? (String(obj).trim().startsWith('<') ? 'text/html; charset=utf-8' : 'text/plain') : 'application/json',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  });
  res.end(body);
}
function auth(req, role) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!t) return null;
  const db = loadDb();
  const sess = db.sessions[t];
  if (!sess || sess.expires < Date.now()) return null;
  if (role && sess.role !== role) return null;
  return { token: t, sess, db };
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    return res.end();
  }

  const u = new URL(req.url, 'http://localhost');
  const p = u.pathname;

  try {
    // API
    if (p === '/api/health') return send(res, 200, { ok: true, service: 'juegos-reto-fisica-lite' });

    if (p === '/api/admin/login' && req.method === 'POST') {
      const body = await readBody(req);
      const ip = req.socket.remoteAddress || 'unknown';
      if (!loginAllowed('admin:' + ip)) return send(res, 429, { error: 'Demasiados intentos. Espera unos minutos.' });
      const db = loadDb();
      if (body.username !== db.admin.username || !verifyPw(body.password || '', db.admin.password_hash))
        return send(res, 401, { error: 'Credenciales incorrectas' });
      clearLoginAttempts('admin:' + ip);
      if (needsRehash(db.admin.password_hash)) db.admin.password_hash = hashPw(body.password || '');
      const t = token();
      db.sessions[t] = { role: 'admin', expires: Date.now() + 12 * 3600 * 1000 };
      saveDb(db);
      return send(res, 200, { token: t, role: 'admin' });
    }

    if (p === '/api/admin/change-password' && req.method === 'POST') {
      const a = auth(req, 'admin');
      if (!a) return send(res, 401, { error: 'No autorizado' });
      const body = await readBody(req);
      const current = String(body.currentPassword || '');
      const next = String(body.newPassword || '');
      if (!current || !next) return send(res, 400, { error: 'Completa la clave actual y la nueva clave' });
      if (next.length < 8) return send(res, 400, { error: 'La nueva clave debe tener al menos 8 caracteres' });
      if (current === next) return send(res, 400, { error: 'La nueva clave debe ser diferente' });
      if (!verifyPw(current, a.db.admin.password_hash)) return send(res, 401, { error: 'La clave actual es incorrecta' });
      a.db.admin.password_hash = hashPw(next);
      saveDb(a.db);
      return send(res, 200, { ok: true });
    }
    if (p === '/api/teacher/register' && req.method === 'POST') {
      const body = await readBody(req);
      if (!body.name || !body.email || !body.password || String(body.password).length < 6)
        return send(res, 400, { error: 'Datos incompletos' });
      const db = loadDb();
      if (Object.values(db.teachers).some(x => x.email.toLowerCase() === body.email.toLowerCase()))
        return send(res, 409, { error: 'Correo ya registrado' });
      const id = uuid();
      const classCode = ('C' + crypto.randomBytes(3).toString('hex')).toUpperCase();
      db.teachers[id] = {
        id, name: body.name.trim(), email: body.email.trim().toLowerCase(),
        password_hash: hashPw(body.password), school: (body.school || '').trim(),
        certificateEmail: body.email.trim().toLowerCase(), active: true, plan: 'trial',
        validUntil: new Date(Date.now() + 7 * 86400000).toISOString(),
        classCode, createdAt: new Date().toISOString()
      };
      saveDb(db);
      return send(res, 200, { ok: true, message: 'Prueba 7 días', teacher: publicTeacher(db.teachers[id]) });
    }

    if (p === '/api/teacher/login' && req.method === 'POST') {
      const body = await readBody(req);
      const ip = req.socket.remoteAddress || 'unknown';
      const loginKey = 'teacher:' + ip;
      if (!loginAllowed(loginKey)) return send(res, 429, { error: 'Demasiados intentos. Espera unos minutos.' });
      const db = loadDb();
      const entry = Object.values(db.teachers).find(x => x.email.toLowerCase() === (body.email || '').toLowerCase());
      if (!entry || !verifyPw(body.password || '', entry.password_hash))
        return send(res, 401, { error: 'Correo o contraseña incorrectos' });
      clearLoginAttempts(loginKey);
      if (needsRehash(entry.password_hash)) entry.password_hash = hashPw(body.password || '');
      const t = token();
      db.sessions[t] = { role: 'teacher', teacherId: entry.id, expires: Date.now() + 12 * 3600 * 1000 };
      saveDb(db);
      return send(res, 200, { token: t, role: 'teacher', teacher: publicTeacher(entry), access: licenseActive(entry) ? 'granted' : 'blocked' });
    }

    if (p === '/api/teacher/me' && req.method === 'GET') {
      const a = auth(req, 'teacher');
      if (!a) return send(res, 401, { error: 'No autorizado' });
      const t = a.db.teachers[a.sess.teacherId];
      return send(res, 200, { teacher: publicTeacher(t), access: licenseActive(t) ? 'granted' : 'blocked' });
    }

    if (p === '/api/admin/teachers' && req.method === 'GET') {
      const a = auth(req, 'admin');
      if (!a) return send(res, 401, { error: 'No autorizado' });
      return send(res, 200, { teachers: Object.values(a.db.teachers).map(publicTeacher) });
    }

    if (p.startsWith('/api/admin/teachers/') && p.endsWith('/activate') && req.method === 'POST') {
      const a = auth(req, 'admin');
      if (!a) return send(res, 401, { error: 'No autorizado' });
      const id = p.split('/')[4];
      const t = a.db.teachers[id];
      if (!t) return send(res, 404, { error: 'No encontrado' });
      const body = await readBody(req);
      const days = Math.max(1, parseInt(body.days, 10) || 30);
      t.active = true; t.plan = body.plan || 'paid';
      t.validUntil = new Date(Date.now() + days * 86400000).toISOString();
      saveDb(a.db);
      return send(res, 200, { ok: true, teacher: publicTeacher(t) });
    }

    if (p.startsWith('/api/admin/teachers/') && p.endsWith('/suspend') && req.method === 'POST') {
      const a = auth(req, 'admin');
      if (!a) return send(res, 401, { error: 'No autorizado' });
      const id = p.split('/')[4];
      const t = a.db.teachers[id];
      if (!t) return send(res, 404, { error: 'No encontrado' });
      t.active = false; saveDb(a.db);
      return send(res, 200, { ok: true, teacher: publicTeacher(t) });
    }

    if (p === '/api/admin/teachers' && req.method === 'POST') {
      const a = auth(req, 'admin');
      if (!a) return send(res, 401, { error: 'No autorizado' });
      const body = await readBody(req);
      if (!body.name || !body.email || !body.password) return send(res, 400, { error: 'Faltan datos' });
      const id = uuid();
      const days = Math.max(1, parseInt(body.days, 10) || 30);
      a.db.teachers[id] = {
        id, name: body.name.trim(), email: body.email.trim().toLowerCase(),
        password_hash: hashPw(body.password), school: (body.school || '').trim(),
        certificateEmail: body.email.trim().toLowerCase(), active: true,
        plan: body.plan || 'paid',
        validUntil: new Date(Date.now() + days * 86400000).toISOString(),
        classCode: ('C' + crypto.randomBytes(3).toString('hex')).toUpperCase(),
        createdAt: new Date().toISOString()
      };
      saveDb(a.db);
      return send(res, 200, { ok: true, teacher: publicTeacher(a.db.teachers[id]) });
    }

    if (p === '/api/access/check' && req.method === 'GET') {
      const classCode = (u.searchParams.get('classCode') || '').toUpperCase();
      const db = loadDb();
      if (!classCode) return send(res, 200, { allowed: false, reason: 'no_credentials' });
      const t = Object.values(db.teachers).find(x => (x.classCode || '') === classCode);
      if (!t) return send(res, 200, { allowed: false, reason: 'invalid_class_code' });
      if (!licenseActive(t)) return send(res, 200, { allowed: false, reason: 'license_inactive' });
      return send(res, 200, {
        allowed: true, mode: 'student',
        certificateEmail: t.certificateEmail || t.email,
        school: t.school || '', classCode: t.classCode, teacherName: t.name
      });
    }

    if (p === '/api/teacher/results' && req.method === 'GET') {
      const a = auth(req, 'teacher');
      if (!a) return send(res, 401, { error: 'No autorizado' });
      const list = (a.db.results || []).filter(r => r.teacherId === a.sess.teacherId).slice(-100).reverse();
      return send(res, 200, { results: list });
    }

    if (p === '/api/teacher/settings' && req.method === 'POST') {
      const a = auth(req, 'teacher');
      if (!a) return send(res, 401, { error: 'No autorizado' });
      const t = a.db.teachers[a.sess.teacherId];
      if (!licenseActive(t)) return send(res, 403, { error: 'Licencia inactiva' });
      const body = await readBody(req);
      if (body.certificateEmail) t.certificateEmail = String(body.certificateEmail).trim().toLowerCase();
      if (body.school !== undefined) t.school = String(body.school).trim();
      saveDb(a.db);
      return send(res, 200, { ok: true, teacher: publicTeacher(t) });
    }

    // Static files
    let filePath = path.join(PUBLIC, p === '/' ? 'index.html' : p);
    const relative = path.relative(PUBLIC, filePath);
    if (relative.startsWith('..') || path.isAbsolute(relative)) return send(res, 403, { error: 'Forbidden' });
    if (fs.existsSync(filePath) && fs.statSync(filePath).isDirectory())
      filePath = path.join(filePath, 'index.html');
    if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
      if (p === '/' || p === '') {
        return send(res, 200, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Juegos de Reto para Física</title>
<style>body{font-family:system-ui;background:#0b1220;color:#e2e8f0;padding:40px;max-width:640px;margin:auto}
a{color:#38bdf8;display:block;margin:10px 0;font-size:1.1rem}</style></head><body>
<h1>Juegos de Reto para Física</h1>
<p>Aprende física resolviendo retos · GILAST</p>
<a href="/catalogo.html">Catálogo de juegos</a>
<a href="/profesor.html">Panel del profesor</a>
<a href="/admin.html">Admin (licencias)</a>

</body></html>`);
      }
      return send(res, 404, { error: 'Not found' });
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    fs.createReadStream(filePath).pipe(res);
  } catch (e) {
    console.error(e);
    send(res, 500, { error: 'Error interno del servidor' });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('Juegos de Reto para Física — http://localhost:' + PORT);
  console.log('Catálogo: http://localhost:' + PORT + '/catalogo.html');
});
