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
console.log('PUBLIC dir:', PUBLIC);
const DB_PATH = path.join(__dirname, 'data', 'db.json');

function loadDb() {
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}
function saveDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}
function hashPw(pw, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const h = crypto.createHash('sha256').update(salt + pw).digest('hex');
  return salt + ':' + h;
}
function verifyPw(pw, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  return crypto.createHash('sha256').update(salt + pw).digest('hex') === hash;
}
function token() { return crypto.randomBytes(24).toString('hex'); }
function licenseActive(t) {
  return t && t.active && t.validUntil && new Date(t.validUntil).getTime() >= Date.now();
}
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
    'Content-Type': typeof obj === 'string' ? (String(obj).trim().startsWith('<') ? 'text/html; charset=utf-8' : 'text/plain') : 'application/json',
    'Access-Control-Allow-Origin': '*',
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
      'Access-Control-Allow-Origin': '*',
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
      const db = loadDb();
      if (body.username !== db.admin.username || !verifyPw(body.password || '', db.admin.password_hash))
        return send(res, 401, { error: 'Credenciales incorrectas' });
      const t = token();
      db.sessions[t] = { role: 'admin', expires: Date.now() + 12 * 3600 * 1000 };
      saveDb(db);
      return send(res, 200, { token: t, role: 'admin' });
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
      const db = loadDb();
      const entry = Object.values(db.teachers).find(x => x.email.toLowerCase() === (body.email || '').toLowerCase());
      if (!entry || !verifyPw(body.password || '', entry.password_hash))
        return send(res, 401, { error: 'Correo o contraseña incorrectos' });
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
    if (!filePath.startsWith(PUBLIC)) return send(res, 403, { error: 'Forbidden' });
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
<p style="color:#94a3b8;font-size:.9rem;margin-top:24px">PUBLIC: ` + PUBLIC + `</p>
</body></html>`);
      }
      return send(res, 404, { error: 'Not found', path: p, public: PUBLIC });
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    fs.createReadStream(filePath).pipe(res);
  } catch (e) {
    console.error(e);
    send(res, 500, { error: e.message });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('Juegos de Reto para Física — http://localhost:' + PORT);
  console.log('Admin: admin / NewtonSaaS2026!');
  console.log('Catálogo: http://localhost:' + PORT + '/catalogo.html');
});
