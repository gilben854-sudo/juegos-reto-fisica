/**
 * Física SaaS — Control de acceso y licencias
 * Admin activa profesores. Sin licencia activa = no se puede usar.
 */
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3780;
const DB_PATH = path.join(__dirname, 'data', 'db.json');
const DB_SEED_PATH = path.join(__dirname, 'db-template.json');
const PUBLIC = path.join(__dirname, 'public');

app.use(cors({ origin: process.env.APP_ORIGIN || false }));
app.disable('x-powered-by');
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});
app.use(express.json({ limit: '1mb' }));
app.use(express.static(PUBLIC));

function loadDb() {
  if (!fs.existsSync(DB_PATH)) {
    if (!fs.existsSync(DB_SEED_PATH)) throw new Error('Base de datos no inicializada');
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    fs.copyFileSync(DB_SEED_PATH, DB_PATH);
  }
  const db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  // Compatibilidad con bases persistentes creadas antes de añadir sesiones y resultados.
  if (!db.teachers || typeof db.teachers !== 'object' || Array.isArray(db.teachers)) db.teachers = {};
  if (!db.sessions || typeof db.sessions !== 'object' || Array.isArray(db.sessions)) db.sessions = {};
  if (!db.studentSessions || typeof db.studentSessions !== 'object' || Array.isArray(db.studentSessions)) db.studentSessions = {};
  if (!Array.isArray(db.results)) db.results = [];
  if (!db.classrooms || typeof db.classrooms !== 'object' || Array.isArray(db.classrooms)) db.classrooms = {};
  if (!db.licenses || typeof db.licenses !== 'object' || Array.isArray(db.licenses)) db.licenses = {};
  return db;
}
function saveDb(db) {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  const serialized = JSON.stringify(db, null, 2);
  try {
    const backupDir = path.join(path.dirname(DB_PATH), 'backups'); fs.mkdirSync(backupDir, { recursive: true });
    if (fs.existsSync(DB_PATH)) fs.copyFileSync(DB_PATH, path.join(backupDir, 'db-' + new Date().toISOString().replace(/[:.]/g, '-') + '.json'));
    const backups = fs.readdirSync(backupDir).filter(x => x.endsWith('.json')).sort(); while (backups.length > 10) fs.unlinkSync(path.join(backupDir, backups.shift()));
  } catch (_) {}
  fs.writeFileSync(DB_PATH, serialized, 'utf8');
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
function authTeacher(req) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!t) return null;
  const db = loadDb();
  const sess = db.sessions[t];
  if (!sess || sess.role !== 'teacher') return null;
  if (sess.expires < Date.now()) {
    delete db.sessions[t];
    saveDb(db);
    return null;
  }
  const teacher = db.teachers[sess.teacherId];
  if (!teacher) return null;
  return { token: t, teacher, teacherId: sess.teacherId, db };
}
function authAdmin(req) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!t) return null;
  const db = loadDb();
  const sess = db.sessions[t];
  if (!sess || sess.role !== 'admin') return null;
  if (sess.expires < Date.now()) {
    delete db.sessions[t];
    saveDb(db);
    return null;
  }
  return { token: t, db };
}
function licenseActive(teacher) {
  if (!teacher || !teacher.active) return false;
  if (!teacher.validUntil) return false;
  return new Date(teacher.validUntil).getTime() >= Date.now();
}
const SUBJECTS = ['fisica','quimica','biologia','matematicas'];
function normalizeSubjects(value) { const list=Array.isArray(value)?value:[]; return [...new Set(list.map(x=>String(x).toLowerCase()).filter(x=>SUBJECTS.includes(x)))]; }
function teacherSubjects(t) { const list=normalizeSubjects(t&&t.subjects); return list.length?list:['fisica']; }

function publicTeacher(t) {
  return {
    id: t.id,
    name: t.name,
    email: t.email,
    school: t.school || '',
    certificateEmail: t.certificateEmail || t.email,
    active: !!t.active,
    validUntil: t.validUntil || null,
    plan: t.plan || 'trial',
    classCode: t.classCode || null,
    licenseOk: licenseActive(t),
    subjects: teacherSubjects(t)
  };
}

// ---------- AUTH ----------
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body || {};
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  if (!loginAllowed('admin:' + ip)) return res.status(429).json({ error: 'Demasiados intentos. Espera unos minutos.' });
  const db = loadDb();
  if (username !== db.admin.username || !verifyPw(password || '', db.admin.password_hash)) {
    return res.status(401).json({ error: 'Credenciales de administrador incorrectas' });
  }
  clearLoginAttempts('admin:' + ip);
  if (needsRehash(db.admin.password_hash)) db.admin.password_hash = hashPw(password || '');
  const t = token();
  db.sessions[t] = { role: 'admin', expires: Date.now() + 12 * 3600 * 1000 };
  saveDb(db);
  res.json({ token: t, role: 'admin' });
});

app.post('/api/admin/change-password', (req, res) => {
  const a = authAdmin(req);
  if (!a) return res.status(401).json({ error: 'No autorizado' });
  const current = String(req.body.currentPassword || '');
  const next = String(req.body.newPassword || '');
  if (!current || !next) return res.status(400).json({ error: 'Completa la clave actual y la nueva clave' });
  if (next.length < 8) return res.status(400).json({ error: 'La nueva clave debe tener al menos 8 caracteres' });
  if (current === next) return res.status(400).json({ error: 'La nueva clave debe ser diferente' });
  if (!verifyPw(current, a.db.admin.password_hash)) return res.status(401).json({ error: 'La clave actual es incorrecta' });
  a.db.admin.password_hash = hashPw(next);
  saveDb(a.db);
  res.json({ ok: true });
});
app.post('/api/teacher/login', (req, res) => {
  const { email, password } = req.body || {};
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const loginKey = 'teacher:' + ip;
  if (!loginAllowed(loginKey)) return res.status(429).json({ error: 'Demasiados intentos. Espera unos minutos.' });
  const db = loadDb();
  const entry = Object.values(db.teachers).find(
    (x) => (x.email || '').toLowerCase() === (email || '').toLowerCase()
  );
  if (!entry || !verifyPw(password || '', entry.password_hash)) {
    return res.status(401).json({ error: 'Correo o contraseña incorrectos' });
  }
  clearLoginAttempts(loginKey);
  if (needsRehash(entry.password_hash)) entry.password_hash = hashPw(password || '');
  const t = token();
  db.sessions[t] = {
    role: 'teacher',
    teacherId: entry.id,
    expires: Date.now() + 12 * 3600 * 1000
  };
  saveDb(db);
  res.json({
    token: t,
    role: 'teacher',
    teacher: publicTeacher(entry),
    access: licenseActive(entry) ? 'granted' : 'blocked'
  });
});

app.post('/api/teacher/register', (req, res) => {
  return res.status(403).json({ error: 'El registro de profesores está deshabilitado. Solicita tu acceso al administrador.' });
});
// ---------- ADMIN ----------
app.get('/api/admin/teachers', (req, res) => {
  const a = authAdmin(req);
  if (!a) return res.status(401).json({ error: 'No autorizado' });
  const list = Object.values(a.db.teachers).map(publicTeacher);
  res.json({ teachers: list });
});

app.post('/api/admin/teachers/:id/password', (req, res) => {
  const a = authAdmin(req);
  if (!a) return res.status(401).json({ error: 'No autorizado' });
  const t = a.db.teachers[req.params.id];
  if (!t) return res.status(404).json({ error: 'Profesor no encontrado' });
  const password = String(req.body.password || '');
  if (password.length < 8) return res.status(400).json({ error: 'La nueva clave debe tener al menos 8 caracteres' });
  t.password_hash = hashPw(password);
  saveDb(a.db);
  res.json({ ok: true });
});

app.post('/api/admin/teachers/:id/activate', (req, res) => {
  const a = authAdmin(req);
  if (!a) return res.status(401).json({ error: 'No autorizado' });
  const t = a.db.teachers[req.params.id];
  if (!t) return res.status(404).json({ error: 'Profesor no encontrado' });
  const days = Math.max(1, parseInt(req.body.days, 10) || 30);
  const plan = req.body.plan || 'paid';
  if (Array.isArray(req.body.subjects)) t.subjects = normalizeSubjects(req.body.subjects);
  t.active = true;
  t.plan = plan;
  t.validUntil = new Date(Date.now() + days * 86400000).toISOString();
  saveDb(a.db);
  res.json({ ok: true, teacher: publicTeacher(t) });
});

app.post('/api/admin/teachers/:id/suspend', (req, res) => {
  const a = authAdmin(req);
  if (!a) return res.status(401).json({ error: 'No autorizado' });
  const t = a.db.teachers[req.params.id];
  if (!t) return res.status(404).json({ error: 'Profesor no encontrado' });
  t.active = false;
  saveDb(a.db);
  res.json({ ok: true, teacher: publicTeacher(t) });
});

app.post('/api/admin/teachers', (req, res) => {
  const a = authAdmin(req);
  if (!a) return res.status(401).json({ error: 'No autorizado' });
  const { name, email, password, school, days, plan } = req.body || {};
  const subjects = normalizeSubjects(req.body && req.body.subjects);
  if (!subjects.length) return res.status(400).json({ error: 'Selecciona al menos una materia' });
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Faltan datos' });
  }
  if (Object.values(a.db.teachers).some((x) => x.email.toLowerCase() === email.toLowerCase())) {
    return res.status(409).json({ error: 'Correo ya registrado' });
  }
  const id = uuidv4();
  const d = Math.max(1, parseInt(days, 10) || 30);
  a.db.teachers[id] = {
    id,
    name: String(name).trim(),
    email: String(email).trim().toLowerCase(),
    password_hash: hashPw(password),
    school: (school || '').trim(),
    certificateEmail: String(email).trim().toLowerCase(),
    active: true,
    plan: plan || 'paid',
    subjects,
    validUntil: new Date(Date.now() + d * 86400000).toISOString(),
    classCode: ('C' + crypto.randomBytes(3).toString('hex')).toUpperCase(),
    createdAt: new Date().toISOString()
  };
  saveDb(a.db);
  res.json({ ok: true, teacher: publicTeacher(a.db.teachers[id]) });
});

app.get('/api/admin/backup', (req, res) => {
  const a = authAdmin(req); if (!a) return res.status(401).json({ error: 'No autorizado' });
  const backup = JSON.parse(JSON.stringify(a.db)); backup.sessions = {}; backup.studentSessions = {};
  res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.setHeader('Content-Disposition', 'attachment; filename="juegos-reto-respaldo.json"'); res.send(JSON.stringify(backup, null, 2));
});
// ---------- TEACHER ----------
app.get('/api/teacher/me', (req, res) => {
  const a = authTeacher(req);
  if (!a) return res.status(401).json({ error: 'No autorizado' });
  res.json({
    teacher: publicTeacher(a.teacher),
    access: licenseActive(a.teacher) ? 'granted' : 'blocked'
  });
});

app.post('/api/teacher/settings', (req, res) => {
  const a = authTeacher(req);
  if (!a) return res.status(401).json({ error: 'No autorizado' });
  if (!licenseActive(a.teacher)) {
    return res.status(403).json({ error: 'Licencia inactiva o vencida. No puede configurar hasta renovar.' });
  }
  const { certificateEmail, school, name } = req.body || {};
  if (certificateEmail) a.teacher.certificateEmail = String(certificateEmail).trim().toLowerCase();
  if (school !== undefined) a.teacher.school = String(school).trim();
  if (name) a.teacher.name = String(name).trim();
  saveDb(a.db);
  res.json({ ok: true, teacher: publicTeacher(a.teacher) });
});

// Comprobación de acceso para los juegos (el candado)
app.get('/api/access/check', (req, res) => {
  const classCode=(req.query.classCode||req.headers['x-class-code']||'').toString().toUpperCase(); const studentName=String(req.query.studentName||'').trim().slice(0,80); const bearer=String(req.headers.authorization||'').replace(/^Bearer\s+/i,''); const db=loadDb();
  if(bearer && db.studentSessions[bearer]){ const sess=db.studentSessions[bearer], t=db.teachers[sess.teacherId]; if(sess.expires>=Date.now()&&t&&licenseActive(t)) return res.json({allowed:true,mode:'student',accessToken:bearer,expiresAt:sess.expires,certificateEmail:t.certificateEmail||t.email,school:t.school||'',classCode:t.classCode,teacherName:t.name,studentName:sess.studentName,subjects:teacherSubjects(t)}); delete db.studentSessions[bearer]; saveDb(db); return res.json({allowed:false,reason:'license_inactive'}); }
  if(!classCode) return res.json({allowed:false,reason:'no_credentials'}); const t=Object.values(db.teachers).find(x=>(x.classCode||'')===classCode); if(!t) return res.json({allowed:false,reason:'invalid_class_code'}); if(!licenseActive(t)) return res.json({allowed:false,reason:'license_inactive'});
  let accessToken=null,expiresAt=null; if(studentName){accessToken=token();expiresAt=Date.now()+12*3600000;db.studentSessions[accessToken]={role:'student',teacherId:t.id,classCode,studentName,expires:expiresAt};saveDb(db);} return res.json({allowed:true,mode:'student',accessToken,expiresAt,certificateEmail:t.certificateEmail||t.email,school:t.school||'',classCode:t.classCode,teacherName:t.name,studentName,subjects:teacherSubjects(t)});
});
// Registro de resultado (para historial del profesor)
app.post('/api/results', (req, res) => {
  const { module, score, level, meta } = req.body || {}; const bearer=String(req.headers.authorization||'').replace(/^Bearer\s+/i,''); const db=loadDb(); const sess=db.studentSessions[bearer];
  if(!sess || sess.expires<Date.now()) return res.status(401).json({error:'Sesión estudiantil inválida o vencida'});
  const t=db.teachers[sess.teacherId]; if(!t || !licenseActive(t)) return res.status(403).json({error:'Licencia inactiva'});
  const row = {
    id: uuidv4(),
    teacherId: t.id,
    studentName: sess.studentName,
    module: String(module || '').trim(),
    score: score ?? null,
    level: level ?? null,
    meta: meta || {},
    at: new Date().toISOString()
  };
  db.results.push(row);
  // limitar historial
  if (db.results.length > 5000) db.results = db.results.slice(-4000);
  saveDb(db);
  res.json({
    ok: true,
    certificateEmail: t.certificateEmail || t.email,
    resultId: row.id
  });
});

app.get('/api/teacher/results', (req, res) => {
  const a = authTeacher(req);
  if (!a) return res.status(401).json({ error: 'No autorizado' });
  if (!licenseActive(a.teacher)) {
    return res.status(403).json({ error: 'Licencia inactiva' });
  }
  const list = a.db.results
    .filter((r) => r.teacherId === a.teacherId)
    .slice(-200)
    .reverse();
  res.json({ results: list });
});

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'fisica-saas-control', time: new Date().toISOString() });
});

// SPA fallback
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api')) return next();
  const file = path.join(PUBLIC, 'index.html');
  if (fs.existsSync(file)) return res.sendFile(file);
  res.status(404).send('Not found');
});

app.listen(PORT, () => {
  console.log('Física SaaS control en http://localhost:' + PORT);
});
