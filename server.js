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
const PUBLIC = path.join(__dirname, 'public');

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(PUBLIC));

function loadDb() {
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}
function saveDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf8');
}
function hashPw(pw, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const h = crypto.createHash('sha256').update(salt + pw).digest('hex');
  return salt + ':' + h;
}
function verifyPw(pw, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const h = crypto.createHash('sha256').update(salt + pw).digest('hex');
  return h === hash;
}
function token() {
  return crypto.randomBytes(32).toString('hex');
}
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
    licenseOk: licenseActive(t)
  };
}

// ---------- AUTH ----------
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body || {};
  const db = loadDb();
  if (username !== db.admin.username || !verifyPw(password || '', db.admin.password_hash)) {
    return res.status(401).json({ error: 'Credenciales de administrador incorrectas' });
  }
  const t = token();
  db.sessions[t] = { role: 'admin', expires: Date.now() + 12 * 3600 * 1000 };
  saveDb(db);
  res.json({ token: t, role: 'admin' });
});

app.post('/api/teacher/login', (req, res) => {
  const { email, password } = req.body || {};
  const db = loadDb();
  const entry = Object.values(db.teachers).find(
    (x) => (x.email || '').toLowerCase() === (email || '').toLowerCase()
  );
  if (!entry || !verifyPw(password || '', entry.password_hash)) {
    return res.status(401).json({ error: 'Correo o contraseña incorrectos' });
  }
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
  // Registro crea cuenta en prueba; admin debe activar/extender
  const { name, email, password, school } = req.body || {};
  if (!name || !email || !password || password.length < 6) {
    return res.status(400).json({ error: 'Nombre, correo y contraseña (mín. 6) son obligatorios' });
  }
  const db = loadDb();
  if (Object.values(db.teachers).some((x) => x.email.toLowerCase() === email.toLowerCase())) {
    return res.status(409).json({ error: 'Ese correo ya está registrado' });
  }
  const id = uuidv4();
  const classCode = ('C' + crypto.randomBytes(3).toString('hex')).toUpperCase();
  const trialDays = 7;
  const validUntil = new Date(Date.now() + trialDays * 86400000).toISOString();
  db.teachers[id] = {
    id,
    name: String(name).trim(),
    email: String(email).trim().toLowerCase(),
    password_hash: hashPw(password),
    school: (school || '').trim(),
    certificateEmail: String(email).trim().toLowerCase(),
    active: true,
    plan: 'trial',
    validUntil,
    classCode,
    createdAt: new Date().toISOString()
  };
  saveDb(db);
  res.json({
    ok: true,
    message: 'Cuenta creada. Prueba de ' + trialDays + ' días. Un administrador puede extender o suspender el acceso.',
    teacher: publicTeacher(db.teachers[id])
  });
});

// ---------- ADMIN ----------
app.get('/api/admin/teachers', (req, res) => {
  const a = authAdmin(req);
  if (!a) return res.status(401).json({ error: 'No autorizado' });
  const list = Object.values(a.db.teachers).map(publicTeacher);
  res.json({ teachers: list });
});

app.post('/api/admin/teachers/:id/activate', (req, res) => {
  const a = authAdmin(req);
  if (!a) return res.status(401).json({ error: 'No autorizado' });
  const t = a.db.teachers[req.params.id];
  if (!t) return res.status(404).json({ error: 'Profesor no encontrado' });
  const days = Math.max(1, parseInt(req.body.days, 10) || 30);
  const plan = req.body.plan || 'paid';
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
    validUntil: new Date(Date.now() + d * 86400000).toISOString(),
    classCode: ('C' + crypto.randomBytes(3).toString('hex')).toUpperCase(),
    createdAt: new Date().toISOString()
  };
  saveDb(a.db);
  res.json({ ok: true, teacher: publicTeacher(a.db.teachers[id]) });
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
  const classCode = (req.query.classCode || req.headers['x-class-code'] || '').toString().toUpperCase();
  const teacherToken = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const db = loadDb();

  // Profesor logueado
  if (teacherToken && db.sessions[teacherToken]) {
    const sess = db.sessions[teacherToken];
    if (sess.role === 'teacher' && sess.expires >= Date.now()) {
      const t = db.teachers[sess.teacherId];
      if (t && licenseActive(t)) {
        return res.json({
          allowed: true,
          mode: 'teacher',
          certificateEmail: t.certificateEmail || t.email,
          school: t.school || '',
          classCode: t.classCode,
          teacherName: t.name
        });
      }
      return res.json({ allowed: false, reason: 'license_inactive' });
    }
  }

  // Alumno con código de clase
  if (classCode) {
    const t = Object.values(db.teachers).find((x) => (x.classCode || '') === classCode);
    if (!t) return res.json({ allowed: false, reason: 'invalid_class_code' });
    if (!licenseActive(t)) return res.json({ allowed: false, reason: 'license_inactive' });
    return res.json({
      allowed: true,
      mode: 'student',
      certificateEmail: t.certificateEmail || t.email,
      school: t.school || '',
      classCode: t.classCode,
      teacherName: t.name
    });
  }

  res.json({ allowed: false, reason: 'no_credentials' });
});

// Registro de resultado (para historial del profesor)
app.post('/api/results', (req, res) => {
  const { classCode, studentName, module, score, level, meta } = req.body || {};
  const db = loadDb();
  const t = Object.values(db.teachers).find(
    (x) => (x.classCode || '') === String(classCode || '').toUpperCase()
  );
  if (!t || !licenseActive(t)) {
    return res.status(403).json({ error: 'No autorizado o licencia inactiva' });
  }
  const row = {
    id: uuidv4(),
    teacherId: t.id,
    studentName: String(studentName || 'Estudiante').trim(),
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
  console.log('Admin por defecto: admin / NewtonSaaS2026!  (cámbialo en producción)');
});
