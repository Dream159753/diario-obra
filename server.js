// server.js
const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

const app = express();

const PORT = process.env.PORT || 10000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret-diario-obra';

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 12, // 12h
    },
  })
);

// ✅ Agora só publica a pasta /public
app.use(express.static(path.join(__dirname, 'public')));

// -------------------------
// Banco de dados (SQLite)
// -------------------------
const DB_FILE = path.join(__dirname, 'diario_obra.db');
const db = new Database(DB_FILE);

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','engenheiro','apontador')),
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS obras (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nome TEXT UNIQUE NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS diarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  data TEXT NOT NULL,
  obra TEXT NOT NULL,
  responsavel TEXT NOT NULL,
  observacoes TEXT
);

CREATE TABLE IF NOT EXISTS funcoes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  diario_id INTEGER NOT NULL,
  funcao TEXT NOT NULL,
  presentes INTEGER NOT NULL DEFAULT 0,
  ausentes  INTEGER NOT NULL DEFAULT 0,
  ferias    INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (diario_id) REFERENCES diarios(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS intercorrencias (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  diario_id INTEGER NOT NULL,
  codigo TEXT NOT NULL,
  descricao TEXT,
  FOREIGN KEY (diario_id) REFERENCES diarios(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ausentes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  diario_id INTEGER NOT NULL,
  chapa TEXT,
  nome TEXT,
  funcao TEXT,
  FOREIGN KEY (diario_id) REFERENCES diarios(id) ON DELETE CASCADE
);
`);

db.exec(`
CREATE INDEX IF NOT EXISTS idx_diarios_data         ON diarios(data);
CREATE INDEX IF NOT EXISTS idx_funcoes_diario       ON funcoes(diario_id);
CREATE INDEX IF NOT EXISTS idx_intercorrencias_did  ON intercorrencias(diario_id);
CREATE INDEX IF NOT EXISTS idx_intercorrencias_cod  ON intercorrencias(codigo);
CREATE INDEX IF NOT EXISTS idx_ausentes_diario      ON ausentes(diario_id);
CREATE INDEX IF NOT EXISTS idx_obras_nome           ON obras(nome);
`);

function ensureUser(email, pass, role) {
  const row = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (!row) {
    const hash = bcrypt.hashSync(pass, 10);
    db.prepare(
      'INSERT INTO users(email, password_hash, role, active) VALUES (?, ?, ?, 1)'
    ).run(email, hash, role);
    console.log(`Seed user criado: ${email} / ${pass} (${role})`);
  }
}
ensureUser('admin@obra.local', 'admin123', 'admin');
ensureUser('engenheiro@obra.local', '123456', 'engenheiro');
ensureUser('apontador@obra.local', '123456', 'apontador');

// CSV funcionários
const funcionarios = [];
(function loadFuncionarios() {
  try {
    const csvPath = path.join(__dirname, 'funcionarios.csv');
    if (!fs.existsSync(csvPath)) return;
    const raw = fs.readFileSync(csvPath, 'utf8');
    const linhas = raw.split(/\r?\n/);
    let l = 0;
    for (const ln of linhas) {
      const line = ln.trim();
      if (!line) continue;
      l++;
      if (l === 1 && /chapa/i.test(line) && /nome/i.test(line)) continue;
      const parts = line.split(/[;,]/).map(s => s.trim());
      if (parts.length < 3) continue;
      const [chapa, nome, funcao] = parts;
      if (!chapa) continue;
      funcionarios.push({ chapa: String(chapa).trim(), nome: (nome || '').trim(), funcao: (funcao || '').trim() });
    }
    console.log(`Carregados ${funcionarios.length} funcionários`);
  } catch (e) {
    console.error('Erro lendo funcionarios.csv:', e);
  }
})();

function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Não autenticado' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Acesso restrito a administradores.' });
  }
  next();
}
function requireEngenharia(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Não autenticado' });
  if (!['admin', 'engenheiro'].includes(req.session.user.role)) {
    return res.status(403).json({ error: 'Acesso restrito à engenharia.' });
  }
  next();
}

// LOGIN
app.post('/api/login', (req, res) => {
  const { email, senha } = req.body || {};
  if (!email || !senha) return res.status(400).json({ error: 'Informe email e senha.' });
  const u = db.prepare('SELECT * FROM users WHERE email = ? AND active = 1').get(email);
  if (!u) return res.status(401).json({ error: 'Usuário ou senha inválidos.' });
  if (!bcrypt.compareSync(String(senha), u.password_hash)) return res.status(401).json({ error: 'Usuário ou senha inválidos.' });
  req.session.user = { id: u.id, email: u.email, role: u.role };
  res.json({ ok: true, user: { email: u.email, role: u.role } });
});

app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.json({ user: null });
  res.json({ user: req.session.user });
});

// USERS (admin)
app.get('/api/users', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT id,email,role,active,created_at FROM users ORDER BY id').all();
  res.json(rows);
});
app.post('/api/users', requireAdmin, (req, res) => {
  const { email, senha, role } = req.body || {};
  if (!email || !senha || !role) return res.status(400).json({ error: 'Campos obrigatórios faltando.' });
  try {
    const hash = bcrypt.hashSync(senha, 10);
    db.prepare('INSERT INTO users(email,password_hash,role,active) VALUES(?,?,?,1)').run(email, hash, role);
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: 'Não foi possível criar o usuário.' });
  }
});
app.patch('/api/users/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const { role, active, senha } = req.body || {};
  try {
    if (senha) db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(senha, 10), id);
    if (role) db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, id);
    if (typeof active !== 'undefined') db.prepare('UPDATE users SET active = ? WHERE id = ?').run(active ? 1 : 0, id);
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: 'Falha ao atualizar usuário.' });
  }
});
app.delete('/api/users/:id', requireAdmin, (req, res) => {
  try {
    db.prepare('DELETE FROM users WHERE id = ?').run(Number(req.params.id));
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: 'Falha ao excluir usuário.' });
  }
});

// OBRAS
app.get('/api/obras', requireLogin, (req, res) => {
  const rows = db.prepare(`SELECT id,nome,active,created_at FROM obras WHERE active=1 ORDER BY LOWER(nome)`).all();
  res.json(rows);
});
app.get('/api/obras/all', requireAdmin, (req, res) => {
  const rows = db.prepare(`SELECT id,nome,active,created_at FROM obras ORDER BY active DESC, LOWER(nome)`).all();
  res.json(rows);
});
app.post('/api/obras', requireAdmin, (req, res) => {
  const nm = String((req.body||{}).nome || '').trim();
  if (!nm) return res.status(400).json({ error: 'Informe o nome da obra.' });
  try {
    db.prepare('INSERT INTO obras(nome, active) VALUES(?, 1)').run(nm);
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: 'Não foi possível cadastrar a obra (talvez já exista).' });
  }
});
app.patch('/api/obras/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const { nome, active } = req.body || {};
  try {
    if (typeof nome !== 'undefined') {
      const nm = String(nome || '').trim();
      if (!nm) return res.status(400).json({ error: 'Nome inválido.' });
      db.prepare('UPDATE obras SET nome = ? WHERE id = ?').run(nm, id);
    }
    if (typeof active !== 'undefined') {
      db.prepare('UPDATE obras SET active = ? WHERE id = ?').run(active ? 1 : 0, id);
    }
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: 'Falha ao atualizar obra.' });
  }
});
app.delete('/api/obras/:id', requireAdmin, (req, res) => {
  try {
    db.prepare('DELETE FROM obras WHERE id = ?').run(Number(req.params.id));
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: 'Falha ao excluir obra.' });
  }
});

// Funcionários
app.get('/api/funcionarios', requireLogin, (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q) return res.json([]);
  const isDigits = /^\d+$/.test(q);
  let matches = funcionarios.filter(f => f.chapa.startsWith(q));
  if (matches.length === 0 && !isDigits) {
    const qLower = q.toLowerCase();
    matches = funcionarios.filter(f => f.nome.toLowerCase().includes(qLower));
  }
  res.json(matches.slice(0, 30));
});

// Diários
app.post('/api/diarios', requireLogin, (req, res) => {
  try {
    const { data, obra, responsavel, observacoes, funcoes = [], intercorrencias = [], ausentes = [] } = req.body || {};
    if (!data || !obra || !responsavel) return res.status(400).json({ error: 'Campos obrigatórios faltando.' });

    const info = db.prepare(`INSERT INTO diarios(data,obra,responsavel,observacoes) VALUES (?,?,?,?)`)
      .run(data, obra, responsavel, observacoes || null);

    const diarioId = info.lastInsertRowid;

    const insF = db.prepare(`INSERT INTO funcoes(diario_id,funcao,presentes,ausentes,ferias) VALUES (?,?,?,?,?)`);
    for (const f of funcoes) {
      insF.run(diarioId, (f.funcao || '').trim(), Number(f.presente||f.presentes||0), Number(f.ausente||f.ausentes||0), Number(f.ferias||0));
    }

    const insI = db.prepare(`INSERT INTO intercorrencias(diario_id,codigo,descricao) VALUES (?,?,?)`);
    for (const i of intercorrencias) {
      if (!i || (!i.codigo && !i.descricao)) continue;
      insI.run(diarioId, String(i.codigo||'').trim(), String(i.descricao||'').trim());
    }

    const insA = db.prepare(`INSERT INTO ausentes(diario_id,chapa,nome,funcao) VALUES (?,?,?,?)`);
    for (const a of ausentes) {
      const chapa = String(a?.chapa||'').trim();
      const nome  = String(a?.nome||'').trim();
      const func  = String(a?.funcao||'').trim();
      if (!chapa && !nome && !func) continue;
      insA.run(diarioId, chapa || null, nome || null, func || null);
    }

    res.json({ ok: true, id: diarioId });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Falha ao salvar diário.' });
  }
});

app.get('/api/diarios/:id', requireLogin, (req, res) => {
  try {
    const id = Number(req.params.id);
    const d = db.prepare('SELECT * FROM diarios WHERE id = ?').get(id);
    if (!d) return res.status(404).json({ error: 'Diário não encontrado.' });

    const fun = db.prepare('SELECT funcao,presentes,ausentes,ferias FROM funcoes WHERE diario_id = ? ORDER BY funcao').all(id);
    const inc = db.prepare('SELECT codigo,descricao FROM intercorrencias WHERE diario_id = ? ORDER BY id').all(id);
    const aus = db.prepare('SELECT chapa,nome,funcao FROM ausentes WHERE diario_id = ? ORDER BY id').all(id);

    res.json({ ...d, funcoes: fun, intercorrencias: inc, ausentes: aus });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Falha ao buscar diário.' });
  }
});

// Rotas HTML (agora apontando para /public)
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/form', requireLogin, (_req, res) => res.sendFile(path.join(__dirname, 'public', 'form.html')));
app.get('/viewer', requireLogin, requireEngenharia, (_req, res) => res.sendFile(path.join(__dirname, 'public', 'viewer.html')));
app.get('/admin.html', requireLogin, requireAdmin, (_req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
