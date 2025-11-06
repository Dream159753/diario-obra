const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const { parse } = require('csv-parse/sync');

const PORT = process.env.PORT || 10000;
const DB_FILE = process.env.DB_FILE || 'diario_obra.db';
const FUNCIONARIOS_GLOB = /^funcionarios.*\.csv$/i;

const app = express();

// ---------- MIDDLEWARE BÁSICO ----------
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'diario-obra-super-secreto',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 8 // 8 horas
  }
}));

// servir arquivos estáticos (HTML + assets da pasta atual)
app.use(express.static(path.join(__dirname)));

// ---------- BANCO DE DADOS ----------
const db = new Database(DB_FILE);

// cria tabelas se não existirem
db.exec(`
  CREATE TABLE IF NOT EXISTS usuarios (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT NOT NULL UNIQUE,
    senha_hash  TEXT NOT NULL,
    perfil      TEXT NOT NULL DEFAULT 'user', -- admin | engenheiro | user
    ativo       INTEGER NOT NULL DEFAULT 1,
    criado_em   TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS diarios (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    data            TEXT NOT NULL,
    obra            TEXT NOT NULL,
    responsavel     TEXT NOT NULL,
    observacoes     TEXT,
    funcoes_json    TEXT NOT NULL,
    ausentes_json   TEXT NOT NULL,
    interc_json     TEXT NOT NULL,
    criado_em       TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  );
`);

// ---------- SEED / CORREÇÃO DE USUÁRIOS PADRÃO ----------
function seedUser(email, senha, perfil) {
  const existente = db.prepare('SELECT id, perfil, ativo FROM usuarios WHERE email = ?').get(email);

  if (!existente) {
    const hash = bcrypt.hashSync(senha, 10);
    db.prepare(
      'INSERT INTO usuarios (email, senha_hash, perfil, ativo) VALUES (?, ?, ?, 1)'
    ).run(email, hash, perfil);
    console.log(`Seed user criado: ${email} / ${senha} (${perfil})`);
  } else {
    // Garante perfil correto e ativo=1 (não mexe na senha)
    db.prepare('UPDATE usuarios SET perfil = ?, ativo = 1 WHERE id = ?')
      .run(perfil, existente.id);
    console.log(`Seed user ajustado: ${email} -> perfil=${perfil}, ativo=1`);
  }
}

seedUser('admin@obra.local',      'admin123', 'admin');
seedUser('engenheiro@obra.local', '123456',   'engenheiro');

// ---------- AUTENTICAÇÃO / SESSÃO ----------
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Não autenticado' });
  }

  try {
    const user = db
      .prepare('SELECT id, perfil, ativo FROM usuarios WHERE id = ?')
      .get(req.session.userId);

    if (!user || !user.ativo) {
      return res.status(401).json({ error: 'Sessão inválida.' });
    }

    req.session.perfil = user.perfil;
    next();
  } catch (err) {
    console.error('Erro em requireLogin:', err);
    return res.status(500).json({ error: 'Erro de sessão.' });
  }
}

// (Deixei aqui se um dia quiser voltar a travar pelo backend)
function requireAdmin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Não autenticado' });
  }
  try {
    const user = db
      .prepare('SELECT id, perfil, ativo FROM usuarios WHERE id = ?')
      .get(req.session.userId);

    if (!user || !user.ativo || user.perfil !== 'admin') {
      return res.status(403).json({ error: 'Acesso negado' });
    }

    req.session.perfil = user.perfil;
    next();
  } catch (err) {
    console.error('Erro em requireAdmin:', err);
    return res.status(500).json({ error: 'Erro de sessão.' });
  }
}

// rota de login
app.post('/api/login', (req, res) => {
  const { email, usuario, senha } = req.body || {};

  const loginEmail = (email || usuario || '').trim();
  const senhaStr   = (senha || '').toString();

  if (!loginEmail || !senhaStr) {
    return res.status(400).json({ error: 'Usuário e senha são obrigatórios.' });
  }

  try {
    const user = db
      .prepare('SELECT id, email, senha_hash, perfil, ativo FROM usuarios WHERE email = ?')
      .get(loginEmail);

    if (!user || !user.ativo) {
      return res.status(401).json({ error: 'Usuário ou senha inválidos.' });
    }

    const ok = bcrypt.compareSync(senhaStr, user.senha_hash);
    if (!ok) {
      return res.status(401).json({ error: 'Usuário ou senha inválidos.' });
    }

    req.session.userId = user.id;
    req.session.perfil = user.perfil;

    return res.json({ ok: true, perfil: user.perfil });
  } catch (err) {
    console.error('Erro no login:', err);
    return res.status(500).json({ error: 'Erro ao efetuar login.' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.get('/api/me', (req, res) => {
  if (!req.session.userId) {
    return res.json({ user: null });
  }
  const user = db
    .prepare('SELECT id, email, perfil, ativo, criado_em FROM usuarios WHERE id = ?')
    .get(req.session.userId);
  if (!user || !user.ativo) {
    return res.json({ user: null });
  }
  res.json({ user });
});

// ---------- ADMIN: USUÁRIOS ----------
// ⚠️ AGORA SÓ EXIGE LOGIN (admin ou engenheiro); o admin.html decide quem vê o quê.
app.get('/api/users', requireLogin, (req, res) => {
  try {
    const rows = db.prepare('SELECT id, email, perfil, ativo, criado_em FROM usuarios ORDER BY id').all();
    res.json({ users: rows });
  } catch (err) {
    console.error('Erro /api/users:', err);
    res.status(500).json({ error: 'Erro ao listar usuários.' });
  }
});

app.post('/api/users', requireLogin, (req, res) => {
  const { email, senha, perfil } = req.body || {};
  if (!email || !senha || !perfil) {
    return res.status(400).json({ error: 'Campos obrigatórios faltando.' });
  }
  try {
    const hash = bcrypt.hashSync(senha.toString(), 10);
    const info = db
      .prepare('INSERT INTO usuarios (email, senha_hash, perfil, ativo) VALUES (?, ?, ?, 1)')
      .run(email.trim(), hash, perfil);
    res.json({ ok: true, id: info.lastInsertRowid });
  } catch (err) {
    console.error('Erro POST /api/users:', err);
    if (String(err).includes('UNIQUE')) {
      return res.status(409).json({ error: 'Já existe um usuário com este e-mail.' });
    }
    res.status(500).json({ error: 'Erro ao criar usuário.' });
  }
});

app.patch('/api/users/:id', requireLogin, (req, res) => {
  const id = Number(req.params.id);
  const { perfil, ativo } = req.body || {};
  if (!id || !perfil || typeof ativo === 'undefined') {
    return res.status(400).json({ error: 'Campos obrigatórios faltando.' });
  }
  try {
    db.prepare('UPDATE usuarios SET perfil = ?, ativo = ? WHERE id = ?')
      .run(perfil, ativo ? 1 : 0, id);
    res.json({ ok: true });
  } catch (err) {
    console.error('Erro PATCH /api/users/:id', err);
    res.status(500).json({ error: 'Erro ao atualizar usuário.' });
  }
});

app.post('/api/users/:id/reset-password', requireLogin, (req, res) => {
  const id = Number(req.params.id);
  const { novaSenha } = req.body || {};
  if (!id || !novaSenha) {
    return res.status(400).json({ error: 'Campos obrigatórios faltando.' });
  }
  try {
    const hash = bcrypt.hashSync(novaSenha.toString(), 10);
    db.prepare('UPDATE usuarios SET senha_hash = ? WHERE id = ?').run(hash, id);
    res.json({ ok: true });
  } catch (err) {
    console.error('Erro reset-password:', err);
    res.status(500).json({ error: 'Erro ao trocar senha.' });
  }
});

// ---------- FUNCIONÁRIOS (CSV) ----------
let funcionariosIndex = new Map();

function carregarFuncionarios() {
  funcionariosIndex = new Map();
  try {
    const arquivos = fs.readdirSync(__dirname)
      .filter(f => FUNCIONARIOS_GLOB.test(f));

    if (!arquivos.length) {
      console.log(`Nenhum arquivo funcionarios*.csv encontrado na pasta ${__dirname}.`);
      return;
    }

    const caminho = path.join(__dirname, arquivos[0]);
    const conteudo = fs.readFileSync(caminho);
    const registros = parse(conteudo, {
      columns: true,
      skip_empty_lines: true,
      delimiter: ';'
    });

    for (const row of registros) {
      const chapa = String(row.chapa || row.Chapa || '').trim();
      const nome = String(row.nome || row.Nome || '').trim();
      const funcao = String(row.funcao || row.funcao_simplificada || row.FUNCAO || '').trim();
      if (!chapa) continue;
      funcionariosIndex.set(chapa, {
        chapa,
        nome,
        funcao
      });
    }

    console.log(`Carregados ${funcionariosIndex.size} funcionários de ${caminho}`);
  } catch (err) {
    console.error('Erro ao carregar funcionarios CSV:', err);
  }
}

carregarFuncionarios();

app.get('/api/funcionarios/:chapa', requireLogin, (req, res) => {
  const chapa = String(req.params.chapa || '').trim();
  if (!chapa) return res.status(400).json({ error: 'Chapa obrigatória.' });

  const func = funcionariosIndex.get(chapa);
  if (!func) {
    return res.status(404).json({ error: 'Funcionário não encontrado.' });
  }
  res.json(func);
});

app.get('/api/funcionarios', requireLogin, (req, res) => {
  const q = String(req.query.q || '').trim();
  if (!q) {
    return res.json([]);
  }
  const termo = q.toLowerCase();
  const out = [];
  for (const f of funcionariosIndex.values()) {
    if (f.chapa.includes(q) || (f.nome && f.nome.toLowerCase().includes(termo))) {
      out.push(f);
      if (out.length >= 20) break;
    }
  }
  res.json(out);
});

// ---------- DIÁRIOS ----------
app.post('/api/diarios', requireLogin, (req, res) => {
  const { obra, responsavel, data, observacoes, funcoes, ausentes, intercorrencias } = req.body || {};

  if (!obra || !responsavel || !data) {
    return res.status(400).json({ error: 'Obra, responsável e data são obrigatórios.' });
  }

  // trava: pelo menos 1 intercorrência (pode ser código 0 = sem intercorrência)
  if (!Array.isArray(intercorrencias) || intercorrencias.length === 0) {
    return res.status(400).json({ error: 'Informe pelo menos uma intercorrência.' });
  }

  try {
    const info = db.prepare(`
      INSERT INTO diarios (obra, responsavel, data, observacoes, funcoes_json, ausentes_json, interc_json)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      obra.trim(),
      responsavel.trim(),
      data,
      (observacoes || '').trim(),
      JSON.stringify(funcoes || []),
      JSON.stringify(ausentes || []),
      JSON.stringify(intercorrencias || [])
    );

    res.json({ ok: true, id: info.lastInsertRowid });
  } catch (err) {
    console.error('Erro ao salvar diário:', err);
    res.status(500).json({ error: 'Erro ao salvar diário.' });
  }
});

app.get('/api/diarios', requireLogin, (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT id, obra, responsavel, data, observacoes, funcoes_json, ausentes_json, interc_json, criado_em
      FROM diarios
      ORDER BY data DESC, id DESC
      LIMIT 500
    `).all();

    const parsed = rows.map(r => ({
      id: r.id,
      obra: r.obra,
      responsavel: r.responsavel,
      data: r.data,
      observacoes: r.observacoes,
      funcoes: JSON.parse(r.funcoes_json || '[]'),
      ausentes: JSON.parse(r.ausentes_json || '[]'),
      intercorrencias: JSON.parse(r.interc_json || '[]'),
      criado_em: r.criado_em
    }));

    res.json({ diarios: parsed });
  } catch (err) {
    console.error('Erro /api/diarios:', err);
    res.status(500).json({ error: 'Erro ao listar diários.' });
  }
});

// ---------- ROTAS DE PÁGINA SIMPLES ----------
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/form', (req, res) => {
  res.sendFile(path.join(__dirname, 'form.html'));
});

app.get('/viewer', (req, res) => {
  res.sendFile(path.join(__dirname, 'viewer.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

// ---------- START ----------
app.listen(PORT, () => {
  console.log(`API rodando em http://localhost:${PORT}`);
});
