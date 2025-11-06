// server.js
const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 10000;

// ------------------------------------------------------
// MIDDLEWARE BÁSICO
// ------------------------------------------------------
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'diario-obra-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 8 // 8 horas
    }
  })
);

// arquivos estáticos (html, css, js, csv, etc)
app.use(express.static(path.join(__dirname)));

// ------------------------------------------------------
// BANCO DE DADOS (better-sqlite3)
// ------------------------------------------------------
const dbPath = path.join(__dirname, 'diario_obra.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS usuarios (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    email     TEXT UNIQUE NOT NULL,
    senha     TEXT NOT NULL,
    perfil    TEXT NOT NULL CHECK (perfil IN ('admin','engenheiro','user')),
    ativo     INTEGER NOT NULL DEFAULT 1,
    criado_em TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS diarios (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    data        TEXT NOT NULL,
    obra        TEXT NOT NULL,
    responsavel TEXT NOT NULL,
    observacoes TEXT,
    payload     TEXT NOT NULL,
    criado_em   TEXT NOT NULL
  );
`);

// ------------------------------------------------------
// SEED DE USUÁRIOS
// ------------------------------------------------------
function seedUser(email, senha, perfil) {
  const exists = db
    .prepare('SELECT id FROM usuarios WHERE email = ?')
    .get(email);

  if (!exists) {
    const now = new Date().toISOString();
    db.prepare(
      'INSERT INTO usuarios (email, senha, perfil, ativo, criado_em) VALUES (?,?,?,?,?)'
    ).run(email, senha, perfil, 1, now);
    console.log(
      `Seed user criado: ${email} / ${senha} (${perfil})`
    );
  }
}

seedUser('admin@obra.local', 'admin123', 'admin');
seedUser('engenheiro@obra.local', '123456', 'engenheiro');

// ------------------------------------------------------
// CARREGAR FUNCIONÁRIOS DO CSV
// ------------------------------------------------------
const funcionarios = {};

function carregarFuncionarios() {
  try {
    const csvPath = path.join(__dirname, 'funcionarios.csv');
    if (!fs.existsSync(csvPath)) {
      console.log(
        `Nenhum arquivo funcionarios.csv encontrado na pasta ${__dirname}.`
      );
      return;
    }

    const raw = fs.readFileSync(csvPath, 'utf8');
    const linhas = raw.split(/\r?\n/).filter((l) => l.trim());
    if (linhas.length <= 1) return;

    const headerLine = linhas[0];
    const sep = headerLine.includes(';') ? ';' : ',';
    const headers = headerLine
      .split(sep)
      .map((h) => h.trim().toLowerCase());

    const idxChapa = headers.indexOf('chapa');
    const idxNome = headers.indexOf('nome');
    const idxFunc = headers.indexOf('funcao');

    if (idxChapa === -1 || idxNome === -1 || idxFunc === -1) {
      console.log(
        'Cabeçalho do funcionarios.csv não contém chapa/nome/funcao'
      );
      return;
    }

    for (let i = 1; i < linhas.length; i++) {
      const cols = linhas[i].split(sep);
      const chapa = (cols[idxChapa] || '').trim();
      const nome = (cols[idxNome] || '').trim();
      const funcao = (cols[idxFunc] || '').trim();

      if (!chapa) continue;
      funcionarios[chapa] = { chapa, nome, funcao };
    }

    console.log(
      `Carregados ${Object.keys(funcionarios).length} funcionários de ${csvPath}`
    );
  } catch (err) {
    console.error('Erro ao carregar funcionarios.csv:', err);
  }
}

carregarFuncionarios();

// ------------------------------------------------------
// HELPERS DE AUTENTICAÇÃO
// ------------------------------------------------------
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: 'Não autenticado' });
}

function requireAdmin(req, res, next) {
  if (req.session?.user?.perfil === 'admin') return next();
  return res
    .status(403)
    .json({ error: 'Acesso restrito a administradores.' });
}

// ------------------------------------------------------
// ROTAS ABERTAS (NÃO PRECISAM DE LOGIN)
// ------------------------------------------------------

// LOGIN
app.post('/api/login', (req, res) => {
  const { email, senha } = req.body || {};
  if (!email || !senha) {
    return res
      .status(400)
      .json({ error: 'Usuário e senha são obrigatórios.' });
  }

  const user = db
    .prepare(
      'SELECT id, email, senha, perfil, ativo FROM usuarios WHERE email = ?'
    )
    .get(email);

  if (!user || !user.ativo || user.senha !== senha) {
    return res
      .status(400)
      .json({ error: 'Usuário ou senha inválidos.' });
  }

  req.session.user = {
    id: user.id,
    email: user.email,
    perfil: user.perfil
  };

  res.json({
    ok: true,
    user: {
      id: user.id,
      email: user.email,
      perfil: user.perfil
    }
  });
});

// LOGOUT
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

// /api/me – pode ser público, só retorna null se não tiver login
app.get('/api/me', (req, res) => {
  res.json({ user: req.session.user || null });
});

// FUNCIONÁRIOS – AUTOCOMPLETE POR CHAPA/NOME
app.get('/api/funcionarios', (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q) return res.json([]);

  const qLower = q.toLowerCase();
  const todos = Object.values(funcionarios);

  const resultado = todos
    .filter(
      (f) =>
        f.chapa.startsWith(q) ||
        f.nome.toLowerCase().includes(qLower)
    )
    .slice(0, 20);

  res.json(resultado);
});

// FUNCIONÁRIO POR CHAPA
app.get('/api/funcionarios/:chapa', (req, res) => {
  const { chapa } = req.params;
  const f = funcionarios[chapa];
  if (!f) return res.status(404).json({ error: 'Não encontrado' });
  res.json(f);
});

// POST /api/diarios – LANÇAMENTO DO FORM (SEM LOGIN)
app.post('/api/diarios', (req, res) => {
  try {
    const payload = req.body || {};
    const { obra, responsavel, data, observacoes } = payload;

    if (!obra || !responsavel || !data) {
      return res
        .status(400)
        .json({ error: 'Campos obrigatórios faltando.' });
    }

    const now = new Date().toISOString();
    const stmt = db.prepare(
      'INSERT INTO diarios (data, obra, responsavel, observacoes, payload, criado_em) VALUES (?,?,?,?,?,?)'
    );
    const info = stmt.run(
      data,
      obra,
      responsavel,
      observacoes || '',
      JSON.stringify(payload),
      now
    );

    res.json({ ok: true, id: info.lastInsertRowid });
  } catch (err) {
    console.error('Erro ao salvar diário:', err);
    res.status(500).json({ error: 'Falha ao salvar diário.' });
  }
});

// ------------------------------------------------------
// A PARTIR DAQUI, TUDO EM /api PRECISA DE LOGIN
// ------------------------------------------------------
app.use('/api', requireAuth);

// LISTAR USUÁRIOS (ADMIN)
app.get('/api/users', requireAdmin, (req, res) => {
  const rows = db
    .prepare(
      'SELECT id, email, perfil, ativo, criado_em FROM usuarios ORDER BY id'
    )
    .all();
  res.json(rows);
});

// CRIAR NOVO USUÁRIO (ADMIN)
app.post('/api/users', requireAdmin, (req, res) => {
  const { email, senhaInicial, perfil } = req.body || {};
  if (!email || !senhaInicial || !perfil) {
    return res
      .status(400)
      .json({ error: 'Campos obrigatórios faltando.' });
  }

  try {
    const now = new Date().toISOString();
    const stmt = db.prepare(
      'INSERT INTO usuarios (email, senha, perfil, ativo, criado_em) VALUES (?,?,?,?,?)'
    );
    const info = stmt.run(email, senhaInicial, perfil, 1, now);
    res.json({
      ok: true,
      user: {
        id: info.lastInsertRowid,
        email,
        perfil,
        ativo: 1,
        criado_em: now
      }
    });
  } catch (err) {
    if (String(err.message).includes('UNIQUE')) {
      return res
        .status(400)
        .json({ error: 'Já existe usuário com esse e-mail.' });
    }
    console.error('Erro ao criar usuário:', err);
    res.status(500).json({ error: 'Falha ao criar usuário.' });
  }
});

// ATUALIZAR USUÁRIO (ADMIN) – PUT ou PATCH
function handleUpdateUser(req, res) {
  const { id } = req.params;
  const { email, senhaNova, perfil, ativo } = req.body || {};
  const user = db
    .prepare('SELECT * FROM usuarios WHERE id = ?')
    .get(id);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });

  const updates = [];
  const params = [];

  if (email) {
    updates.push('email = ?');
    params.push(email);
  }
  if (senhaNova) {
    updates.push('senha = ?');
    params.push(senhaNova);
  }
  if (perfil) {
    updates.push('perfil = ?');
    params.push(perfil);
  }
  if (typeof ativo !== 'undefined') {
    updates.push('ativo = ?');
    params.push(ativo ? 1 : 0);
  }

  if (!updates.length) {
    return res.json({ ok: true }); // nada a mudar
  }

  params.push(id);
  const sql = `UPDATE usuarios SET ${updates.join(', ')} WHERE id = ?`;
  db.prepare(sql).run(...params);

  res.json({ ok: true });
}

app.put('/api/users/:id', requireAdmin, handleUpdateUser);
app.patch('/api/users/:id', requireAdmin, handleUpdateUser);

// BUSCAR DIÁRIOS (CURADORIA)
app.get('/api/diarios', (req, res) => {
  const { obra, responsavel, de, ate, codInter, texto } = req.query;

  const rows = db
    .prepare(
      'SELECT id, data, obra, responsavel, observacoes, payload, criado_em FROM diarios ORDER BY data DESC, id DESC'
    )
    .all();

  const cod = (codInter || '').trim();
  const textoBusca = (texto || '').trim().toLowerCase();

  const filtrados = rows.filter((row) => {
    const p = JSON.parse(row.payload || '{}');

    if (obra && !row.obra.toLowerCase().includes(obra.toLowerCase())) {
      return false;
    }
    if (
      responsavel &&
      !row.responsavel
        .toLowerCase()
        .includes(responsavel.toLowerCase())
    ) {
      return false;
    }
    if (de && row.data < de) return false;
    if (ate && row.data > ate) return false;

    if (cod) {
      const temCod = Array.isArray(p.intercorrencias)
        ? p.intercorrencias.some(
            (i) => String(i.codigo || '') === String(cod)
          )
        : false;
      if (!temCod) return false;
    }

    if (textoBusca) {
      const campo = (
        row.observacoes ||
        '' +
          JSON.stringify(p.intercorrencias || []) +
          JSON.stringify(p.ausentes || [])
      ).toLowerCase();
      if (!campo.includes(textoBusca)) return false;
    }

    return true;
  });

  const resumo = filtrados.map((row) => {
    const p = JSON.parse(row.payload || '{}');
    let presentes = 0;
    let ausentes = 0;
    let ferias = 0;

    if (Array.isArray(p.funcoes)) {
      for (const f of p.funcoes) {
        presentes += Number(f.presente || 0);
        ausentes += Number(f.ausente || 0);
        ferias += Number(f.ferias || 0);
      }
    }

    return {
      id: row.id,
      data: row.data,
      obra: row.obra,
      responsavel: row.responsavel,
      presentes,
      ausentes,
      ferias
    };
  });

  res.json(resumo);
});

// DETALHE DE UM DIÁRIO
app.get('/api/diarios/:id', (req, res) => {
  const { id } = req.params;
  const row = db
    .prepare(
      'SELECT id, data, obra, responsavel, observacoes, payload, criado_em FROM diarios WHERE id = ?'
    )
    .get(id);

  if (!row) return res.status(404).json({ error: 'Não encontrado.' });

  const payload = JSON.parse(row.payload || '{}');
  res.json({ ...row, ...payload });
});

// ------------------------------------------------------
// START
// ------------------------------------------------------
app.listen(PORT, () => {
  console.log(`API rodando em http://localhost:${PORT}`);
});
