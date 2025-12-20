// server.js
// Diário de Obra – API (Express + better-sqlite3)
// -----------------------------------------------

const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

const app = express();

// -------------------------
// Configurações básicas
// -------------------------
const PORT = process.env.PORT || 10000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret-diario-obra';

// Middlewares
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

// Conteúdo estático (HTML/JS/CSS)
app.use(express.static(path.join(__dirname)));

// -------------------------
// Banco de dados (SQLite)
// -------------------------
const DB_FILE = path.join(__dirname, 'diario_obra.db');
const db = new Database(DB_FILE);

// Criação de tabelas
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','engenheiro')),
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS diarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  data TEXT NOT NULL,              -- ISO: YYYY-MM-DD
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
`);

// (Opcional) Índices para desempenho
db.exec(`
CREATE INDEX IF NOT EXISTS idx_diarios_data         ON diarios(data);
CREATE INDEX IF NOT EXISTS idx_funcoes_diario       ON funcoes(diario_id);
CREATE INDEX IF NOT EXISTS idx_intercorrencias_did  ON intercorrencias(diario_id);
CREATE INDEX IF NOT EXISTS idx_intercorrencias_cod  ON intercorrencias(codigo);
`);

// Seeds de usuários
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

// --------------------------------------------------
// Carregamento do CSV de funcionários em memória
// --------------------------------------------------
/**
 * Espera CSV com cabeçalho: chapa;nome;funcao (ou vírgula)
 * Exemplo:
 *   20019;JOSE HADONIAS ALVES PINHEIRO;CARPINTEIRO
 */
const funcionarios = [];
(function loadFuncionarios() {
  try {
    const csvPath = path.join(__dirname, 'funcionarios.csv');
    if (!fs.existsSync(csvPath)) {
      console.warn('Nenhum arquivo funcionarios.csv encontrado na pasta do projeto.');
      return;
    }
    const raw = fs.readFileSync(csvPath, 'utf8');
    const linhas = raw.split(/\r?\n/);
    let l = 0;
    for (const ln of linhas) {
      const line = ln.trim();
      if (!line) continue;
      l++;
      if (l === 1 && /chapa/i.test(line) && /nome/i.test(line)) {
        // Cabeçalho – ignora
        continue;
      }
      // divide por ; ou ,
      const parts = line.split(/[;,]/).map(s => s.trim());
      if (parts.length < 3) continue;
      const [chapa, nome, funcao] = parts;
      if (!chapa) continue;
      funcionarios.push({
        chapa: String(chapa).trim(),
        nome: (nome || '').trim(),
        funcao: (funcao || '').trim(),
      });
    }
    console.log(`Carregados ${funcionarios.length} funcionários de ${csvPath}`);
  } catch (e) {
    console.error('Erro lendo funcionarios.csv:', e);
  }
})();

// --------------------------------------------------
// Helpers de autenticação/autorização
// --------------------------------------------------
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Não autenticado' });
  }
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Acesso restrito a administradores.' });
  }
  next();
}

// --------------------------------------------------
// Rotas de sessão / usuários
// --------------------------------------------------
app.post('/api/login', (req, res) => {
  const { email, senha } = req.body || {};
  if (!email || !senha) {
    return res.status(400).json({ error: 'Informe email e senha.' });
  }
  const u = db.prepare('SELECT * FROM users WHERE email = ? AND active = 1').get(email);
  if (!u) return res.status(401).json({ error: 'Usuário ou senha inválidos.' });
  const ok = bcrypt.compareSync(String(senha), u.password_hash);
  if (!ok) return res.status(401).json({ error: 'Usuário ou senha inválidos.' });

  req.session.user = { id: u.id, email: u.email, role: u.role };
  return res.json({ ok: true, user: { email: u.email, role: u.role } });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.json({ user: null });
  res.json({ user: req.session.user });
});

// Administração de usuários
app.get('/api/users', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT id,email,role,active,created_at FROM users ORDER BY id').all();
  res.json(rows);
});

app.post('/api/users', requireAdmin, (req, res) => {
  const { email, senha, role } = req.body || {};
  if (!email || !senha || !role) {
    return res.status(400).json({ error: 'Campos obrigatórios faltando.' });
  }
  try {
    const hash = bcrypt.hashSync(senha, 10);
    db.prepare('INSERT INTO users(email,password_hash,role,active) VALUES(?,?,?,1)')
      .run(email, hash, role);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: 'Não foi possível criar o usuário.' });
  }
});

app.patch('/api/users/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const { role, active, senha } = req.body || {};
  try {
    if (senha) {
      const hash = bcrypt.hashSync(senha, 10);
      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, id);
    }
    if (role) {
      db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, id);
    }
    if (typeof active !== 'undefined') {
      db.prepare('UPDATE users SET active = ? WHERE id = ?').run(active ? 1 : 0, id);
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: 'Falha ao atualizar usuário.' });
  }
});

// --------------------------------------------------
// Funcionários (auto-complete por chapa / prefixo)
// --------------------------------------------------
app.get('/api/funcionarios', requireLogin, (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q) return res.json([]);
  const isDigits = /^\d+$/.test(q);

  // Busca por chapa (prefixo) primeiro
  let matches = funcionarios.filter(f => f.chapa.startsWith(q));

  // Se nada, tenta por nome (contém)
  if (matches.length === 0 && !isDigits) {
    const qLower = q.toLowerCase();
    matches = funcionarios.filter(f => f.nome.toLowerCase().includes(qLower));
  }

  // Limita a 30 resultados
  res.json(matches.slice(0, 30));
});

// --------------------------------------------------
// Diários – criação e leitura
// --------------------------------------------------

// Cria/salva um diário
app.post('/api/diarios', requireLogin, (req, res) => {
  try {
    const {
      data,          // 'YYYY-MM-DD'
      obra,
      responsavel,
      observacoes,
      funcoes = [],          // [{funcao, presentes, ausentes, ferias}]
      intercorrencias = [],  // [{codigo, descricao}]
    } = req.body || {};

    if (!data || !obra || !responsavel) {
      return res.status(400).json({ error: 'Campos obrigatórios faltando.' });
    }

    const insD = db.prepare(
      `INSERT INTO diarios(data,obra,responsavel,observacoes) VALUES (?,?,?,?)`
    );
    const info = insD.run(data, obra, responsavel, observacoes || null);
    const diarioId = info.lastInsertRowid;

    const insF = db.prepare(
      `INSERT INTO funcoes(diario_id,funcao,presentes,ausentes,ferias) VALUES (?,?,?,?,?)`
    );
    for (const f of funcoes) {
      insF.run(
        diarioId,
        (f.funcao || '').trim(),
        Number(f.presentes || 0),
        Number(f.ausentes || 0),
        Number(f.ferias || 0)
      );
    }

    const insI = db.prepare(
      `INSERT INTO intercorrencias(diario_id,codigo,descricao) VALUES (?,?,?)`
    );
    for (const i of intercorrencias) {
      if (!i || !i.codigo) continue;
      insI.run(diarioId, String(i.codigo).trim(), (i.descricao || '').trim());
    }

    res.json({ ok: true, id: diarioId });
  } catch (e) {
    console.error('POST /api/diarios erro:', e);
    res.status(500).json({ error: 'Falha ao salvar diário.' });
  }
});

// LISTA DIÁRIOS (com filtro por intercorrência, obra, responsável e datas)
app.get('/api/diarios', requireLogin, (req, res) => {
  try {
    const obra = (req.query.obra || '').trim();
    const responsavel = (req.query.responsavel || '').trim();

    // Aceita vários nomes para compatibilidade
    const codigoParam =
      (req.query.codigo_intercorrencia ||
        req.query.codigo ||
        req.query.cod ||
        req.query.intercorrencia ||
        '').trim();
    const codigo = codigoParam || null;

    const dataDe = (req.query.dataDe || req.query.data_de || '').trim();
    const dataAte = (req.query.dataAte || req.query.data_ate || '').trim();

    let sql = `
      SELECT
        d.id,
        d.data,
        d.obra,
        d.responsavel,
        COALESCE(SUM(f.presentes), 0) AS presentes,
        COALESCE(SUM(f.ausentes),  0) AS ausentes,
        COALESCE(SUM(f.ferias),    0) AS ferias
      FROM diarios d
      LEFT JOIN funcoes f ON f.diario_id = d.id
      WHERE 1=1
    `;
    const params = {};

    if (obra) {
      sql += ` AND LOWER(d.obra) LIKE LOWER(@obra) `;
      params.obra = `%${obra}%`;
    }
    if (responsavel) {
      sql += ` AND LOWER(d.responsavel) LIKE LOWER(@responsavel) `;
      params.responsavel = `%${responsavel}%`;
    }
    if (dataDe) {
      sql += ` AND DATE(d.data) >= DATE(@dataDe) `;
      params.dataDe = dataDe;
    }
    if (dataAte) {
      sql += ` AND DATE(d.data) <= DATE(@dataAte) `;
      params.dataAte = dataAte;
    }
    if (codigo) {
      sql += `
        AND EXISTS (
          SELECT 1
          FROM intercorrencias ic
          WHERE ic.diario_id = d.id
            AND TRIM(ic.codigo) = TRIM(@codigo)
        )
      `;
      params.codigo = codigo;
    }

    sql += `
      GROUP BY d.id
      ORDER BY DATE(d.data) DESC, d.id DESC
    `;

    const rows = db.prepare(sql).all(params);

    const out = rows.map(r => {
      let dataBr = '';
      try {
        const dt = new Date(r.data);
        if (!isNaN(dt.getTime())) {
          const dd = String(dt.getDate()).padStart(2, '0');
          const mm = String(dt.getMonth() + 1).padStart(2, '0');
          const yy = dt.getFullYear();
          dataBr = `${dd}/${mm}/${yy}`;
        }
      } catch {}
      return { ...r, dataBr };
    });

    res.json(out);
  } catch (e) {
    console.error('GET /api/diarios erro:', e);
    res.status(500).json({ error: 'Falha ao listar diários.' });
  }
});

// Detalhe de um diário
app.get('/api/diarios/:id', requireLogin, (req, res) => {
  try {
    const id = Number(req.params.id);
    const d = db.prepare('SELECT * FROM diarios WHERE id = ?').get(id);
    if (!d) return res.status(404).json({ error: 'Diário não encontrado.' });

    const fun = db.prepare(
      'SELECT funcao,presentes,ausentes,ferias FROM funcoes WHERE diario_id = ? ORDER BY funcao'
    ).all(id);

    const inc = db.prepare(
      'SELECT codigo,descricao FROM intercorrencias WHERE diario_id = ? ORDER BY id'
    ).all(id);

    res.json({ ...d, funcoes: fun, intercorrencias: inc });
  } catch (e) {
    console.error('GET /api/diarios/:id erro:', e);
    res.status(500).json({ error: 'Falha ao buscar diário.' });
  }
});

// -----------------------------------------------
// Fallback para arquivos HTML (roteamento simples)
// -----------------------------------------------
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('/login', (_req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});
app.get('/form', requireLogin, (_req, res) => {
  res.sendFile(path.join(__dirname, 'form.html'));
});
app.get('/viewer', requireLogin, (_req, res) => {
  res.sendFile(path.join(__dirname, 'viewer.html'));
});
app.get('/admin.html', requireLogin, requireAdmin, (_req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// -------------------------
// Inicialização do servidor
// -------------------------
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
  console.log(`--> http://localhost:${PORT}`);
});
