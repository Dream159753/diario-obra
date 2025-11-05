// server.js — Diário de Obra (auth + gestão de usuários)
const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const { parse } = require('csv-parse/sync');

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true })); // aceita forms também

// ===== Sessão =====
app.use(session({
  name: 'diario.sid',
  secret: process.env.SESSION_SECRET || 'mude-esta-secret-antes-de-produzir',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 1000*60*60*8 }
}));

// ===== DB =====
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, 'diario_obra.db');
const db = new Database(DB_PATH);
db.exec(`
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS diario (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  obra TEXT NOT NULL,
  responsavel TEXT NOT NULL,
  data TEXT NOT NULL,
  observacoes TEXT
);
CREATE TABLE IF NOT EXISTS funcoes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  diario_id INTEGER NOT NULL,
  funcao TEXT NOT NULL,
  presente INTEGER DEFAULT 0,
  ausente INTEGER DEFAULT 0,
  ferias INTEGER DEFAULT 0,
  FOREIGN KEY (diario_id) REFERENCES diario(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS intercorrencia (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  diario_id INTEGER NOT NULL,
  codigo INTEGER,
  descricao TEXT,
  FOREIGN KEY (diario_id) REFERENCES diario(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS funcionarios (
  chapa   TEXT PRIMARY KEY,
  nome    TEXT,
  funcao  TEXT
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user'
);
`);

// ===== Seeds de usuários (admin + engenheiro) =====
function seedUsers(){
  const defaults = [
    { name:'Administrador', email:'admin@obra.local',      password:'admin123', role:'admin' },
    { name:'Engenheiro',    email:'engenheiro@obra.local', password:'123456',  role:'user'  }
  ];
  const findByEmail = db.prepare(`SELECT id FROM users WHERE email=?`);
  const insertUser  = db.prepare(`INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,?)`);

  for (const u of defaults){
    const found = findByEmail.get(u.email);
    if (!found){
      const hash = bcrypt.hashSync(u.password, 10);
      insertUser.run(u.name, u.email, hash, u.role);
      console.log(`Seed user: ${u.email} / ${u.password}`);
    }
  }
}
seedUsers();

// ===== Seed Funcionários de CSV (opcional) =====
function seedFuncionariosCSV(){
  try{
    const csvPath = path.join(__dirname, 'funcionarios.csv');
    if(!fs.existsSync(csvPath)) return;
    const buf = fs.readFileSync(csvPath);
    const rows = parse(buf.toString(), { columns: true, skip_empty_lines: true, delimiter: ';' });
    const insert = db.prepare(`INSERT OR REPLACE INTO funcionarios (chapa,nome,funcao) VALUES (?,?,?)`);
    const insertMany = db.transaction((list)=>{
      for(const r of list){
        const chapa = String(r.chapa || r.Chapa || '').trim();
        const nome  = String(r.nome  || r.Nome  || '').trim();
        const func  = String(r.funcao|| r.Função|| r.Funcao || '').trim();
        if(chapa) insert.run(chapa, nome, func);
      }
    });
    insertMany(rows);
    console.log(`Seed: ${rows.length} funcionários do CSV`);
  }catch(err){
    console.log('Seed funcionarios CSV ignorado:', err.message);
  }
}
seedFuncionariosCSV();

// ===== Helpers de auth =====
function requireAuth(req,res,next){
  if(!req.session.user) return res.status(401).json({ error:'Não autenticado' });
  next();
}
function requireRole(role){
  return (req,res,next)=>{
    if(!req.session.user) return res.status(401).json({ error:'Não autenticado' });
    if(req.session.user.role !== role) return res.status(403).json({ error:'Sem permissão' });
    next();
  };
}

// ===== Rotas de Auth =====
app.post('/api/login', (req,res)=>{
  const { email, password } = req.body || {};
  if(!email || !password) return res.status(400).json({ error:'Informe email e senha' });

  const user = db.prepare(`SELECT * FROM users WHERE email=?`).get(email);
  if(!user) return res.status(400).json({ error:'Usuário ou senha inválidos' });
  if(!bcrypt.compareSync(password, user.password_hash)){
    return res.status(400).json({ error:'Usuário ou senha inválidos' });
  }
  req.session.user = { id:user.id, name:user.name, email:user.email, role:user.role };
  res.json({ ok:true, user:req.session.user });
});

app.post('/api/logout', (req,res)=>{
  req.session.destroy(()=> res.json({ ok:true }));
});

app.get('/api/me', (req,res)=>{
  res.json({ user: req.session.user || null });
});

// ===== CRUD de usuários (apenas admin) =====
app.get('/api/users', requireAuth, requireRole('admin'), (req,res)=>{
  const list = db.prepare(`SELECT id,name,email,role FROM users ORDER BY id DESC`).all();
  res.json(list);
});

// POST /api/users — usado pelo admin.html para criar novo usuário
app.post('/api/users', requireAuth, requireRole('admin'), (req,res)=>{
  let body = req.body || {};

  // aceita vários nomes de campos vindos do front
  let email = (
    body.email ||
    body.usuario ||
    body.user ||
    body.login ||
    ''
  );
  let password = (
    body.password ||
    body.senha ||
    body.pass ||
    body.novaSenha ||
    ''
  );
  let role = body.role || body.perfil || 'user';
  let name = body.name || body.nome || '';

  email = String(email).trim();
  password = String(password).trim();
  role = String(role || 'user').trim();

  if (!email || !password){
    return res.status(400).json({ error:'Campos obrigatórios faltando' });
  }

  // se não vier name, usa o pedaço antes do @
  if (!name || !String(name).trim()){
    name = email.includes('@') ? email.split('@')[0] : email;
  }

  const hash = bcrypt.hashSync(password, 10);

  try{
    const info = db.prepare(
      `INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,?)`
    ).run(name, email, hash, role);
    res.json({ id: info.lastInsertRowid });
  }catch(err){
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/users/:id', requireAuth, requireRole('admin'), (req,res)=>{
  const { name, email, password, role } = req.body || {};
  const id = Number(req.params.id);
  const u = db.prepare(`SELECT * FROM users WHERE id=?`).get(id);
  if(!u) return res.status(404).json({ error:'Usuário não encontrado' });

  let hash = u.password_hash;
  if(password) hash = bcrypt.hashSync(password, 10);
  try{
    db.prepare(`UPDATE users SET name=?, email=?, password_hash=?, role=? WHERE id=?`)
      .run(name || u.name, email || u.email, hash, role || u.role, id);
    res.json({ ok:true });
  }catch(err){
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/users/:id', requireAuth, requireRole('admin'), (req,res)=>{
  const id = Number(req.params.id);
  db.prepare(`DELETE FROM users WHERE id=?`).run(id);
  res.json({ ok:true });
});

// ===== Diários =====
app.post('/api/diarios', (req,res)=>{
  const { obra, responsavel, data, observacoes, funcoes, intercorrencias } = req.body || {};
  if(!obra || !responsavel || !data) return res.status(400).json({ error:'Campos obrigatórios faltando' });

  const insertDiario = db.prepare(`INSERT INTO diario (obra,responsavel,data,observacoes) VALUES (?,?,?,?)`);
  const insertFunc   = db.prepare(`INSERT INTO funcoes (diario_id,funcao,presente,ausente,ferias) VALUES (?,?,?,?,?)`);
  const insertInter  = db.prepare(`INSERT INTO intercorrencia (diario_id,codigo,descricao) VALUES (?,?,?)`);

  try{
    const tx = db.transaction(()=>{
      const info = insertDiario.run(obra, responsavel, data, observacoes || null);
      const id = info.lastInsertRowid;

      if(Array.isArray(funcoes)){
        for(const f of funcoes){
          insertFunc.run(
            id,
            f.funcao,
            Number(f.presente||0),
            Number(f.ausente||0),
            Number(f.ferias||0)
          );
        }
      }
      if(Array.isArray(intercorrencias)){
        for(const it of intercorrencias){
          const codigo = it.codigo ? Number(it.codigo) : null;
          const desc   = (it.descricao || '').trim() || null;
          if(codigo || desc) insertInter.run(id, codigo, desc);
        }
      }
      return id;
    });
    const novoId = tx();
    res.json({ id: novoId });
  }catch(err){
    console.error(err);
    res.status(500).json({ error:'Falha ao salvar diário' });
  }
});

app.get('/api/diarios', requireAuth, (req,res)=>{
  const list = db.prepare(`
    SELECT d.id, d.obra, d.responsavel, d.data, d.observacoes
    FROM diario d
    ORDER BY d.id DESC
    LIMIT 200
  `).all();
  res.json(list);
});

app.get('/api/diarios/:id', requireAuth, (req,res)=>{
  const id = Number(req.params.id);
  const d = db.prepare(`SELECT * FROM diario WHERE id=?`).get(id);
  if(!d) return res.status(404).json({ error:'Não encontrado' });

  const funcoes = db.prepare(`SELECT funcao,presente,ausente,ferias FROM funcoes WHERE diario_id=?`).all(id);
  const inter   = db.prepare(`SELECT codigo,descricao FROM intercorrencia WHERE diario_id=?`).all(id);
  res.json({ ...d, funcoes, intercorrencias: inter });
});

// ===== Funcionários (autocomplete) =====
app.get('/api/funcionarios', (req,res)=>{
  const q = String(req.query.q || '').trim();
  if(!q) return res.json([]);

  const rows = db.prepare(`
    SELECT chapa,nome,funcao
    FROM funcionarios
    WHERE chapa LIKE ? OR LOWER(nome) LIKE LOWER(?)
    ORDER BY chapa
    LIMIT 20
  `).all(`%${q}%`, `%${q}%`);
  res.json(rows);
});

app.get('/api/funcionarios/:chapa', (req,res)=>{
  const chapa = String(req.params.chapa || '').trim();
  if(!chapa) return res.status(400).json({ error:'Chapa obrigatória' });

  const row = db.prepare(`SELECT chapa,nome,funcao FROM funcionarios WHERE chapa=?`).get(chapa);
  if (!row) return res.status(404).json({ error:'Funcionário não encontrado' });
  res.json(row);
});

// ===== Proteção de páginas =====
app.get(['/viewer.html','/details.html'], requireAuth, (req,res,next)=>next());
app.get(['/admin.html'], requireAuth, requireRole('admin'), (req,res,next)=>next());

// ===== Estáticos e raiz =====
app.use(express.static('.'));
app.get('/', (_req,res)=>res.sendFile(path.join(__dirname, 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log(`API rodando em http://localhost:${PORT}`));
