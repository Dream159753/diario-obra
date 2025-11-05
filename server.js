// server.js
const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// =================== MIDDLEWARE BÁSICO ===================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// =================== ARQUIVOS ESTÁTICOS / HTML ===================
// Todos os HTML (index.html, form.html, login.html, viewer.html) devem estar
// na MESMA PASTA que este server.js
const PUBLIC_DIR = __dirname;

// Servir arquivos estáticos (HTML, CSS, JS, imagens)
app.use(express.static(PUBLIC_DIR));

// Rota raiz -> index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// =================== ARQUIVOS DE DADOS ===================
const DB_DIR = path.join(__dirname, 'data');
const DIARIOS_FILE = path.join(DB_DIR, 'diarios.json');

if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}

function carregarDiarios() {
  if (!fs.existsSync(DIARIOS_FILE)) {
    fs.writeFileSync(
      DIARIOS_FILE,
      JSON.stringify({ lastId: 0, itens: [] }, null, 2)
    );
  }
  const conteudo = fs.readFileSync(DIARIOS_FILE, 'utf8');
  try {
    return JSON.parse(conteudo);
  } catch (e) {
    console.error('Erro ao ler diarios.json, recriando arquivo...', e);
    const vazio = { lastId: 0, itens: [] };
    fs.writeFileSync(DIARIOS_FILE, JSON.stringify(vazio, null, 2));
    return vazio;
  }
}

function salvarDiarios(db) {
  fs.writeFileSync(DIARIOS_FILE, JSON.stringify(db, null, 2));
}

// =================== LOGIN SIMPLES ===================
const USERS = [
  { username: 'engenheiro', password: '123', role: 'engenheiro' },
  { username: 'mestre', password: '123', role: 'mestre' },
  { username: 'adm', password: '123', role: 'admin' }
];

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuário e senha são obrigatórios.' });
  }

  const user = USERS.find(
    u => u.username === username && u.password === password
  );

  if (!user) {
    return res.status(401).json({ error: 'Usuário ou senha inválidos.' });
  }

  res.json({
    username: user.username,
    role: user.role
  });
});

// =================== ROTAS DE DIÁRIOS ===================

// Salvar diário
app.post('/api/diarios', (req, res) => {
  try {
    const payload = req.body || {};

    if (!payload.obra || !payload.responsavel || !payload.data) {
      return res
        .status(400)
        .json({ error: 'Obra, responsável e data são obrigatórios.' });
    }

    // Trava de intercorrência
    const intercorrencias = Array.isArray(payload.intercorrencias)
      ? payload.intercorrencias
      : [];
    const temInterValida = intercorrencias.some(
      i => i.codigo || i.descricao
    );
    if (!temInterValida) {
      return res
        .status(400)
        .json({ error: 'Preencha pelo menos uma intercorrência.' });
    }

    const db = carregarDiarios();
    const novoId = db.lastId + 1;

    const diario = {
      id: novoId,
      criadoEm: new Date().toISOString(),
      ...payload
    };

    db.lastId = novoId;
    db.itens.push(diario);
    salvarDiarios(db);

    res.status(201).json({ id: novoId });
  } catch (err) {
    console.error('Erro ao salvar diário:', err);
    res.status(500).json({ error: 'Erro interno ao salvar diário.' });
  }
});

// Listar diários
app.get('/api/diarios', (req, res) => {
  try {
    const db = carregarDiarios();
    res.json(db.itens || []);
  } catch (err) {
    console.error('Erro ao listar diários:', err);
    res.status(500).json({ error: 'Erro interno ao listar diários.' });
  }
});

// Obter diário por ID
app.get('/api/diarios/:id', (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const db = carregarDiarios();
    const diario = (db.itens || []).find(d => d.id === id);
    if (!diario) {
      return res.status(404).json({ error: 'Diário não encontrado' });
    }
    res.json(diario);
  } catch (err) {
    console.error('Erro ao buscar diário:', err);
    res.status(500).json({ error: 'Erro interno ao buscar diário.' });
  }
});

// =================== FUNCIONÁRIOS / CSV ===================
const funcionarios = [];

// Lê todos arquivos funcionarios*.csv na pasta /data
function carregarFuncionarios() {
  try {
    if (!fs.existsSync(DB_DIR)) {
      console.warn('Diretório data/ não existe, nenhum funcionário carregado.');
      return;
    }

    const arquivos = fs
      .readdirSync(DB_DIR)
      .filter(f => /^funcionarios.*\.csv$/i.test(f));

    if (!arquivos.length) {
      console.warn(
        'Nenhum arquivo funcionarios*.csv encontrado na pasta /data.'
      );
      return;
    }

    console.log('Arquivos de funcionários encontrados:', arquivos);

    arquivos.forEach(nomeArq => {
      const caminho = path.join(DB_DIR, nomeArq);
      const conteudo = fs.readFileSync(caminho, 'utf8');

      const linhas = conteudo
        .split(/\r?\n/)
        .filter(l => l.trim() !== '');
      if (linhas.length < 2) return;

      const headerLine = linhas[0];
      const sep = headerLine.includes(';') ? ';' : ',';
      const headers = headerLine.split(sep).map(h => h.trim());

      for (let i = 1; i < linhas.length; i++) {
        const linha = linhas[i];
        if (!linha.trim()) continue;
        const cols = linha.split(sep);
        const row = {};
        headers.forEach((h, idx) => {
          row[h] = (cols[idx] || '').trim();
        });
        funcionarios.push(row);
      }
    });

    console.log(`Total de funcionários carregados: ${funcionarios.length}`);
  } catch (err) {
    console.error('Erro ao carregar funcionários dos CSVs:', err);
  }
}

// Padroniza um funcionário: { chapa, nome, funcao }
function mapFuncionario(row) {
  const keys = Object.keys(row);

  let chapa =
    row.chapa ||
    row.CHAPA ||
    row.Chapa ||
    row['chapa'] ||
    row['CHAPA'] ||
    row['Chapa'];

  let nome = row.nome || row.NOME || row.Nome;
  let funcao =
    row.funcao ||
    row.FUNCAO ||
    row.Funcao ||
    row['FUNÇÃO'] ||
    row['Função'];

  // tenta achar chave que contenha "nome"
  if (!nome) {
    for (const k of keys) {
      if (k.toLowerCase().includes('nome')) {
        nome = row[k];
        break;
      }
    }
  }

  // tenta achar chave que contenha "func"
  if (!funcao) {
    for (const k of keys) {
      if (k.toLowerCase().includes('func')) {
        funcao = row[k];
        break;
      }
    }
  }

  // fallback bruto: 1ª = chapa, 2ª = nome, 3ª = função
  if (!chapa && keys[0]) chapa = row[keys[0]];
  if (!nome && keys[1]) nome = row[keys[1]];
  if (!funcao && keys[2]) funcao = row[keys[2]];

  return {
    chapa: chapa ? String(chapa).trim() : '',
    nome: nome ? String(nome).trim() : '',
    funcao: funcao ? String(funcao).trim() : ''
  };
}

// GET /api/funcionarios?q=...  (autocomplete de chapa)
app.get('/api/funcionarios', (req, res) => {
  const q = (req.query.q || '').toString().trim();

  if (!q) {
    return res.json(funcionarios.slice(0, 50).map(mapFuncionario));
  }

  const termo = q.toLowerCase();

  const filtrados = funcionarios.filter(row => {
    const f = mapFuncionario(row);
    return (
      f.chapa.toLowerCase().includes(termo) ||
      f.nome.toLowerCase().includes(termo)
    );
  });

  res.json(filtrados.slice(0, 50).map(mapFuncionario));
});

// GET /api/funcionarios/:chapa  (preencher nome + função)
app.get('/api/funcionarios/:chapa', (req, res) => {
  const chapaParam = req.params.chapa.toString().trim();

  const row = funcionarios.find(r => {
    const f = mapFuncionario(r);
    return f.chapa === chapaParam;
  });

  if (!row) {
    return res.status(404).json({ error: 'Funcionário não encontrado' });
  }

  const f = mapFuncionario(row);
  res.json(f);
});

// =================== HEALTHCHECK ===================
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', funcionarios: funcionarios.length });
});

// =================== INICIAR SERVIDOR ===================
carregarFuncionarios();

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
