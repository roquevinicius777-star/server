// ===============================
// Ficha_The_Obscurity - Servidor Principal
// ===============================

const express = require("express");
const fs = require("fs");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path");

const app = express();
app.use(express.json());
app.use(cors());

// Caminho para o banco local
const dbPath = path.join(__dirname, "db.json");
const SECRET_KEY = "the_obscurity_secret_key";

// Função para ler e salvar o db.json
function readDB() {
  return JSON.parse(fs.readFileSync(dbPath, "utf-8"));
}
function saveDB(data) {
  fs.writeFileSync(dbPath, JSON.stringify(data, null, 2));
}

// Cria o Mestre automaticamente se não existir
function ensureMasterExists() {
  const db = readDB();
  const master = db.users.find(u => u.username === "Mestre");
  if (!master) {
    const hashed = bcrypt.hashSync("obscuritymaster", 10);
    db.users.push({
      username: "Mestre",
      password: hashed,
      role: "admin",
      ficha: {}
    });
    saveDB(db);
    console.log("👑 Usuário Mestre criado automaticamente.");
  }
}

// Middleware de autenticação JWT
function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(403).json({ message: "Token não fornecido" });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Token inválido" });
    req.user = decoded;
    next();
  });
}

// ===============================
// ROTAS DE AUTENTICAÇÃO
// ===============================

// Registro
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  const db = readDB();

  if (db.users.find(u => u.username === username)) {
    return res.status(400).json({ message: "Usuário já existe" });
  }

  const hashed = await bcrypt.hash(password, 10);
  db.users.push({
    username,
    password: hashed,
    role: "player",
    ficha: {}
  });
  saveDB(db);

  res.json({ message: "Usuário registrado com sucesso" });
});

// Login
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const db = readDB();
  const user = db.users.find(u => u.username === username);

  if (!user) return res.status(400).json({ message: "Usuário não encontrado" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ message: "Senha incorreta" });

  const token = jwt.sign({ username: user.username, role: user.role }, SECRET_KEY, { expiresIn: "2h" });
  res.json({ token, role: user.role });
});

// ===============================
// ROTAS DE FICHA
// ===============================

// Carregar ficha do usuário logado
app.get("/api/sheet/:username", verifyToken, (req, res) => {
  const { username } = req.params;
  const db = readDB();

  if (req.user.username !== username && req.user.role !== "admin") {
    return res.status(403).json({ message: "Acesso negado" });
  }

  const user = db.users.find(u => u.username === username);
  if (!user) return res.status(404).json({ message: "Usuário não encontrado" });

  res.json(user.ficha || {});
});

// Salvar ficha do usuário
app.post("/api/sheet/:username", verifyToken, (req, res) => {
  const { username } = req.params;
  const fichaData = req.body;
  const db = readDB();

  if (req.user.username !== username && req.user.role !== "admin") {
    return res.status(403).json({ message: "Acesso negado" });
  }

  const user = db.users.find(u => u.username === username);
  if (!user) return res.status(404).json({ message: "Usuário não encontrado" });

  user.ficha = fichaData;
  saveDB(db);

  res.json({ message: "Ficha salva com sucesso" });
});

// ===============================
// ROTAS DO MESTRE
// ===============================

// Listar todas as fichas (apenas admin)
app.get("/api/all", verifyToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Acesso restrito ao Mestre" });
  }

  const db = readDB();
  const fichas = db.users.map(u => ({
    username: u.username,
    role: u.role,
    ficha: u.ficha
  }));

  res.json(fichas);
});

// Editar ficha de outro jogador (apenas Mestre)
app.post("/api/edit/:username", verifyToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Acesso restrito ao Mestre" });
  }

  const { username } = req.params;
  const novaFicha = req.body;
  const db = readDB();

  const user = db.users.find(u => u.username === username);
  if (!user) return res.status(404).json({ message: "Usuário não encontrado" });

  user.ficha = novaFicha;
  saveDB(db);
  res.json({ message: "Ficha atualizada pelo Mestre" });
});

// ===============================
// INICIALIZAÇÃO
// ===============================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  ensureMasterExists();
  console.log(`🌑 Servidor The Obscurity rodando na porta ${PORT}`);
});
