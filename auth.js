// ===============================
// Ficha_The_Obscurity - Auth.js
// Middleware e funções auxiliares de autenticação
// ===============================

const jwt = require("jsonwebtoken");
const SECRET_KEY = "the_obscurity_secret_key";

// Função para gerar token JWT
function gerarToken(usuario) {
  return jwt.sign(
    { username: usuario.username, role: usuario.role },
    SECRET_KEY,
    { expiresIn: "2h" }
  );
}

// Middleware para verificar token
function verificarToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(403).json({ message: "Token não fornecido" });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Token inválido" });
    req.user = decoded;
    next();
  });
}

// Middleware para restringir acesso apenas ao Mestre
function apenasMestre(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Acesso restrito ao Mestre" });
  }
  next();
}

module.exports = {
  gerarToken,
  verificarToken,
  apenasMestre
};
