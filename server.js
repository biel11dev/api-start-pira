require("dotenv").config(); // Adicione esta linha no início do arquivo
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors"); // Importa o CORS
const { Client, Machine, Purchase, Payment, DailyReading, Product, Balance, User } = require("./models");
const app = express();
const port = 3000;

app.use(cors()); // Aplica CORS em todas as rotas
app.use(express.json());

const SECRET_KEY = process.env.SECRET_KEY || "2a51f0c6b96167b01f59b41aa2407066735cc39ee71ebd041d8ff59b75c60c15"; // Substitua por uma chave secreta segura

// Rotas para Autenticação
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const newUser = await User.create({ username, password: hashedPassword });
    res.json(newUser);
  } catch (error) {
    console.error("Erro ao registrar usuário:", error); // Adicione este console.error para verificar o erro
    res.status(400).json({ error: "Erro ao registrar usuário", details: error.message });
  }
});

// Rotas para login de usuário
app.get("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ where: { username } });
  if (!user) {
    return res.status(401).json({ error: "Usuário não encontrado" });
  }
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ error: "Senha inválida" });
  }
  const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: "1h" });
  res.json({ token });
});

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Token não fornecido" });
  }
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(401).json({ error: "Token inválido" });
  }
};

// Rotas protegidas
app.get("/protected", authenticate, (req, res) => {
  res.json({ message: "Acesso autorizado" });
});

// Rotas para Clients
app.get("/clients", async (req, res) => {
  const clients = await Client.findAll();
  res.json(clients);
});

app.get("/clients/:id", async (req, res) => {
  const client = await Client.findByPk(req.params.id, {
    include: [Purchase, Payment],
  });
  res.json(client);
});

app.post("/clients", async (req, res) => {
  const newClient = await Client.create(req.body);
  res.json(newClient);
});

// Rotas para Machines
app.get("/machines", async (req, res) => {
  const machines = await Machine.findAll();
  res.json(machines);
});

app.get("/machines/:id", async (req, res) => {
  const machine = await Machine.findByPk(req.params.id, {
    include: [DailyReading],
  });
  if (machine) {
    res.json(machine);
  } else {
    res.status(404).json({ message: "Máquina não encontrada" });
  }
});

app.post("/machines", async (req, res) => {
  const newMachine = await Machine.create(req.body);
  res.json(newMachine);
});

// Rotas para Purchases
app.post("/purchases", async (req, res) => {
  const newPurchase = await Purchase.create(req.body);
  res.json(newPurchase);
});

// Rotas para Payments
app.post("/payments", async (req, res) => {
  const newPayment = await Payment.create(req.body);
  res.json(newPayment);
});

// Rotas para DailyReadings
app.post("/daily-readings", async (req, res) => {
  const { date, value, machineId } = req.body; // Inclui o campo entrada
  const newDailyReading = await DailyReading.create({ date, value, machineId });
  res.json(newDailyReading);
});

app.delete("/daily-readings/:id", async (req, res) => {
  const dailyReading = await DailyReading.findByPk(req.params.id);
  await dailyReading.destroy();
  res.json({ message: "Leitura diária excluída com sucesso" });
});

// Rotas para Products
app.get("/products", async (req, res) => {
  const products = await Product.findAll();
  res.json(products);
});

app.post("/products", async (req, res) => {
  const newProduct = await Product.create(req.body);
  res.json(newProduct);
});

app.delete("/products/:id", async (req, res) => {
  const product = await Product.findByPk(req.params.id);
  await product.destroy();
  res.json({ message: "Produto excluído com sucesso" });
});

// Rotas para Balances
app.get("/balances", async (req, res) => {
  const balances = await Balance.findAll();
  res.json(balances);
});

app.post("/balances", async (req, res) => {
  const { date, balance, cartao, dinheiro } = req.body;
  const newBalance = await Balance.create({ date, balance, cartao, dinheiro });
  res.json(newBalance);
});

app.put("/balances/:id", async (req, res) => {
  const balance = await Balance.findByPk(req.params.id);
  const { cartaofimcaixa, dinheirofimcaixa } = req.body;
  balance.cartaofimcaixa = cartaofimcaixa;
  balance.dinheirofimcaixa = dinheirofimcaixa;
  balance.balancefim = cartaofimcaixa + dinheirofimcaixa;
  balance.lucro = balance.balancefim - balance.balance;
  await balance.save();
  res.json(balance);
});

app.delete("/balances/:id", async (req, res) => {
  const balance = await Balance.findByPk(req.params.id);
  await balance.destroy();
  res.json({ message: "Saldo excluído com sucesso" });
});

app.listen(port, () => {
  console.log(`Server tá on krai --> http://localhost:${port}`);
});
