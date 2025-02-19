require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs"); // Alterado para bcryptjs
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());

const SECRET_KEY = process.env.SECRET_KEY || "2a51f0c6b96167b01f59b41aa2407066735cc39ee71ebd041d8ff59b75c60c15";

// Rotas para Autenticação
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const newUser = await prisma.user.create({
      data: { username, password: hashedPassword },
    });
    res.json(newUser);
  } catch (error) {
    console.error("Erro ao registrar usuário:", error);
    res.status(400).json({ error: "Erro ao registrar usuário", details: error.message });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await prisma.user.findUnique({ where: { username } });
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

app.get("/protected", authenticate, (req, res) => {
  res.json({ message: "Acesso autorizado" });
});

// Rotas para Clients
app.get("/clients", async (req, res) => {
  const clients = await prisma.client.findMany();
  res.json(clients);
});

app.get("/clients/:id", async (req, res) => {
  const client = await prisma.client.findUnique({
    where: { id: parseInt(req.params.id) },
    include: { purchases: true, payments: true },
  });
  res.json(client);
});

app.post("/clients", async (req, res) => {
  const newClient = await prisma.client.create({ data: req.body });
  res.json(newClient);
});

// Rotas para Machines
app.get("/machines", async (req, res) => {
  const machines = await prisma.machine.findMany();
  res.json(machines);
});

app.get("/machines/:id", async (req, res) => {
  const machine = await prisma.machine.findUnique({
    where: { id: parseInt(req.params.id) },
    include: { readings: true },
  });
  if (machine) {
    res.json(machine);
  } else {
    res.status(404).json({ message: "Máquina não encontrada" });
  }
});

app.post("/machines", async (req, res) => {
  const newMachine = await prisma.machine.create({ data: req.body });
  res.json(newMachine);
});

// Rotas para Purchases
app.post("/purchases", async (req, res) => {
  const newPurchase = await prisma.purchase.create({ data: req.body });
  res.json(newPurchase);
});

// Rotas para Payments
app.post("/payments", async (req, res) => {
  const newPayment = await prisma.payment.create({ data: req.body });
  res.json(newPayment);
});

// Rotas para DailyReadings

app.get("/daily-readings", async (req, res) => {
  const { machineId, date } = req.query;
  try {
    const dailyReadings = await prisma.dailyReading.findMany({
      where: {
        machineId: parseInt(machineId),
        date: {
          contains: date,
        },
      },
    });
    res.json(dailyReadings);
  } catch (error) {
    console.error("Erro ao buscar leituras diárias:", error);
    res.status(500).json({ message: "Erro ao buscar leituras diárias", details: error.message });
  }
});

app.post("/daily-readings", async (req, res) => {
  const { date, value, machineId } = req.body;
  const formattedDate = date.split("T")[0]; // Formatar a data para "dd-MM-yyyy"
  const newDailyReading = await prisma.dailyReading.create({
    data: { date: formattedDate, value, machineId },
  });
  res.json(newDailyReading);
});

app.delete("/daily-readings/:id", async (req, res) => {
  const dailyReading = await prisma.dailyReading.delete({
    where: { id: parseInt(req.params.id) },
  });
  res.json({ message: "Leitura diária excluída com sucesso" });
});

// Rotas para Products
app.get("/products", async (req, res) => {
  const products = await prisma.product.findMany();
  res.json(products);
});

app.post("/products", async (req, res) => {
  const newProduct = await prisma.product.create({ data: req.body });
  res.json(newProduct);
});

app.delete("/products/:id", async (req, res) => {
  const product = await prisma.product.delete({
    where: { id: parseInt(req.params.id) },
  });
  res.json({ message: "Produto excluído com sucesso" });
});

// Rotas para Balances
app.get("/balances", async (req, res) => {
  const balances = await prisma.balance.findMany();
  res.json(balances);
});

app.post("/balances", async (req, res) => {
  const { date, balance, cartao, dinheiro } = req.body;
  const newBalance = await prisma.balance.create({
    data: { date, balance, cartao, dinheiro },
  });
  res.json(newBalance);
});

app.put("/balances/:id", async (req, res) => {
  const balance = await prisma.balance.update({
    where: { id: parseInt(req.params.id) },
    data: req.body,
  });
  res.json(balance);
});

app.delete("/balances/:id", async (req, res) => {
  const balance = await prisma.balance.delete({
    where: { id: parseInt(req.params.id) },
  });
  res.json({ message: "Saldo excluído com sucesso" });
});

app.listen(port, () => {
  console.log(`Server tá on krai --> http://localhost:${port}`);
});
