require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const { PrismaClient } = require("@prisma/client");
const { format, parse } = require("date-fns");

const prisma = new PrismaClient();
const app = express();
const port = 3000;
const SECRET_KEY = process.env.SECRET_KEY || "2a51f0c6b96167b01f59b41aa2407066735cc39ee71ebd041d8ff59b75c60c15";

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(morgan("dev"));

// Middleware de autenticação
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token não fornecido" });

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.userId = decoded.userId;
    next();
  } catch {
    res.status(401).json({ error: "Token inválido" });
  }
};

// ROTAS DE AUTENTICAÇÃO
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await prisma.user.create({ data: { username, password: hashedPassword } });
    res.json(newUser);
  } catch (error) {
    res.status(400).json({ error: "Erro ao registrar usuário", details: error.message });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await prisma.user.findUnique({ where: { username } });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "Usuário ou senha inválidos" });
  }

  const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: "1h" });
  res.json({ token });
});

// ROTAS DE CLIENTES
app.get("/clients", async (req, res) => res.json(await prisma.client.findMany()));

app.get("/clients/:id", async (req, res) => {
  const client = await prisma.client.findUnique({
    where: { id: parseInt(req.params.id) },
    include: { purchases: true, payments: true },
  });
  res.json(client || { error: "Cliente não encontrado" });
});

app.post("/clients", async (req, res) => res.json(await prisma.client.create({ data: req.body })));

app.put("/clients/:id", async (req, res) => {
  res.json(await prisma.client.update({ where: { id: parseInt(req.params.id) }, data: req.body }));
});

// ROTAS DE MÁQUINAS
app.get("/machines", async (req, res) => res.json(await prisma.machine.findMany()));

app.get("/machines/:id", async (req, res) => {
  const machine = await prisma.machine.findUnique({
    where: { id: parseInt(req.params.id) },
    include: { readings: true },
  });
  res.json(machine || { error: "Máquina não encontrada" });
});

app.post("/machines", async (req, res) => res.json(await prisma.machine.create({ data: req.body })));

// ROTAS DE COMPRAS (PURCHASES)
app.post("/purchases", async (req, res) => {
  try {
    const { product, quantity, total, date, clientId } = req.body;

    // Converter quantity para um número inteiro
    const parsedQuantity = parseInt(quantity, 10);
    if (isNaN(parsedQuantity)) {
      return res.status(400).json({ error: "Quantidade deve ser um número válido." });
    }

    const newPurchase = await prisma.purchase.create({
      data: { product, quantity: parsedQuantity, total, date, clientId },
    });

    res.status(201).json(newPurchase);
  } catch (error) {
    res.status(500).json({ error: "Erro ao criar compra", details: error.message });
  }
});
// ROTAS DE PAGAMENTOS
app.post("/payments", async (req, res) => res.json(await prisma.payment.create({ data: req.body })));

// ROTAS DE LEITURAS DIÁRIAS

app.get("/daily-readings", async (req, res) => {
  const { machineId, date } = req.query;

  let whereClause = {
    machineId: parseInt(machineId),
  };

  if (date) {
    // Parse a data de entrada e formate-a como "dd-MM-yyyy"
    const parsedDate = parse(date, "yyyy-MM-dd", new Date());
    const formattedDate = format(parsedDate, "dd-MM-yyyy");
    whereClause.date = { contains: formattedDate };
  }

  try {
    const dailyReadings = await prisma.dailyReading.findMany({
      where: whereClause,
    });
    res.json(dailyReadings);
  } catch (error) {
    console.error("Erro ao buscar leituras diárias:", error);
    res.status(500).json({ message: "Erro ao buscar leituras diárias" });
  }
});

app.post("/daily-readings", async (req, res) => {
  const { date, value, machineId } = req.body;
  const formattedDate = format(date, "dd-MM-yyyy"); // Formata a data para "dd-MM-yyyy"
  res.json(await prisma.dailyReading.create({ data: { date: formattedDate, value, machineId } }));
});

app.delete("/daily-readings/:id", async (req, res) => {
  await prisma.dailyReading.delete({ where: { id: parseInt(req.params.id) } });
  res.json({ message: "Leitura diária excluída com sucesso" });
});

// ROTAS DE PRODUTOS (CORREÇÃO DO ERRO `quantity`)
app.get("/products", async (req, res) => res.json(await prisma.product.findMany()));

app.post("/products", async (req, res) => {
  try {
    const { name, quantity, unit, value } = req.body;

    if (!name || !quantity || !unit) {
      return res.status(400).json({ error: "Todos os campos são obrigatórios." });
    }

    const parsedQuantity = parseInt(quantity, 10);
    if (isNaN(parsedQuantity)) {
      return res.status(400).json({ error: "Quantidade deve ser um número válido." });
    }

    const parsedValue = parseInt(value, 10);
    if (isNaN(parsedValue)) {
      return res.status(400).json({ error: "Valor deve ser um número válido." });
    }

    const newProduct = await prisma.product.create({
      data: { name, quantity: parsedQuantity, unit, value: parsedValue },
    });

    res.status(201).json(newProduct);
  } catch (error) {
    res.status(500).json({ error: "Erro ao criar produto", details: error.message });
  }
});

app.delete("/products/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({ error: "ID inválido" });
    }

    await prisma.product.delete({ where: { id } });
    res.json({ message: "Produto excluído com sucesso" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao excluir produto", details: error.message });
  }
});

// ROTAS DE BALANÇO
app.get("/balances", async (req, res) => res.json(await prisma.balance.findMany()));

app.post("/balances", async (req, res) => {
  const { date, balance, cartao, dinheiro } = req.body;
  res.json(await prisma.balance.create({ data: { date, balance, cartao, dinheiro } }));
});

app.put("/balances/:id", async (req, res) => {
  res.json(await prisma.balance.update({ where: { id: parseInt(req.params.id) }, data: req.body }));
});

app.delete("/balances/:id", async (req, res) => {
  await prisma.balance.delete({ where: { id: parseInt(req.params.id) } });
  res.json({ message: "Saldo excluído com sucesso" });
});

// MIDDLEWARE GLOBAL DE ERRO
app.use((err, req, res, next) => {
  console.error("Erro:", err);
  res.status(500).json({ error: "Erro interno do servidor", details: err.message });
});

app.listen(port, () => {
  console.log(`Server tá on krai --> http://localhost:${port}`);
});
