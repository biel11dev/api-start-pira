require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const { PrismaClient } = require("@prisma/client");
const { format, parse } = require("date-fns");
const nodemailer = require("nodemailer");
const prisma = new PrismaClient();
const app = express();
const port = 3000;
const SECRET_KEY = process.env.SECRET_KEY || "2a51f0c6b96167b01f59b41aa2407066735cc39ee71ebd041d8ff59b75c60c15";
const path = require("path");

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        connectSrc: ["'self'", "https://api-start-pira.vercel.app"],
        scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
      },
    },
  })
);
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

async function sendResetEmail(email, token) {
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const resetLink = `https://start-pira-ftd.vercel.app/reset-password?token=${token}`;

  const mailOptions = {
    from: '"Start Pira" <startpira01@gmail.com>',
    to: email,
    subject: "Redefinição de Senha - Start Pira",
    text: `Olá,

Você solicitou a redefinição de sua senha. Use o link abaixo para redefini-la:

${resetLink}

Se você não solicitou isso, ignore este e-mail.

Atenciosamente,
Equipe Start Pira`,
    html: `<p>Olá,</p>
           <p>Você solicitou a redefinição de sua senha. Use o link abaixo para redefini-la:</p>
           <a href="${resetLink}">Redefinir Senha</a>
           <p>Se você não solicitou isso, ignore este e-mail.</p>
           <p>Atenciosamente,<br>Equipe Start Pira</p>`,
  };

  await transporter.sendMail(mailOptions);
  console.log(`E-mail de redefinição enviado para ${email}`);
}

// ROTAS DE AUTENTICAÇÃO
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await prisma.user.create({ data: { username, password: hashedPassword } });
    res.json(newUser);
  } catch (error) {
    console.log("Dados recebidos:", req.body); // Log dos dados recebidos
    res.status(400).json({ error: "Erro ao registrar usuário", details: error.message });
  }
});

app.get("/api/users", async (req, res) => {
  try {
    const users = await prisma.user.findMany();
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar usuários", details: error.message });
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await prisma.user.findUnique({ where: { username } });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "Usuário ou senha inválidos" });
  }

  const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: "1h" });
  // Inclua as permissões do usuário no retorno
  res.json({
    token,
    permissions: {
      caixa: user.caixa,
      produtos: user.produtos,
      maquinas: user.maquinas,
      fiado: user.fiado,
      despesas: user.despesas,
      ponto: user.ponto,
      acessos: user.acessos,
      base_produto: user.base_produto,
      pdv: user.pdv,
    },
  });
});

app.put("/api/users/:id", async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { caixa, produtos, maquinas, fiado, despesas, ponto, acessos, base_produto, pdv } = req.body;

    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: { caixa, produtos, maquinas, fiado, despesas, ponto, acessos, base_produto, pdv  },
    });

    res.json(updatedUser);
  } catch (error) {
    res.status(500).json({ error: "Erro ao atualizar permissões do usuário", details: error.message });
  }
});

// ROTAS DE CLIENTES
app.get("/api/clients", async (req, res) => res.json(await prisma.client.findMany()));

app.get("/api/clients/:id", async (req, res) => {
  try {
    const client = await prisma.client.findUnique({
      where: { id: parseInt(req.params.id) },
      include: {
        Purchase: true,
        Payment: true,
      },
    });
    if (!client) {
      return res.status(404).json({ error: "Cliente não encontrado" });
    }
    res.json(client);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar cliente", details: error.message });
  }
});

app.post("/api/clients", async (req, res) => res.json(await prisma.client.create({ data: req.body })));

app.put("/api/clients/:id", async (req, res) => {
  res.json(await prisma.client.update({ where: { id: parseInt(req.params.id) }, data: req.body }));
});

app.delete("/api/clients/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({ error: "ID inválido" });
    }

    await prisma.client.delete({ where: { id } });
    res.json({ message: "Cliente excluído com sucesso" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao excluir cliente", details: error.message });
  }
});

// ROTAS DE MÁQUINAS
app.get("/api/machines", async (req, res) => res.json(await prisma.machine.findMany()));

app.get("/api/machines/:id", async (req, res) => {
  const machine = await prisma.machine.findUnique({
    where: { id: parseInt(req.params.id) },
    include: { DailyReading: true },
  });

  if (machine) {
    // Formata o campo `date` de cada leitura diária
    machine.DailyReading = machine.DailyReading.map((reading) => ({
      ...reading,
      date: format(parse(reading.date, "dd-MM-yyyy", new Date()), "dd-MM-yyyy"),
    }));
  }

  res.json(machine || { error: "Máquina não encontrada" });
});

app.post("/api/machines", async (req, res) => res.json(await prisma.machine.create({ data: req.body })));

app.put("/api/machines/:id", async (req, res) => {
  res.json(await prisma.machine.update({ where: { id: parseInt(req.params.id) }, data: req.body }));
});

app.delete("/api/machines/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({ error: "ID inválido" });
    }

    await prisma.machine.delete({ where: { id } });
    res.json({ message: "Máquina excluída com sucesso" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao excluir máquina", details: error.message });
  }
});

// ROTAS DE COMPRAS (PURCHASES)
app.get("/api/purchases", async (req, res) => res.json(await prisma.purchase.findMany()));

app.get("/api/purchases/:id", async (req, res) => {
  const purchase = await prisma.purchase.findUnique({
    where: { id: parseInt(req.params.id) },
  });
  res.json(purchase || { error: "Compra não encontrada" });
});

app.post("/api/purchases", async (req, res) => {
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

app.put("/api/purchases/:id", async (req, res) => {
  try {
    const { product, quantity, total, date, clientId } = req.body;

    // Converter quantity para um número inteiro
    const parsedQuantity = parseInt(quantity, 10);
    if (isNaN(parsedQuantity)) {
      return res.status(400).json({ error: "Quantidade deve ser um número válido." });
    }

    const updatedPurchase = await prisma.purchase.update({
      where: { id: parseInt(req.params.id) },
      data: { product, quantity: parsedQuantity, total, date, clientId },
    });

    res.json(updatedPurchase);
  } catch (error) {
    res.status(500).json({ error: "Erro ao atualizar compra", details: error.message });
  }
});

app.delete("/api/purchases/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({ error: "ID inválido" });
    }

    await prisma.purchase.delete({ where: { id } });
    res.json({ message: "Compra excluída com sucesso" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao excluir compra", details: error.message });
  }
});

// ROTAS DE PAGAMENTOS
app.get("/api/payments", async (req, res) => res.json(await prisma.payment.findMany()));

app.get("/api/payments/:id", async (req, res) => {
  const payment = await prisma.payment.findUnique({
    where: { id: parseInt(req.params.id) },
  });
  res.json(payment || { error: "Pagamento não encontrado" });
});

app.post("/api/payments", async (req, res) => res.json(await prisma.payment.create({ data: req.body })));

app.put("/api/payments/:id", async (req, res) => {
  try {
    const { amount, date, clientId } = req.body;

    const formattedDate = new Date(date).toISOString();

    const updatedPayment = await prisma.payment.update({
      where: { id: parseInt(req.params.id) },
      data: { amount, date: formattedDate, clientId },
    });

    res.json(updatedPayment);
  } catch (error) {
    res.status(500).json({ error: "Erro ao atualizar pagamento", details: error.message });
  }
});

app.delete("/api/payments/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({ error: "ID inválido" });
    }

    await prisma.payment.delete({ where: { id } });
    res.json({ message: "Pagamento excluído com sucesso" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao excluir pagamento", details: error.message });
  }
});

// ROTAS DE LEITURAS DIÁRIAS
app.get("/api/daily-readings", async (req, res) => {
  const { machineId, date } = req.query;

  let whereClause = {
    machineId: parseInt(machineId),
  };

  if (date) {
    // Parse a data de entrada e formate-a como "dd-MM-yyyy"
    whereClause.date = { contains: date };
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

app.get("/api/daily-readings/:id", async (req, res) => {
  const dailyReading = await prisma.dailyReading.findUnique({
    where: { id: parseInt(req.params.id) },
  });
  res.json(dailyReading || { error: "Leitura diária não encontrada" });
});

app.post("/api/daily-readings", async (req, res) => {
  const { date, value, machineId } = req.body;
  res.json(await prisma.dailyReading.create({ data: { date: date, value, machineId } }));
});

app.put("/api/daily-readings/:id", async (req, res) => {
  try {
    const { date, value, machineId } = req.body;
    const formattedDate = format(date, "dd-MM-yyyy"); // Formata a data para "dd-MM-yyyy"

    const updatedDailyReading = await prisma.dailyReading.update({
      where: { id: parseInt(req.params.id) },
      data: { date: formattedDate, value, machineId },
    });

    res.json(updatedDailyReading);
  } catch (error) {
    res.status(500).json({ error: "Erro ao atualizar leitura diária", details: error.message });
  }
});

app.delete("/api/daily-readings/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({ error: "ID inválido" });
    }

    await prisma.dailyReading.delete({ where: { id } });
    res.json({ message: "Leitura diária excluída com sucesso" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao excluir leitura diária", details: error.message });
  }
});

// ROTAS DE PRODUTOS (CORREÇÃO DO ERRO `quantity`)
app.get("/api/estoque_prod", async (req, res) => res.json(await prisma.product.findMany()));

app.get("/api/estoque_prod/:id", async (req, res) => {
  const product = await prisma.product.findUnique({
    where: { id: parseInt(req.params.id) },
  });
  res.json(product || { error: "Produto não encontrado" });
});

app.post("/api/estoque_prod", async (req, res) => {
  try {
    const { name, quantity, unit, value, valuecusto } = req.body;

    if (!name || !quantity || !unit) {
      return res.status(400).json({ error: "Todos os campos são obrigatórios." });
    }

    const parsedQuantity = parseInt(quantity, 10);
    if (isNaN(parsedQuantity)) {
      return res.status(400).json({ error: "Quantidade deve ser um número válido." });
    }

    const parsedValue = parseFloat(value, 10);
    if (isNaN(parsedValue)) {
      return res.status(400).json({ error: "Valor deve ser um número válido." });
    }

    const parsedValueCusto = parseFloat(valuecusto, 10);
    if (isNaN(parsedValueCusto)) {
      return res.status(400).json({ error: "Custo deve ser um número válido." });
    }

    const newProduct = await prisma.product.create({
      data: { name, quantity: parsedQuantity, unit, value: parsedValue, valuecusto: parsedValueCusto },
    });

    res.status(201).json(newProduct);
  } catch (error) {
    res.status(500).json({ error: "Erro ao criar produto", details: error.message });
  }
});

app.put("/api/estoque_prod/:id", async (req, res) => {
  try {
    const { name, quantity, unit, value, valuecusto } = req.body;

    if (!name || !quantity || !unit) {
      return res.status(400).json({ error: "Todos os campos são obrigatórios." });
    }

    const parsedQuantity = parseInt(quantity, 10);
    if (isNaN(parsedQuantity)) {
      return res.status(400).json({ error: "Quantidade deve ser um número válido." });
    }

    const parsedValue = parseFloat(value, 10);
    if (isNaN(parsedValue)) {
      return res.status(400).json({ error: "Valor deve ser um número válido." });
    }

    const parsedValueCusto = parseFloat(valuecusto, 10);
    if (isNaN(parsedValueCusto)) {
      return res.status(400).json({ error: "Custo deve ser um número válido." });
    }

    const updatedProduct = await prisma.product.update({
      where: { id: parseInt(req.params.id) },
      data: { name, quantity: parsedQuantity, unit, value: parsedValue, valuecusto: parsedValueCusto },
    });

    res.json(updatedProduct);
  } catch (error) {
    res.status(500).json({ error: "Erro ao atualizar produto", details: error.message });
  }
});

app.delete("/api/estoque_prod/:id", async (req, res) => {
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
// ROTAS DE PRODUTOS (CORREÇÃO DO ERRO `quantity`)
app.get("/api/products", async (req, res) => res.json(await prisma.product.findMany({
  include: { category: true }
})));

app.get("/api/products/:id", async (req, res) => {
  const product = await prisma.product.findUnique({
    where: { id: parseInt(req.params.id) },
    include: { category: true }
  });
  res.json(product || { error: "Produto não encontrado" });
});

app.post("/api/products", async (req, res) => {
  try {
    const { name, quantity, unit, value, valuecusto, categoryId } = req.body;

    if (!name || !quantity || !unit) {
      return res.status(400).json({ error: "Todos os campos são obrigatórios." });
    }

    const parsedQuantity = parseInt(quantity, 10);
    if (isNaN(parsedQuantity)) {
      return res.status(400).json({ error: "Quantidade deve ser um número válido." });
    }

    const parsedValue = parseFloat(value, 10);
    if (isNaN(parsedValue)) {
      return res.status(400).json({ error: "Valor deve ser um número válido." });
    }

    const parsedValueCusto = parseFloat(valuecusto, 10);
    if (isNaN(parsedValueCusto)) {
      return res.status(400).json({ error: "Custo deve ser um número válido." });
    }

    const newProduct = await prisma.product.create({
      data: { 
        name, 
        quantity: parsedQuantity, 
        unit, 
        value: parsedValue, 
        valuecusto: parsedValueCusto,
        categoryId: categoryId || null
      },
      include: { category: true }
    });

    res.status(201).json(newProduct);
  } catch (error) {
    res.status(500).json({ error: "Erro ao criar produto", details: error.message });
  }
});

app.put("/api/products/:id", async (req, res) => {
  try {
    const { name, quantity, unit, value, valuecusto, categoryId } = req.body;

    if (!name || !quantity || !unit) {
      return res.status(400).json({ error: "Todos os campos são obrigatórios." });
    }

    const parsedQuantity = parseInt(quantity, 10);
    if (isNaN(parsedQuantity)) {
      return res.status(400).json({ error: "Quantidade deve ser um número válido." });
    }

    const parsedValue = parseFloat(value, 10);
    if (isNaN(parsedValue)) {
      return res.status(400).json({ error: "Valor deve ser um número válido." });
    }

    const parsedValueCusto = parseFloat(valuecusto, 10);
    if (isNaN(parsedValueCusto)) {
      return res.status(400).json({ error: "Custo deve ser um número válido." });
    }

    const updatedProduct = await prisma.product.update({
      where: { id: parseInt(req.params.id) },
      data: { 
        name, 
        quantity: parsedQuantity, 
        unit, 
        value: parsedValue, 
        valuecusto: parsedValueCusto,
        categoryId: categoryId || null
      },
      include: { category: true }
    });

    res.json(updatedProduct);
  } catch (error) {
    res.status(500).json({ error: "Erro ao atualizar produto", details: error.message });
  }
});

app.delete("/api/products/:id", async (req, res) => {
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
app.get("/api/balances", async (req, res) => res.json(await prisma.balance.findMany()));

app.get("/api/balances/:id", async (req, res) => {
  const balance = await prisma.balance.findUnique({
    where: { id: parseInt(req.params.id) },
  });
  res.json(balance || { error: "Saldo não encontrado" });
});

app.post("/api/balances", async (req, res) => {
  const { date, balance, cartao, dinheiro } = req.body;
  res.json(await prisma.balance.create({ data: { date, balance, cartao, dinheiro } }));
});

app.put("/api/balances/:id", async (req, res) => {
  res.json(await prisma.balance.update({ where: { id: parseInt(req.params.id) }, data: req.body }));
});

app.delete("/api/balances/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({ error: "ID inválido" });
    }

    await prisma.balance.delete({ where: { id } });
    res.json({ message: "Saldo excluído com sucesso" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao excluir saldo", details: error.message });
  }
});

// ROTAS DE DESPESAS
app.get("/api/despesas", async (req, res) => {
  try {
    const despesas = await prisma.despesa.findMany();
    res.json(despesas);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar despesas", details: error.message });
  }
});

app.get("/api/despesas/:id", async (req, res) => {
  try {
    const despesa = await prisma.despesa.findUnique({
      where: { id: parseInt(req.params.id) },
    });
    res.json(despesa || { error: "Despesa não encontrada" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar despesa", details: error.message });
  }
});

app.post("/api/despesas", async (req, res) => {
  try {
    const { nomeDespesa, valorDespesa, descDespesa, date, DespesaFixa } = req.body;
    console.log("Dados recebidos:", req.body); // Log dos dados recebidos

    // Construir dinamicamente o objeto data
    const parsedDate = new Date(date.replace(" ", "T"));

    const data = { nomeDespesa, date: parsedDate, DespesaFixa };
    if (valorDespesa !== undefined) data.valorDespesa = valorDespesa;
    if (descDespesa !== undefined) data.descDespesa = descDespesa;

    const newDespesa = await prisma.despesa.create({
      data,
    });
    res.status(201).json(newDespesa);
  } catch (error) {
    res.status(500).json({ error: "Erro ao criar despesa", details: error.message });
  }
});

app.put("/api/despesas/:id", async (req, res) => {
  try {
    const { nomeDespesa, valorDespesa, descDespesa } = req.body;
    const updatedDespesa = await prisma.despesa.update({
      where: { id: parseInt(req.params.id) },
      data: { nomeDespesa, valorDespesa, descDespesa },
    });
    res.json(updatedDespesa);
  } catch (error) {
    res.status(500).json({ error: "Erro ao atualizar despesa", details: error.message });
  }
});

app.delete("/api/despesas/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({ error: "ID inválido" });
    }

    await prisma.despesa.delete({ where: { id } });
    res.json({ message: "Despesa excluída com sucesso" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao excluir despesa", details: error.message });
  }
});

// ROTAS DE FUNCIONÁRIOS
app.get("/api/employees", async (req, res) => {
  try {
    const employees = await prisma.employee.findMany({
      include: { points: true }, // Inclui os pontos diários relacionados
    });

    // Adiciona um valor padrão para dailyHours se estiver null
    const employeesWithDefaults = employees.map((employee) => ({
      ...employee,
      carga: employee.carga || 8, // Define 8 como valor padrão
    }));

    res.json(employeesWithDefaults);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar funcionários", details: error.message });
  }
});

app.get("/api/employees/:id", async (req, res) => {
  try {
    const employee = await prisma.employee.findUnique({
      where: { id: parseInt(req.params.id) },
      include: { points: true }, // Inclui os pontos diários relacionados
    });
    if (!employee) {
      return res.status(404).json({ error: "Funcionário não encontrado" });
    }
    res.json(employee);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar funcionário", details: error.message });
  }
});

app.post("/api/employees", async (req, res) => {
  try {
    const { name, position, carga = 8 } = req.body; // Define 8 como valor padrão
    const newEmployee = await prisma.employee.create({
      data: { name, position, carga },
    });
    res.status(201).json(newEmployee);
  } catch (error) {
    res.status(500).json({ error: "Erro ao criar funcionário", details: error.message });
  }
});

app.put("/api/employees/:id", async (req, res) => {
  try {
    const { name, position, carga } = req.body;
    const updatedEmployee = await prisma.employee.update({
      where: { id: parseInt(req.params.id) },
      data: { name, position, carga },
    });
    res.json(updatedEmployee);
  } catch (error) {
    res.status(500).json({ error: "Erro ao atualizar funcionário", details: error.message });
  }
});

app.delete("/api/employees/:id", async (req, res) => {
  try {
    await prisma.employee.delete({
      where: { id: parseInt(req.params.id) },
    });
    res.json({ message: "Funcionário excluído com sucesso" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao excluir funcionário", details: error.message });
  }
});

// ROTAS DE PONTOS DIÁRIOS
app.get("/api/daily-points", async (req, res) => {
  try {
    const { employeeId, date } = req.query;

    let where = {};
    if (employeeId) {
      where.employeeId = parseInt(employeeId);
    }

    if (date) {
      // Verifica se a data está no formato "YYYY-MM"

      const [year, month] = date.split("-");
      const startDate = new Date(`${year}-${month}-01T00:00:00.000Z`);
      // Pega o primeiro dia do mês seguinte
      const endDate = new Date(startDate);
      endDate.setMonth(endDate.getMonth() + 1);

      where.date = {
        gte: startDate,
        lt: endDate,
      };
    }

    const points = await prisma.dailyPoint.findMany({
      where,
      include: { employee: true },
    });
    res.json(points);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar pontos diários", details: error.message });
  }
});

app.get("/api/daily-points/:id", async (req, res) => {
  try {
    const employeeId = parseInt(req.params.id);
    const { date } = req.query;
    const usedDate = date ? new Date(date).toISOString().split("T")[0] : new Date().toISOString().split("T")[0];

    const point = await prisma.dailyPoint.findFirst({
      where: {
        employeeId,
        date: {
          gte: new Date(`${usedDate}T00:00:00.000Z`),
          lt: new Date(`${usedDate}T23:59:59.999Z`),
        },
      },
      include: { employee: true },
    });
    if (!point) {
      return res.json(null);
    }
    res.json(point);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar ponto diário", details: error.message });
  }
});

app.post("/api/daily-points", async (req, res) => {
  try {
    const { date, entry, exit, gateOpen, employeeId } = req.body;

    // Função para combinar data e hora
    const combineDateAndTime = (dateStr, timeStr) => {
      if (!dateStr || !timeStr) return null;
      return new Date(`${dateStr}T${timeStr}:00.000Z`);
    };

    const entryDateTime = combineDateAndTime(date, entry);
    const exitDateTime = combineDateAndTime(date, exit);
    const gateOpenDateTime = combineDateAndTime(date, gateOpen);

    const newPoint = await prisma.dailyPoint.create({
      data: {
        date: new Date(date),
        entry: entryDateTime,
        exit: exitDateTime,
        gateOpen: gateOpenDateTime,
        employeeId,
      },
    });
    res.status(201).json(newPoint);
  } catch (error) {
    res.status(500).json({ error: "Erro ao criar ponto diário", details: error.message });
  }
});

app.put("/api/daily-points/:id", async (req, res) => {
  try {
    const PontoId = parseInt(req.params.id);
    const { entry, exit, gateOpen, date } = req.body; // Adicione 'date' aqui

    // Use a data enviada pelo front-end, ou a data atual como fallback
    const usedDate = date ? new Date(date).toISOString().split("T")[0] : new Date().toISOString().split("T")[0];

    const combineDateAndTime = (date, time) => {
      if (!time) return null;
      return new Date(`${date}T${time}:00.000Z`);
    };

    const entryDateTime = combineDateAndTime(usedDate, entry);
    const exitDateTime = combineDateAndTime(usedDate, exit);
    const gateOpenDateTime = combineDateAndTime(usedDate, gateOpen);

    let existingPoint = await prisma.dailyPoint.findFirst({
      where: {
        id: PontoId,
      },
    });

    if (!existingPoint) {
      existingPoint = await prisma.dailyPoint.create({
        data: {
          date: new Date(usedDate),
          entry: entryDateTime,
          exit: exitDateTime,
          gateOpen: gateOpenDateTime,
          employeeId,
        },
      });

      return res.status(201).json({
        message: "Registro criado para o dia informado.",
        point: existingPoint,
      });
    }

    const updatedPoint = await prisma.dailyPoint.update({
      where: { id: existingPoint.id },
      data: {
        entry: entryDateTime || existingPoint.entry,
        exit: exitDateTime || existingPoint.exit,
        gateOpen: gateOpenDateTime || existingPoint.gateOpen,
      },
    });

    res.status(200).json({
      message: "Registro atualizado com sucesso.",
      point: updatedPoint,
    });
  } catch (error) {
    console.error("Erro ao atualizar ou criar ponto diário:", error);
    res.status(500).json({
      error: "Erro ao atualizar ou criar ponto diário",
      details: error.message,
    });
  }
});

app.put("/api/daily-points/falta/:id", async (req, res) => {
  try {
    const employeeId = parseInt(req.params.id);
    const { entry, exit, gateOpen, date } = req.body; // Adicione 'date' aqui

    // Use a data enviada pelo front-end, ou a data atual como fallback
    const usedDate = date ? new Date(date).toISOString().split("T")[0] : new Date().toISOString().split("T")[0];

    const combineDateAndTime = (date, time) => {
      if (!time) return null;
      return new Date(`${date}T${time}:00.000Z`);
    };

    const entryDateTime = combineDateAndTime(usedDate, entry);
    const exitDateTime = combineDateAndTime(usedDate, exit);
    const gateOpenDateTime = combineDateAndTime(usedDate, gateOpen);

    let existingPoint = await prisma.dailyPoint.findFirst({
      where: {
        employeeId: employeeId,
        date: {
          gte: new Date(`${usedDate}T00:00:00.000Z`),
          lt: new Date(`${usedDate}T23:59:59.999Z`),
        },
      },
    });

    if (!existingPoint) {
      existingPoint = await prisma.dailyPoint.create({
        data: {
          date: new Date(usedDate),
          entry: entryDateTime,
          exit: exitDateTime,
          gateOpen: gateOpenDateTime,
          employeeId,
        },
      });

      return res.status(201).json({
        message: "Registro criado para o dia informado.",
        point: existingPoint,
      });
    }

    const updatedPoint = await prisma.dailyPoint.update({
      where: { id: existingPoint.id },
      data: {
        entry: null,
        exit: null,
        gateOpen: null,
        falta: true,
      },
    });

    res.status(200).json({
      message: "Registro atualizado com sucesso.",
      point: updatedPoint,
    });
  } catch (error) {
    console.error("Erro ao atualizar ou criar ponto diário:", error);
    res.status(500).json({
      error: "Erro ao atualizar ou criar ponto diário",
      details: error.message,
    });
  }
});

app.put("/api/daily-points/falta-manual/:id", async (req, res) => {
  try {
    const employeeId = parseInt(req.params.id);
    const { entry, exit, gateOpen, date } = req.body; // Adicione 'date' aqui

    // Use a data enviada pelo front-end, ou a data atual como fallback
    const usedDate = date ? new Date(date).toISOString().split("T")[0] : new Date().toISOString().split("T")[0];

    const combineDateAndTime = (date, time) => {
      if (!time) return null;
      return new Date(`${date}T${time}:00.000Z`);
    };

    let existingPoint = await prisma.dailyPoint.findFirst({
      where: {
        employeeId: employeeId,
        date: {
          gte: new Date(`${usedDate}T00:00:00.000Z`),
          lt: new Date(`${usedDate}T23:59:59.999Z`),
        },
      },
    });

    if (!existingPoint) {
      existingPoint = await prisma.dailyPoint.create({
        data: {
          date: new Date(usedDate),
          entry: null,
          exit: null,
          gateOpen: null,
          falta: true,
          employeeId: employeeId,
        },
      });

      return res.status(201).json({
        message: "Registro criado para o dia informado.",
        point: existingPoint,
      });
    }

    const updatedPoint = await prisma.dailyPoint.update({
      where: { id: existingPoint.id },
      data: {
        entry: null,
        exit: null,
        gateOpen: null,
        falta: true,
      },
    });

    res.status(200).json({
      message: "Registro atualizado com sucesso.",
      point: updatedPoint,
    });
  } catch (error) {
    console.error("Erro ao atualizar ou criar ponto diário:", error);
    res.status(500).json({
      error: "Erro ao atualizar ou criar ponto diário",
      details: error.message,
    });
  }
});

app.delete("/api/daily-points/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({ error: "ID inválido" });
    }

    await prisma.dailyPoint.delete({ where: { id } });
    res.json({ message: "Registro de DailyPoint excluído com sucesso." });
  } catch (error) {
    console.error("Erro ao excluir registro de DailyPoint:", error);
    res.status(500).json({ error: "Erro ao excluir registro de DailyPoint", details: error.message });
  }
});

app.delete("/api/daily-points", async (req, res) => {
  const { employeeId, date } = req.query;
  if (!employeeId) {
    return res.status(400).json({ error: "employeeId é obrigatório" });
  }

  // Se quiser filtrar também por data:
  let where = { employeeId: parseInt(employeeId) };
  if (date) {
    const usedDate = new Date(date).toISOString().split("T")[0];
    where.date = {
      gte: new Date(`${usedDate}T00:00:00.000Z`),
      lt: new Date(`${usedDate}T23:59:59.999Z`),
    };
  }

  try {
    const result = await prisma.dailyPoint.deleteMany({ where });
    res.json({ message: "Registros de DailyPoints excluídos com sucesso.", count: result.count });
  } catch (error) {
    console.error("Erro ao excluir registros de DailyPoints:", error);
    res.status(500).json({ error: "Erro ao excluir registros de DailyPoints", details: error.message });
  }
});

// ROTA DE RECUPERAÇÃO DE SENHA

app.post("/api/forgot-password", async (req, res) => {
  const { email } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { username: email } });
    if (!user) {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }

    const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: "1h" });

    await sendResetEmail(email, token); // Função para enviar o e-mail
    res.json({ message: "E-mail de redefinição enviado com sucesso" });
  } catch (error) {
    console.error("Erro ao processar redefinição de senha:", error);
    res.status(500).json({ message: "Erro ao processar redefinição de senha" });
  }
});

app.post("/api/reset-password", async (req, res) => {
  const { token, newPassword } = req.body;

  try {
    // Verifica e decodifica o token JWT
    const decoded = jwt.verify(token, SECRET_KEY);

    // Atualiza a senha do usuário
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await prisma.user.update({
      where: { username: decoded.email },
      data: { password: hashedPassword },
    });

    res.json({ message: "Senha redefinida com sucesso" });
  } catch (error) {
    console.error("Erro ao redefinir senha:", error);
    res.status(400).json({ message: "Token inválido ou expirado" });
  }
});

app.post("/api/validate-token", (req, res) => {
  const { token } = req.body;

  try {
    jwt.verify(token, SECRET_KEY);
    res.json({ message: "Token válido" });
  } catch (error) {
    console.error("Token inválido ou expirado:", error);
    res.status(401).json({ message: "Token inválido ou expirado" });
  }
});

// ROTAS DE DESPESAS (CADASTRO)
app.get("/api/cadastrodesp", async (req, res) => res.json(await prisma.CadDespesa.findMany()));

app.get("/api/cadastrodesp/:id", async (req, res) => {
  const CadDespesa = await prisma.CadDespesa.findUnique({
    where: { id: parseInt(req.params.id) },
  });
  res.json(CadDespesa || { error: "Despesa não encontrada" });
});

app.post("/api/cadastrodesp", async (req, res) => {
  try {
    const { nomeDespesa } = req.body;
    const newDespesa = await prisma.CadDespesa.create({
      data: { nomeDespesa },
    });

    res.status(201).json(newDespesa);
  } catch (error) {
    res.status(500).json({ error: "Erro ao criar Despesa", details: error.message });
  }
});

app.put("/api/cadastrodesp/:id", async (req, res) => {
  try {
    const { nomeDespesa } = req.body;
    const updatedDespesa = await prisma.CadDespesa.update({
      where: { id: parseInt(req.params.id) },
      data: { nomeDespesa },
    });

    res.json(updatedDespesa);
  } catch (error) {
    res.status(500).json({ error: "Erro ao atualizar compra", details: error.message });
  }
});

app.delete("/api/cadastrodesp/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({ error: "ID inválido" });
    }

    await prisma.CadDespesa.delete({ where: { id } });
    res.json({ message: "Despesa excluída com sucesso" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao excluir compra", details: error.message });
  }
});

// CRUD para valor da máquina por semana
app.get("/api/machine-week-value", async (req, res) => {
  const { year, month, week } = req.query;
  const where = {};
  if (year) where.year = parseInt(year);
  if (month) where.month = parseInt(month);
  if (week) where.week = parseInt(week);
  try {
    const values = await prisma.machineWeekValue.findMany({ where });
    res.json(values);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar valores da máquina", details: error.message });
  }
});

app.post("/api/machine-week-value", async (req, res) => {
  const { year, month, week, value } = req.body;
  try {
    // Se já existe, atualiza; senão, cria
    const existing = await prisma.machineWeekValue.findFirst({ where: { year, month, week } });
    let result;
    if (existing) {
      result = await prisma.machineWeekValue.update({
        where: { id: existing.id },
        data: { value },
      });
    } else {
      result = await prisma.machineWeekValue.create({
        data: { year, month, week, value },
      });
    }
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: "Erro ao salvar valor da máquina", details: error.message });
  }
});

// ROTA DE CATEGORIA
app.get("/api/categories", async (req, res) => {
  const categories = await prisma.category.findMany({
    include: { products: true },
  });
  res.json(categories);
});

app.post("/api/categories", async (req, res) => {
  const { name } = req.body;
  const category = await prisma.category.create({ data: { name } });
  res.json(category);
});

app.delete("/api/categories/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({ error: "ID inválido" });
    }

    await prisma.category.delete({ where: { id } });
    res.json({ message: "Categoria excluída com sucesso" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao excluir categoria", details: error.message });
  }
});

// Rota para criar uma nova venda (PDV)
app.post('/api/sales', async (req, res) => {
  try {
    const { items, total, paymentMethod, customerName, amountReceived, change, date } = req.body;
    
    // Criar registro da venda
    const sale = await prisma.sale.create({
      data: {
        total: parseFloat(total),
        paymentMethod,
        customerName,
        amountReceived: parseFloat(amountReceived) || total,
        change: parseFloat(change) || 0,
        date: parseISO(date),
        items: {
          create: items.map(item => ({
            productId: item.id,
            productName: item.name,
            quantity: item.quantity,
            unitPrice: item.price,
            total: item.price * item.quantity
          }))
        }
      },
      include: {
        items: true
      }
    });

    res.status(201).json(sale);
  } catch (error) {
    console.error('Erro ao criar venda:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rota para buscar vendas
app.get('/api/sales', async (req, res) => {
  try {
    const sales = await prisma.sale.findMany({
      include: {
        items: true
      },
      orderBy: {
        date: 'desc'
      }
    });
    
    res.json(sales);
  } catch (error) {
    console.error('Erro ao buscar vendas:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.get('/api/unit-equivalences', async (req, res) => {
  try {
    const equivalences = await prisma.unitEquivalence.findMany({
      orderBy: { unitName: 'asc' }
    });
    res.json(equivalences);
  } catch (error) {
    console.error('Erro ao buscar equivalências:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// POST /api/unit-equivalences - Criar nova equivalência
app.post('/api/unit-equivalences', async (req, res) => {
  try {
    const { unitName, value } = req.body;
    
    if (!unitName || !value || value <= 0) {
      return res.status(400).json({ error: 'Nome da unidade e valor são obrigatórios' });
    }

    // Verificar se já existe equivalência para esta unidade
    const existingEquivalence = await prisma.unitEquivalence.findUnique({
      where: { unitName }
    });

    if (existingEquivalence) {
      return res.status(409).json({ error: 'Unidade já possui equivalência definida' });
    }

    const equivalence = await prisma.unitEquivalence.create({
      data: { 
        unitName, 
        value: parseFloat(value) 
      }
    });
    
    res.status(201).json(equivalence);
  } catch (error) {
    console.error('Erro ao criar equivalência:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// PUT /api/unit-equivalences/:unitName - Atualizar equivalência
app.put('/api/unit-equivalences/:unitName', async (req, res) => {
  try {
    const { unitName } = req.params;
    const { value } = req.body;
    
    if (!value || value <= 0) {
      return res.status(400).json({ error: 'Valor é obrigatório e deve ser maior que zero' });
    }

    const equivalence = await prisma.unitEquivalence.update({
      where: { unitName },
      data: { value: parseFloat(value) }
    });
    
    res.json(equivalence);
  } catch (error) {
    if (error.code === 'P2025') {
      return res.status(404).json({ error: 'Equivalência não encontrada' });
    }
    console.error('Erro ao atualizar equivalência:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// DELETE /api/unit-equivalences/:unitName - Deletar equivalência
app.delete('/api/unit-equivalences/:unitName', async (req, res) => {
  try {
    const { unitName } = req.params;
    
    await prisma.unitEquivalence.delete({
      where: { unitName }
    });
    
    res.json({ message: 'Equivalência excluída com sucesso' });
  } catch (error) {
    if (error.code === 'P2025') {
      return res.status(404).json({ error: 'Equivalência não encontrada' });
    }
    console.error('Erro ao excluir equivalência:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// ROTA DE TESTE
// Middleware para servir os arquivos estáticos do React
app.use(express.static(path.join(__dirname, "dist")));

// Redireciona todas as requisições que não sejam da API para o React
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "dist", "index.html"));
});

// MIDDLEWARE GLOBAL DE ERRO
app.use((err, req, res, next) => {
  console.error("Erro:", err);
  res.status(500).json({ error: "Erro interno do servidor", details: err.message });
});

app.listen(port, () => {
  console.log(`Server tá on krai --> http://localhost:${port}`);
});
