require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const { PrismaClient } = require("@prisma/client");
const { format, parse, parseISO } = require("date-fns");
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
app.use(express.json({ limit: "15mb" }));
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

// Mapeamento de rotas para módulos (para auditoria)
const rotaParaModulo = (rota) => {
  if (rota.includes("/api/balance")) return "caixa";
  if (rota.includes("/api/sales")) return "pdv";
  if (rota.includes("/api/estoque")) return "pdv";
  if (rota.includes("/api/pdv-caixa") || rota.includes("/api/pdv-origens")) return "pdv";
  if (rota.includes("/api/products")) return "produtos";
  if (rota.includes("/api/categories")) return "estoque";
  if (rota.includes("/api/unit-equivalences")) return "estoque";
  if (rota.includes("/api/stock-movements")) return "estoque";
  if (rota.includes("/api/machines")) return "maquinas";
  if (rota.includes("/api/machine-week")) return "maquinas";
  if (rota.includes("/api/daily-readings")) return "maquinas";
  if (rota.includes("/api/clients")) return "fiado";  
  if (rota.includes("/api/purchases")) return "fiado";
  if (rota.includes("/api/payments")) return "fiado";
  if (rota.includes("/api/despesas") || rota.includes("/api/cadastrodesp")) return "despesas";
  if (rota.includes("/api/desp-pessoal") || rota.includes("/api/cat-desp-pessoal")) return "pessoal";
  if (rota.includes("/api/employees") || rota.includes("/api/daily-points") || rota.includes("/api/weekly-meta")) return "ponto";
  if (rota.includes("/api/users")) return "acessos";
  if (rota.includes("/api/register")) return "acessos";
  if (rota.includes("/api/login")) return "autenticacao";
  return "outro";
};

// Middleware de auditoria - registra ações no banco
const auditoriaMiddleware = async (req, res, next) => {
  // Ignora rotas de auditoria para evitar loop
  if (req.path.includes("/api/auditoria")) return next();
  // Ignora rotas estáticas e de validação de token
  if (!req.path.startsWith("/api/")) return next();
  if (req.path === "/api/validate-token") return next();
  // Ignora requisições GET para não poluir a auditoria
  if (req.method === "GET") return next();

  // Captura a resposta original
  const originalJson = res.json.bind(res);
  res.json = async (body) => {
    try {
      const modulo = rotaParaModulo(req.path);
      const acao = req.method;

      // Verifica se o módulo está configurado para auditoria
      const config = await prisma.auditoriaConfig.findUnique({ where: { modulo } });
      if (config && !config.ativo) {
        return originalJson(body);
      }

      // Tenta obter dados do usuário a partir do token JWT
      let userId = req.userId || null;
      let userName = null;

      // Tenta extrair userId do token mesmo sem authenticate middleware
      if (!userId) {
        try {
          const authHeader = req.headers.authorization;
          if (authHeader && authHeader.startsWith("Bearer ")) {
            const token = authHeader.split(" ")[1];
            const decoded = jwt.verify(token, SECRET_KEY);
            userId = decoded.userId || null;
          }
        } catch (e) { /* token inválido ou ausente, ignora */ }
      }

      if (userId) {
        try {
          const user = await prisma.user.findUnique({ where: { id: userId } });
          userName = user?.name || user?.username || null;
        } catch (e) { /* ignora */ }
      }
      // Para login, captura do body da resposta
      if (req.path === "/api/login" && body?.username) {
        userName = body.name || body.username;
      }

      // Resumo do payload (limita tamanho)
      let payload = null;
      if (req.body && Object.keys(req.body).length > 0) {
        const bodyClone = { ...req.body };
        delete bodyClone.password; // Remove senha por segurança
        payload = JSON.stringify(bodyClone).substring(0, 1000);
      }

      const descricao = `${acao} ${req.path}` + (res.statusCode >= 400 ? ` [ERRO ${res.statusCode}]` : "");

      await prisma.auditoria.create({
        data: {
          modulo,
          acao,
          descricao,
          rota: req.originalUrl || req.path,
          userId,
          userName,
          ip: req.ip || req.connection?.remoteAddress || null,
          payload,
        },
      });
    } catch (err) {
      console.error("Erro ao registrar auditoria:", err.message);
    }
    return originalJson(body);
  };
  next();
};

// Aplica middleware de auditoria globalmente
app.use(auditoriaMiddleware);

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
  const { username, password, name } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await prisma.user.create({ data: { username, password: hashedPassword, name: name || null } });
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
    username: user.username,
    name: user.name,
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
      pessoal: user.pessoal,
      auditoria: user.auditoria,
    },
  });
});

app.put("/api/users/:id", async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { name, caixa, produtos, maquinas, fiado, despesas, ponto, acessos, base_produto, pdv, pessoal, auditoria } = req.body;

    const updateData = { caixa, produtos, maquinas, fiado, despesas, ponto, acessos, base_produto, pdv, pessoal, auditoria };
    if (name !== undefined) updateData.name = name;

    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: updateData,
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

// ROTAS DE ESTOQUE
app.get("/api/estoque_prod", async (req, res) => {
  try {
    const produtos = await prisma.estoque.findMany({
      include: {
        product: true,
        category: { include: { parent: true } },
        composicoes: { include: { opcoes: { include: { estoque: { select: { id: true, name: true, quantity: true } } }, orderBy: { id: 'asc' } } }, orderBy: { ordem: 'asc' } },
        _count: { select: { composicaoOpcoes: true } }
      }
    });
    res.json(produtos);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar estoque", details: error.message });
  }
});

app.get("/api/estoque_prod/:id", async (req, res) => {
  try {
    const product = await prisma.estoque.findUnique({
      where: { id: parseInt(req.params.id) },
      include: {
        product: true,
        category: { include: { parent: true } },
        composicoes: { include: { opcoes: { include: { estoque: { select: { id: true, name: true, quantity: true } } }, orderBy: { id: 'asc' } } }, orderBy: { ordem: 'asc' } }
      }
    });
    res.json(product || { error: "Produto não encontrado" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar produto", details: error.message });
  }
});

// Entrada de estoque - seleciona do catálogo, verifica se já existe, incrementa ou cria
app.post("/api/estoque_prod/entrada", async (req, res) => {
  try {
    const { productId, quantity, unit } = req.body;

    if (!productId || !quantity || !unit) {
      return res.status(400).json({ error: "productId, quantity e unit são obrigatórios." });
    }

    const parsedQuantity = parseInt(quantity, 10);
    if (isNaN(parsedQuantity) || parsedQuantity <= 0) {
      return res.status(400).json({ error: "Quantidade deve ser um número válido maior que zero." });
    }

    // Buscar o produto no catálogo
    const catalogProduct = await prisma.product.findUnique({ 
      where: { id: parseInt(productId) },
      include: { category: { include: { parent: true } } }
    });
    if (!catalogProduct) {
      return res.status(404).json({ error: "Produto não encontrado no catálogo." });
    }

    // Verificar se já existe no estoque com mesmo productId e mesma unidade
    const existingStock = await prisma.estoque.findFirst({
      where: { productId: parseInt(productId), unit: unit }
    });

    const result = await prisma.$transaction(async (tx) => {
      let estoqueItem;

      if (existingStock) {
        // Incrementar quantidade no registro existente
        const previousStock = existingStock.quantity;
        const newStock = previousStock + parsedQuantity;

        estoqueItem = await tx.estoque.update({
          where: { id: existingStock.id },
          data: { 
            quantity: newStock,
            value: catalogProduct.value,
            valuecusto: catalogProduct.valuecusto
          },
          include: { product: true, category: { include: { parent: true } } }
        });

        // Registrar movimentação
        await tx.stockMovement.create({
          data: {
            estoqueId: existingStock.id,
            type: 'ENTRY',
            quantity: parsedQuantity,
            previousStock: previousStock,
            newStock: newStock,
            description: `Entrada de ${parsedQuantity}x ${unit} - ${catalogProduct.name}`,
            referenceType: 'Manual'
          }
        });
      } else {
        // Criar novo registro no estoque
        estoqueItem = await tx.estoque.create({
          data: {
            productId: parseInt(productId),
            name: catalogProduct.name,
            quantity: parsedQuantity,
            unit: unit,
            value: catalogProduct.value,
            valuecusto: catalogProduct.valuecusto,
            categoria_Id: catalogProduct.categoryId || null
          },
          include: { product: true, category: { include: { parent: true } } }
        });

        // Registrar movimentação
        await tx.stockMovement.create({
          data: {
            estoqueId: estoqueItem.id,
            type: 'ENTRY',
            quantity: parsedQuantity,
            previousStock: 0,
            newStock: parsedQuantity,
            description: `Entrada inicial de ${parsedQuantity}x ${unit} - ${catalogProduct.name}`,
            referenceType: 'Manual'
          }
        });
      }

      return estoqueItem;
    });

    res.status(201).json(result);
  } catch (error) {
    console.error("Erro na entrada de estoque:", error);
    res.status(500).json({ error: "Erro ao registrar entrada no estoque", details: error.message });
  }
});

// Conversão de unidades - ex: 1 Fardo (12un) → 12 Unidades
app.post("/api/estoque_prod/converter", async (req, res) => {
  try {
    const { estoqueId, quantityToConvert } = req.body;

    if (!estoqueId || !quantityToConvert) {
      return res.status(400).json({ error: "estoqueId e quantityToConvert são obrigatórios." });
    }

    const parsedQty = parseInt(quantityToConvert, 10);
    if (isNaN(parsedQty) || parsedQty <= 0) {
      return res.status(400).json({ error: "Quantidade deve ser um número válido maior que zero." });
    }

    // Buscar o item no estoque
    const estoqueItem = await prisma.estoque.findUnique({
      where: { id: parseInt(estoqueId) },
      include: { product: true }
    });
    if (!estoqueItem) {
      return res.status(404).json({ error: "Item não encontrado no estoque." });
    }

    if (estoqueItem.unit === "Unidade") {
      return res.status(400).json({ error: "Este item já está em Unidades, não é possível converter." });
    }

    if (estoqueItem.quantity < parsedQty) {
      return res.status(400).json({ 
        error: `Quantidade insuficiente. Disponível: ${estoqueItem.quantity} ${estoqueItem.unit}(s)` 
      });
    }

    // Buscar fator de conversão
    const equivalence = await prisma.unitEquivalence.findUnique({
      where: { unitName: estoqueItem.unit }
    });
    if (!equivalence) {
      return res.status(400).json({ 
        error: `Equivalência não definida para "${estoqueItem.unit}". Cadastre a equivalência primeiro.` 
      });
    }

    const unitsGenerated = parsedQty * equivalence.value;
    const unitValueSell = estoqueItem.value / equivalence.value;
    const unitValueCost = estoqueItem.valuecusto / equivalence.value;

    const result = await prisma.$transaction(async (tx) => {
      // 1. Diminuir quantidade do item original
      const previousStock = estoqueItem.quantity;
      const newStock = previousStock - parsedQty;

      await tx.estoque.update({
        where: { id: estoqueItem.id },
        data: { quantity: newStock }
      });

      // Registrar movimentação de saída (conversão)
      await tx.stockMovement.create({
        data: {
          estoqueId: estoqueItem.id,
          type: 'CONVERSION_OUT',
          quantity: -parsedQty,
          previousStock: previousStock,
          newStock: newStock,
          description: `Conversão: ${parsedQty}x ${estoqueItem.unit} → ${unitsGenerated}x Unidade`,
          referenceType: 'Conversion'
        }
      });

      // 2. Verificar se já existe registro em Unidade para este produto
      const existingUnitStock = await tx.estoque.findFirst({
        where: { productId: estoqueItem.productId, unit: "Unidade" }
      });

      let unitEstoqueItem;
      if (existingUnitStock) {
        const prevUnitStock = existingUnitStock.quantity;
        const newUnitStock = prevUnitStock + unitsGenerated;

        unitEstoqueItem = await tx.estoque.update({
          where: { id: existingUnitStock.id },
          data: { quantity: newUnitStock }
        });

        await tx.stockMovement.create({
          data: {
            estoqueId: existingUnitStock.id,
            type: 'CONVERSION_IN',
            quantity: unitsGenerated,
            previousStock: prevUnitStock,
            newStock: newUnitStock,
            description: `Conversão: ${parsedQty}x ${estoqueItem.unit} → ${unitsGenerated}x Unidade`,
            referenceType: 'Conversion'
          }
        });
      } else {
        unitEstoqueItem = await tx.estoque.create({
          data: {
            productId: estoqueItem.productId,
            name: estoqueItem.name,
            quantity: unitsGenerated,
            unit: "Unidade",
            value: Math.round(unitValueSell * 100) / 100,
            valuecusto: Math.round(unitValueCost * 100) / 100,
            categoria_Id: estoqueItem.categoria_Id
          }
        });

        await tx.stockMovement.create({
          data: {
            estoqueId: unitEstoqueItem.id,
            type: 'CONVERSION_IN',
            quantity: unitsGenerated,
            previousStock: 0,
            newStock: unitsGenerated,
            description: `Conversão: ${parsedQty}x ${estoqueItem.unit} → ${unitsGenerated}x Unidade (novo registro)`,
            referenceType: 'Conversion'
          }
        });
      }

      return {
        origin: { id: estoqueItem.id, name: estoqueItem.name, unit: estoqueItem.unit, removed: parsedQty, remaining: newStock },
        destination: { id: unitEstoqueItem.id, name: estoqueItem.name, unit: "Unidade", added: unitsGenerated, total: unitEstoqueItem.quantity },
        conversionFactor: equivalence.value
      };
    });

    res.json(result);
  } catch (error) {
    console.error("Erro na conversão de unidade:", error);
    res.status(500).json({ error: "Erro ao converter unidade", details: error.message });
  }
});

// Converter Unidades → Unidade empacotada (reverso)
app.post("/api/estoque_prod/converter-reverso", async (req, res) => {
  try {
    const { estoqueId, targetUnit, quantityPacked } = req.body;

    if (!estoqueId || !targetUnit || !quantityPacked) {
      return res.status(400).json({ error: "estoqueId, targetUnit e quantityPacked são obrigatórios." });
    }

    const parsedQty = parseInt(quantityPacked, 10);
    if (isNaN(parsedQty) || parsedQty <= 0) {
      return res.status(400).json({ error: "Quantidade deve ser um número válido maior que zero." });
    }

    // Buscar o item de Unidade no estoque
    const estoqueItem = await prisma.estoque.findUnique({
      where: { id: parseInt(estoqueId) },
      include: { product: true }
    });
    if (!estoqueItem) {
      return res.status(404).json({ error: "Item não encontrado no estoque." });
    }

    if (estoqueItem.unit !== "Unidade") {
      return res.status(400).json({ error: "Este item não está em Unidades. Use a conversão normal." });
    }

    // Buscar fator de conversão da unidade de destino
    const equivalence = await prisma.unitEquivalence.findUnique({
      where: { unitName: targetUnit }
    });
    if (!equivalence) {
      return res.status(400).json({
        error: `Equivalência não definida para "${targetUnit}". Cadastre a equivalência primeiro.`
      });
    }

    const unitsNeeded = parsedQty * equivalence.value;

    if (estoqueItem.quantity < unitsNeeded) {
      return res.status(400).json({
        error: `Unidades insuficientes. Necessário: ${unitsNeeded} un. Disponível: ${estoqueItem.quantity} un.`
      });
    }

    const packedValueSell = estoqueItem.value * equivalence.value;
    const packedValueCost = estoqueItem.valuecusto * equivalence.value;

    const result = await prisma.$transaction(async (tx) => {
      // 1. Diminuir unidades do item original
      const previousStock = estoqueItem.quantity;
      const newStock = previousStock - unitsNeeded;

      await tx.estoque.update({
        where: { id: estoqueItem.id },
        data: { quantity: newStock }
      });

      await tx.stockMovement.create({
        data: {
          estoqueId: estoqueItem.id,
          type: 'CONVERSION_OUT',
          quantity: -unitsNeeded,
          previousStock: previousStock,
          newStock: newStock,
          description: `Conversão reversa: ${unitsNeeded}x Unidade → ${parsedQty}x ${targetUnit}`,
          referenceType: 'Conversion'
        }
      });

      // 2. Verificar se já existe registro nessa unidade para este produto
      const existingPackedStock = await tx.estoque.findFirst({
        where: { productId: estoqueItem.productId, unit: targetUnit }
      });

      let packedEstoqueItem;
      if (existingPackedStock) {
        const prevPackedStock = existingPackedStock.quantity;
        const newPackedStock = prevPackedStock + parsedQty;

        packedEstoqueItem = await tx.estoque.update({
          where: { id: existingPackedStock.id },
          data: { quantity: newPackedStock }
        });

        await tx.stockMovement.create({
          data: {
            estoqueId: existingPackedStock.id,
            type: 'CONVERSION_IN',
            quantity: parsedQty,
            previousStock: prevPackedStock,
            newStock: newPackedStock,
            description: `Conversão reversa: ${unitsNeeded}x Unidade → ${parsedQty}x ${targetUnit}`,
            referenceType: 'Conversion'
          }
        });
      } else {
        packedEstoqueItem = await tx.estoque.create({
          data: {
            productId: estoqueItem.productId,
            name: estoqueItem.name,
            quantity: parsedQty,
            unit: targetUnit,
            value: Math.round(packedValueSell * 100) / 100,
            valuecusto: Math.round(packedValueCost * 100) / 100,
            categoria_Id: estoqueItem.categoria_Id
          }
        });

        await tx.stockMovement.create({
          data: {
            estoqueId: packedEstoqueItem.id,
            type: 'CONVERSION_IN',
            quantity: parsedQty,
            previousStock: 0,
            newStock: parsedQty,
            description: `Conversão reversa: ${unitsNeeded}x Unidade → ${parsedQty}x ${targetUnit} (novo registro)`,
            referenceType: 'Conversion'
          }
        });
      }

      return {
        origin: { id: estoqueItem.id, name: estoqueItem.name, unit: "Unidade", removed: unitsNeeded, remaining: newStock },
        destination: { id: packedEstoqueItem.id, name: estoqueItem.name, unit: targetUnit, added: parsedQty, total: packedEstoqueItem.quantity },
        conversionFactor: equivalence.value
      };
    });

    res.json(result);
  } catch (error) {
    console.error("Erro na conversão reversa:", error);
    res.status(500).json({ error: "Erro ao converter unidade", details: error.message });
  }
});

// Converter qualquer unidade em porções customizadas (ex: Garrafa → Dose)
app.post("/api/estoque_prod/converter-dose", async (req, res) => {
  try {
    const { estoqueId, quantityToConvert, targetUnit, yieldPerUnit, targetValue, targetValueCusto } = req.body;

    if (!estoqueId || !quantityToConvert || !targetUnit || !yieldPerUnit) {
      return res.status(400).json({ error: "estoqueId, quantityToConvert, targetUnit e yieldPerUnit são obrigatórios." });
    }

    const parsedQty = parseInt(quantityToConvert, 10);
    const parsedYield = parseFloat(yieldPerUnit);
    if (isNaN(parsedQty) || parsedQty <= 0 || isNaN(parsedYield) || parsedYield <= 0) {
      return res.status(400).json({ error: "Quantidade e rendimento devem ser números válidos maiores que zero." });
    }

    const estoqueItem = await prisma.estoque.findUnique({
      where: { id: parseInt(estoqueId) },
      include: { product: true }
    });
    if (!estoqueItem) return res.status(404).json({ error: "Item não encontrado no estoque." });
    if (estoqueItem.quantity < parsedQty) {
      return res.status(400).json({ error: `Quantidade insuficiente. Disponível: ${estoqueItem.quantity} ${estoqueItem.unit}(s)` });
    }

    const portionsGenerated = Math.floor(parsedQty * parsedYield);
    const sellValue = parseFloat(targetValue) || (estoqueItem.value / parsedYield);
    const costValue = parseFloat(targetValueCusto) || (estoqueItem.valuecusto / parsedYield);

    const result = await prisma.$transaction(async (tx) => {
      // 1. Reduzir estoque da unidade fonte
      const prevStock = estoqueItem.quantity;
      const newStock = prevStock - parsedQty;
      await tx.estoque.update({ where: { id: estoqueItem.id }, data: { quantity: newStock } });
      await tx.stockMovement.create({
        data: {
          estoqueId: estoqueItem.id, type: 'CONVERSION_OUT',
          quantity: -parsedQty, previousStock: prevStock, newStock: newStock,
          description: `Conversão: ${parsedQty}x ${estoqueItem.unit} → ${portionsGenerated}x ${targetUnit}`,
          referenceType: 'Conversion'
        }
      });

      // 2. Incrementar ou criar registro na unidade destino
      const existingTarget = await tx.estoque.findFirst({
        where: { productId: estoqueItem.productId, unit: targetUnit }
      });

      let targetItem;
      if (existingTarget) {
        const prevTarget = existingTarget.quantity;
        const newTarget = prevTarget + portionsGenerated;
        targetItem = await tx.estoque.update({ where: { id: existingTarget.id }, data: { quantity: newTarget } });
        await tx.stockMovement.create({
          data: {
            estoqueId: existingTarget.id, type: 'CONVERSION_IN',
            quantity: portionsGenerated, previousStock: prevTarget, newStock: newTarget,
            description: `Conversão: ${parsedQty}x ${estoqueItem.unit} → ${portionsGenerated}x ${targetUnit}`,
            referenceType: 'Conversion'
          }
        });
      } else {
        targetItem = await tx.estoque.create({
          data: {
            productId: estoqueItem.productId,
            name: estoqueItem.name,
            quantity: portionsGenerated,
            unit: targetUnit,
            value: Math.round(sellValue * 100) / 100,
            valuecusto: Math.round(costValue * 100) / 100,
            categoria_Id: estoqueItem.categoria_Id
          }
        });
        await tx.stockMovement.create({
          data: {
            estoqueId: targetItem.id, type: 'CONVERSION_IN',
            quantity: portionsGenerated, previousStock: 0, newStock: portionsGenerated,
            description: `Conversão: ${parsedQty}x ${estoqueItem.unit} → ${portionsGenerated}x ${targetUnit} (novo registro)`,
            referenceType: 'Conversion'
          }
        });
      }

      return {
        origin: { id: estoqueItem.id, name: estoqueItem.name, unit: estoqueItem.unit, removed: parsedQty, remaining: newStock },
        destination: { id: targetItem.id, name: estoqueItem.name, unit: targetUnit, added: portionsGenerated, total: targetItem.quantity },
        yieldPerUnit: parsedYield
      };
    });

    res.json(result);
  } catch (error) {
    console.error("Erro na conversão de dose:", error);
    res.status(500).json({ error: "Erro ao converter em porções", details: error.message });
  }
  try {
    const { name, quantity, unit, value, valuecusto, categoryId, productId } = req.body;

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

    const newProduct = await prisma.estoque.create({
      data: { 
        name, 
        quantity: parsedQuantity, 
        unit, 
        value: parsedValue, 
        valuecusto: parsedValueCusto,
        categoria_Id: categoryId ? parseInt(categoryId) : null,
        productId: productId ? parseInt(productId) : null
      },
      include: {
        product: true,
        category: {
          include: {
            parent: true
          }
        }
      }
    });

    res.status(201).json(newProduct);
  } catch (error) {
    res.status(500).json({ error: "Erro ao criar produto", details: error.message });
  }
});

app.put("/api/estoque_prod/:id", async (req, res) => {
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

    const updatedProduct = await prisma.estoque.update({
      where: { id: parseInt(req.params.id) },
      data: { 
        name, 
        quantity: parsedQuantity, 
        unit, 
        value: parsedValue, 
        valuecusto: parsedValueCusto,
        categoria_Id: categoryId ? parseInt(categoryId) : null
      },
      include: {
        product: true,
        category: {
          include: {
            parent: true
          }
        }
      }
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

    // Excluir registros relacionados antes de excluir o item do estoque
    await prisma.$transaction([
      prisma.stockMovement.deleteMany({ where: { estoqueId: id } }),
      prisma.saleItem.deleteMany({ where: { estoqueId: id } }),
      prisma.estoque.delete({ where: { id } }),
    ]);

    res.json({ message: "Produto excluído com sucesso" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao excluir produto", details: error.message });
  }
});

// Rota para verificar senha do usuário (confirmação de ações sensíveis)
app.post("/api/verify-password", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: "Usuário e senha são obrigatórios" });
    }
    const user = await prisma.user.findUnique({ where: { username } });
    if (!user) {
      return res.status(401).json({ error: "Usuário não encontrado" });
    }
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ error: "Senha incorreta" });
    }
    res.json({ verified: true });
  } catch (error) {
    res.status(500).json({ error: "Erro ao verificar senha", details: error.message });
  }
});

// Rota para verificar senha do Vale (usa JWT token para identificar o usuário)
app.post("/api/verify-vale-password", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Token não fornecido" });
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, SECRET_KEY);
    const user = await prisma.user.findUnique({ where: { id: decoded.userId } });
    if (!user) return res.status(404).json({ error: "Usuário não encontrado" });
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: "Senha é obrigatória" });
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).json({ error: "Senha incorreta" });
    res.json({ verified: true });
  } catch (error) {
    if (error.name === "JsonWebTokenError" || error.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Token inválido ou expirado" });
    }
    res.status(500).json({ error: "Erro ao verificar senha", details: error.message });
  }
});

// ROTAS DE PRODUTOS (CORREÇÃO DO ERRO `quantity`)
app.get("/api/products", async (req, res) => {
  try {
    const products = await prisma.product.findMany({
      include: { 
        category: {
          include: {
            parent: true
          }
        }
      }
    });
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar produtos", details: error.message });
  }
});

app.get("/api/products/:id", async (req, res) => {
  try {
    const product = await prisma.product.findUnique({
      where: { id: parseInt(req.params.id) },
      include: { 
        category: {
          include: {
            parent: true
          }
        }
      }
    });
    res.json(product || { error: "Produto não encontrado" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar produto", details: error.message });
  }
});

// Atualizar POST e PUT de produtos para incluir categoria com parent no retorno
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
      include: { 
        category: {
          include: {
            parent: true
          }
        }
      }
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
      include: { 
        category: {
          include: {
            parent: true
          }
        }
      }
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
    
    // Criar objeto de dados dinamicamente apenas com campos não nulos
    const updateData = {};
    
    if (nomeDespesa !== null && nomeDespesa !== undefined) {
      updateData.nomeDespesa = nomeDespesa;
    }
    
    if (valorDespesa !== null && valorDespesa !== undefined) {
      updateData.valorDespesa = valorDespesa;
    }
    
    if (descDespesa !== null && descDespesa !== undefined) {
      updateData.descDespesa = descDespesa;
    }
    
    const updatedDespesa = await prisma.despesa.update({
      where: { id: parseInt(req.params.id) },
      data: updateData,
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

    // Adiciona valores padrão para campos se estiverem null
    const employeesWithDefaults = employees.map((employee) => ({
      ...employee,
      carga: employee.carga || 8,
      valorHora: employee.valorHora || 0,
      metaHoras: employee.metaHoras || null,
      bonificacao: employee.bonificacao || null,
      contato: employee.contato || null,
      dataEntrada: employee.dataEntrada || null,
      ativo: employee.ativo !== undefined ? employee.ativo : true,
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
    const { 
      name, 
      position, 
      carga = 8,
      valorHora = 0, 
      metaHoras = null, 
      bonificacao = null,
      metasExtras = null,
      contato = null,
      dataEntrada = null,
      ativo = true
    } = req.body;
    
    const newEmployee = await prisma.employee.create({
      data: { 
        name, 
        position,
        carga: parseInt(carga) || 8,
        valorHora: parseFloat(valorHora) || 0,
        metaHoras: metaHoras ? parseFloat(metaHoras) : null,
        bonificacao: bonificacao ? parseFloat(bonificacao) : null,
        metasExtras: metasExtras ? JSON.stringify(metasExtras) : null,
        contato,
        dataEntrada: dataEntrada ? new Date(dataEntrada) : null,
        ativo
      },
    });
    res.status(201).json(newEmployee);
  } catch (error) {
    res.status(500).json({ error: "Erro ao criar funcionário", details: error.message });
  }
});

app.put("/api/employees/:id", async (req, res) => {
  try {
    const { 
      name, 
      position,
      carga,
      valorHora, 
      metaHoras, 
      bonificacao,
      metasExtras,
      contato,
      dataEntrada,
      ativo
    } = req.body;
    
    // Construir objeto de atualização dinamicamente
    const updateData = {};
    if (name !== undefined) updateData.name = name;
    if (position !== undefined) updateData.position = position;
    if (carga !== undefined) updateData.carga = parseInt(carga) || 8;
    if (valorHora !== undefined) updateData.valorHora = parseFloat(valorHora) || 0;
    if (metaHoras !== undefined) updateData.metaHoras = metaHoras ? parseFloat(metaHoras) : null;
    if (bonificacao !== undefined) updateData.bonificacao = bonificacao ? parseFloat(bonificacao) : null;
    if (metasExtras !== undefined) updateData.metasExtras = metasExtras ? JSON.stringify(metasExtras) : null;
    if (contato !== undefined) updateData.contato = contato;
    if (dataEntrada !== undefined) updateData.dataEntrada = dataEntrada ? new Date(dataEntrada) : null;
    if (ativo !== undefined) updateData.ativo = ativo;
    
    const updatedEmployee = await prisma.employee.update({
      where: { id: parseInt(req.params.id) },
      data: updateData,
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

// GET /api/categories - Listar categorias com subcategorias
app.get("/api/categories", async (req, res) => {
  try {
    const categories = await prisma.category.findMany({
      where: { parentId: null }, // Só categorias principais
      include: {
        subcategories: {
          include: {
            products: true,
            prod_estoq: true
          }
        },
        products: true,
        prod_estoq: true
      },
    });
    res.json(categories);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar categorias", details: error.message });
  }
});

// GET /api/categories/all - Listar todas as categorias (incluindo subcategorias)
app.get("/api/categories/all", async (req, res) => {
  try {
    const categories = await prisma.category.findMany({
      include: {
        parent: true,
        subcategories: true,
        products: true,
        prod_estoq: true
      },
    });
    res.json(categories);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar todas as categorias", details: error.message });
  }
});

// POST /api/categories - Criar categoria ou subcategoria
app.post("/api/categories", async (req, res) => {
  try {
    const { name, parentId } = req.body;
    
    if (!name || name.trim() === '') {
      return res.status(400).json({ error: "Nome da categoria é obrigatório" });
    }

    const data = { name: name.trim() };
    if (parentId && !isNaN(parseInt(parentId))) {
      // Verificar se a categoria pai existe
      const parentCategory = await prisma.category.findUnique({
        where: { id: parseInt(parentId) }
      });
      
      if (!parentCategory) {
        return res.status(404).json({ error: "Categoria pai não encontrada" });
      }
      
      data.parentId = parseInt(parentId);
    }

    const category = await prisma.category.create({ 
      data,
      include: {
        parent: true,
        subcategories: true
      }
    });
    
    res.status(201).json(category);
  } catch (error) {
    res.status(500).json({ error: "Erro ao criar categoria", details: error.message });
  }
});

// PUT /api/categories/:id - Atualizar categoria
app.put("/api/categories/:id", async (req, res) => {
  try {
    const { name, parentId } = req.body;
    const categoryId = parseInt(req.params.id);
    
    if (isNaN(categoryId)) {
      return res.status(400).json({ error: "ID da categoria inválido" });
    }

    if (!name || name.trim() === '') {
      return res.status(400).json({ error: "Nome da categoria é obrigatório" });
    }

    const data = { name: name.trim() };
    
    if (parentId !== undefined) {
      if (parentId === null || parentId === '') {
        data.parentId = null;
      } else {
        const parentIdNum = parseInt(parentId);
        if (parentIdNum === categoryId) {
          return res.status(400).json({ error: "Uma categoria não pode ser pai de si mesma" });
        }
        
        // Verificar se a categoria pai existe
        const parentCategory = await prisma.category.findUnique({
          where: { id: parentIdNum }
        });
        
        if (!parentCategory) {
          return res.status(404).json({ error: "Categoria pai não encontrada" });
        }
        
        data.parentId = parentIdNum;
      }
    }

    const updatedCategory = await prisma.category.update({
      where: { id: categoryId },
      data,
      include: {
        parent: true,
        subcategories: true
      }
    });

    res.json(updatedCategory);
  } catch (error) {
    res.status(500).json({ error: "Erro ao atualizar categoria", details: error.message });
  }
});

// DELETE /api/categories/:id - Excluir categoria (substitua a existente)
app.delete("/api/categories/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({ error: "ID inválido" });
    }

    // Verificar se a categoria tem subcategorias
    const subcategories = await prisma.category.findMany({
      where: { parentId: id }
    });

    if (subcategories.length > 0) {
      return res.status(400).json({ 
        error: "Não é possível excluir uma categoria que possui subcategorias. Exclua primeiro as subcategorias." 
      });
    }

    // Verificar se a categoria tem produtos associados
    const productsCount = await prisma.product.count({
      where: { categoryId: id }
    });

    const estoqueCount = await prisma.estoque.count({
      where: { categoria_Id: id }
    });

    if (productsCount > 0 || estoqueCount > 0) {
      return res.status(400).json({ 
        error: "Não é possível excluir uma categoria que possui produtos associados." 
      });
    }

    await prisma.category.delete({ where: { id } });
    res.json({ message: "Categoria excluída com sucesso" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao excluir categoria", details: error.message });
  }
});

// Rota para criar uma nova venda (PDV) com baixa de estoque
app.post('/api/sales', async (req, res) => {
  try {
    const { items, total, paymentMethod, customerName, amountReceived, change, date, discount, splitPayments: splitPay, pendente, vale, subtotal, finalTotal } = req.body;

    // Verificar estoque antes de prosseguir (verificação inicial rápida)
    for (const item of items) {
      const estoqueItem = await prisma.estoque.findUnique({ where: { id: item.id } });
      if (!estoqueItem) {
        return res.status(400).json({ error: `Produto "${item.name}" não encontrado no estoque.` });
      }
      if (estoqueItem.quantity < item.quantity) {
        // Buscar última venda que baixou este item para informar ao operador
        const lastMovement = await prisma.stockMovement.findFirst({
          where: { estoqueId: item.id, type: 'SALE' },
          orderBy: { createdAt: 'desc' }
        });
        const saleRef = lastMovement?.referenceId ? ` Último desconto registrado na Venda #${lastMovement.referenceId}.` : '';
        return res.status(400).json({
          error: `Estoque insuficiente para "${item.name}". Disponível: ${estoqueItem.quantity}, Solicitado: ${item.quantity}.${saleRef}`
        });
      }
    }

    // Verificar limite de comanda se pendente (usa soma de comandas abertas, não totalDebt)
    if (pendente && pendente.clientId) {
      const client = await prisma.client.findUnique({ where: { id: pendente.clientId } });
      if (!client) return res.status(400).json({ error: "Cliente não encontrado." });
      const limiteConfig = await prisma.pdvConfigVenda.findFirst({ where: { chave: "limite_comanda" } });
      if (limiteConfig) {
        const limite = parseFloat(limiteConfig.valor);
        const valorPendente = parseFloat(finalTotal || total);
        // Somar comandas abertas do cliente
        const comandasAbertas = await prisma.pdvComanda.aggregate({
          where: { clientId: pendente.clientId, status: "ABERTA" },
          _sum: { total: true },
        });
        const totalAberto = (comandasAbertas._sum.total || 0) + valorPendente;
        if (totalAberto > limite) {
          return res.status(400).json({ error: `Limite de comanda excedido! Total em aberto: R$ ${(comandasAbertas._sum.total || 0).toFixed(2)} + R$ ${valorPendente.toFixed(2)} = R$ ${totalAberto.toFixed(2)}, Limite: R$ ${limite.toFixed(2)}` });
        }
      }
    }

    // Verificar senha do Vale se necessário
    if (vale && vale.password) {
      const authHeader = req.headers.authorization;
      if (!authHeader) return res.status(401).json({ error: "Token não fornecido para verificação do Vale." });
      const token = authHeader.split(" ")[1];
      const decoded = jwt.verify(token, SECRET_KEY);
      const user = await prisma.user.findUnique({ where: { id: decoded.userId } });
      if (!user) return res.status(401).json({ error: "Usuário do Vale não encontrado." });
      const isValid = await bcrypt.compare(vale.password, user.password);
      if (!isValid) return res.status(401).json({ error: "Senha do Vale incorreta." });
    }

    const saleTotal = parseFloat(finalTotal || total);

    // Usar transação para garantir consistência entre venda, estoque e movimentação
    const result = await prisma.$transaction(async (tx) => {
      // 1. Criar a venda
      const sale = await tx.sale.create({
        data: {
          total: saleTotal,
          paymentMethod,
          customerName,
          amountReceived: parseFloat(amountReceived) || saleTotal,
          change: parseFloat(change) || 0,
          date: parseISO(date),
          items: {
            create: items.map(item => ({
              estoqueId: item.id,
              productName: item.name,
              quantity: item.quantity,
              unitPrice: item.price,
              total: item.price * item.quantity,
              ...(item.composicao ? { composicao: item.composicao } : {})
            }))
          }
        },
        include: {
          items: true
        }
      });

      // 2. Dar baixa no ESTOQUE e registrar movimentações (com re-verificação para concorrência)
      for (const item of items) {
        // Re-verificar estoque dentro da transação (proteção contra race condition)
        const estoqueItem = await tx.estoque.findUnique({ where: { id: item.id } });
        const previousStock = estoqueItem.quantity;

        if (previousStock < item.quantity) {
          // Buscar última movimentação de venda para este item
          const lastMovement = await tx.stockMovement.findFirst({
            where: { estoqueId: item.id, type: 'SALE' },
            orderBy: { createdAt: 'desc' }
          });
          const saleRef = lastMovement?.referenceId ? ` Último desconto registrado na Venda #${lastMovement.referenceId}.` : '';
          throw new Error(`Estoque insuficiente para "${item.name}". Disponível: ${previousStock}, Solicitado: ${item.quantity}.${saleRef}`);
        }

        const newStock = previousStock - item.quantity;

        // Atualizar quantidade no estoque
        await tx.estoque.update({
          where: { id: item.id },
          data: { quantity: newStock }
        });

        // Registrar movimentação de estoque
        await tx.stockMovement.create({
          data: {
            estoqueId: item.id,
            type: 'SALE',
            quantity: -item.quantity,
            previousStock: previousStock,
            newStock: newStock,
            description: `Venda #${sale.id} - ${item.name} (${item.quantity}x)`,
            referenceId: sale.id,
            referenceType: 'Sale'
          }
        });
      }

      // 2b. Dar baixa no estoque dos componentes de composição
      for (const item of items) {
        if (!item.composicao) continue;
        let selections;
        try { selections = JSON.parse(item.composicao); } catch { continue; }
        // selections = { [composicaoId]: [opcaoId, ...] }
        const allOpcaoIds = Object.values(selections).flat().map(Number).filter(Boolean);
        if (allOpcaoIds.length === 0) continue;
        const opcoes = await tx.composicaoOpcao.findMany({
          where: { id: { in: allOpcaoIds }, estoqueId: { not: null } }
        });
        for (const opcao of opcoes) {
          const estoqueComp = await tx.estoque.findUnique({ where: { id: opcao.estoqueId } });
          if (!estoqueComp) continue;
          const needed = item.quantity; // 1 unidade do componente por item vendido
          if (estoqueComp.quantity < needed) {
            throw new Error(`Estoque insuficiente para o componente "${opcao.nome}" (${estoqueComp.name}). Disponível: ${estoqueComp.quantity}, Necessário: ${needed}.`);
          }
          const newQty = estoqueComp.quantity - needed;
          await tx.estoque.update({ where: { id: opcao.estoqueId }, data: { quantity: newQty } });
          await tx.stockMovement.create({
            data: {
              estoqueId: opcao.estoqueId,
              type: 'SALE',
              quantity: -needed,
              previousStock: estoqueComp.quantity,
              newStock: newQty,
              description: `Venda #${sale.id} - Componente "${opcao.nome}" p/ ${item.name} (${needed}x)`,
              referenceId: sale.id,
              referenceType: 'Sale'
            }
          });
        }
      }

      // 3. Se pendente, criar COMANDA (NÃO fiado imediatamente) - fiado só após 24h sem pagamento
      if (pendente && pendente.clientId) {
        await tx.pdvComanda.create({
          data: {
            clientId: pendente.clientId,
            saleId: sale.id,
            total: splitPay
              ? parseFloat((splitPay.find(s => s.forma === "pendente") || {}).valor || 0)
              : saleTotal,
            status: "ABERTA",
            items: {
              create: items.map(item => ({
                productName: item.name,
                quantity: item.quantity,
                unitPrice: item.price,
                total: item.price * item.quantity,
                estoqueId: item.id,
              }))
            }
          }
        });
      }

      // 4. Se cupom foi usado, incrementar vezesUsado
      if (discount && discount.cupomCodigo) {
        const cupom = await tx.pdvCupom.findFirst({ where: { codigo: discount.cupomCodigo } });
        if (cupom) {
          await tx.pdvCupom.update({
            where: { id: cupom.id },
            data: { vezesUsado: { increment: 1 } }
          });
        }
      }

      return sale;
    });

    res.status(201).json(result);
  } catch (error) {
    console.error('Erro ao criar venda:', error);
    res.status(500).json({ error: 'Erro interno do servidor', details: error.message });
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

// ROTAS DE MOVIMENTAÇÕES DE ESTOQUE

// Buscar todas as movimentações (com filtros opcionais)
app.get('/api/stock-movements', async (req, res) => {
  try {
    const { estoqueId, type, startDate, endDate, limit } = req.query;
    
    const where = {};
    if (estoqueId) where.estoqueId = parseInt(estoqueId);
    if (type) where.type = type;
    if (startDate || endDate) {
      where.createdAt = {};
      if (startDate) where.createdAt.gte = new Date(startDate);
      if (endDate) where.createdAt.lte = new Date(endDate);
    }

    const movements = await prisma.stockMovement.findMany({
      where,
      include: {
        estoque: {
          select: { id: true, name: true, unit: true, quantity: true }
        }
      },
      orderBy: { createdAt: 'desc' },
      take: limit ? parseInt(limit) : 100
    });

    res.json(movements);
  } catch (error) {
    console.error('Erro ao buscar movimentações:', error);
    res.status(500).json({ error: 'Erro ao buscar movimentações', details: error.message });
  }
});

// Buscar movimentações de um item do estoque específico
app.get('/api/stock-movements/estoque/:estoqueId', async (req, res) => {
  try {
    const estoqueId = parseInt(req.params.estoqueId);
    
    const movements = await prisma.stockMovement.findMany({
      where: { estoqueId },
      include: {
        estoque: {
          select: { id: true, name: true, unit: true, quantity: true }
        }
      },
      orderBy: { createdAt: 'desc' }
    });

    res.json(movements);
  } catch (error) {
    console.error('Erro ao buscar movimentações do produto:', error);
    res.status(500).json({ error: 'Erro ao buscar movimentações', details: error.message });
  }
});

// Registrar movimentação manual de estoque (entrada, ajuste, etc.)
app.post('/api/stock-movements', async (req, res) => {
  try {
    const { estoqueId, type, quantity, description } = req.body;

    if (!estoqueId || !type || quantity === undefined) {
      return res.status(400).json({ error: 'estoqueId, type e quantity são obrigatórios.' });
    }

    const validTypes = ['ENTRY', 'ADJUSTMENT', 'RETURN', 'LOSS'];
    if (!validTypes.includes(type)) {
      return res.status(400).json({ error: `Tipo inválido. Use: ${validTypes.join(', ')}` });
    }

    const result = await prisma.$transaction(async (tx) => {
      const estoqueItem = await tx.estoque.findUnique({ where: { id: parseInt(estoqueId) } });
      if (!estoqueItem) {
        throw new Error('Produto não encontrado no estoque');
      }

      const previousStock = estoqueItem.quantity;
      const parsedQty = parseFloat(quantity);
      const newStock = previousStock + parsedQty; // positivo = entrada, negativo = saída

      if (newStock < 0) {
        throw new Error(`Estoque não pode ficar negativo. Estoque atual: ${previousStock}`);
      }

      // Atualizar quantidade no estoque
      await tx.estoque.update({
        where: { id: parseInt(estoqueId) },
        data: { quantity: newStock }
      });

      // Registrar movimentação
      const movement = await tx.stockMovement.create({
        data: {
          estoqueId: parseInt(estoqueId),
          type,
          quantity: parsedQty,
          previousStock,
          newStock,
          description: description || `${type} manual`,
          referenceType: 'Manual'
        },
        include: {
          estoque: {
            select: { id: true, name: true, unit: true, quantity: true }
          }
        }
      });

      return movement;
    });

    res.status(201).json(result);
  } catch (error) {
    console.error('Erro ao registrar movimentação:', error);
    res.status(error.message.includes('não') ? 400 : 500).json({ 
      error: error.message || 'Erro ao registrar movimentação' 
    });
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
    
    if (!unitName || value === undefined || value === null || parseFloat(value) < 0) {
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
    
    if (value === undefined || value === null || parseFloat(value) < 0) {
      return res.status(400).json({ error: 'Valor é obrigatório e deve ser maior ou igual a zero' });
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

// ===================== ROTAS DE COMPOSIÇÃO DE PRODUTOS =====================

// Rotas de opções devem vir ANTES das rotas com :id para evitar conflitos de roteamento
app.put('/api/composicoes/opcoes/:id', async (req, res) => {
  try {
    const { nome, valorExtra, disponivel, estoqueId } = req.body;
    const updateData = {};
    if (nome !== undefined) updateData.nome = nome;
    if (valorExtra !== undefined) updateData.valorExtra = parseFloat(valorExtra) || 0;
    if (disponivel !== undefined) updateData.disponivel = disponivel !== false && disponivel !== 0;
    if (estoqueId !== undefined) updateData.estoqueId = estoqueId ? parseInt(estoqueId) : null;
    const opcao = await prisma.composicaoOpcao.update({
      where: { id: parseInt(req.params.id) },
      data: updateData,
      include: { estoque: { select: { id: true, name: true, quantity: true } } }
    });
    res.json(opcao);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao atualizar opção', details: error.message });
  }
});

app.delete('/api/composicoes/opcoes/:id', async (req, res) => {
  try {
    await prisma.composicaoOpcao.delete({ where: { id: parseInt(req.params.id) } });
    res.json({ message: 'Opção excluída' });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao excluir opção', details: error.message });
  }
});

app.get('/api/composicoes/:estoqueId', async (req, res) => {
  try {
    const composicoes = await prisma.composicaoProduto.findMany({
      where: { estoqueId: parseInt(req.params.estoqueId) },
      include: { opcoes: { include: { estoque: { select: { id: true, name: true, quantity: true } } }, orderBy: { id: 'asc' } } },
      orderBy: { ordem: 'asc' }
    });
    res.json(composicoes);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar composições', details: error.message });
  }
});

app.post('/api/composicoes', async (req, res) => {
  try {
    const { estoqueId, nome, descricao, obrigatorio, multiplo, minOpcoes, maxOpcoes, ordem } = req.body;
    if (!estoqueId || !nome) return res.status(400).json({ error: 'estoqueId e nome são obrigatórios' });
    const comp = await prisma.composicaoProduto.create({
      data: {
        estoqueId: parseInt(estoqueId), nome, descricao: descricao || null,
        obrigatorio: obrigatorio !== false, multiplo: !!multiplo,
        minOpcoes: parseInt(minOpcoes) || 1, maxOpcoes: parseInt(maxOpcoes) || 1,
        ordem: parseInt(ordem) || 0
      },
      include: { opcoes: true }
    });
    res.status(201).json(comp);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao criar composição', details: error.message });
  }
});

app.put('/api/composicoes/:id', async (req, res) => {
  try {
    const { nome, descricao, obrigatorio, multiplo, minOpcoes, maxOpcoes, ordem } = req.body;
    const comp = await prisma.composicaoProduto.update({
      where: { id: parseInt(req.params.id) },
      data: { nome, descricao, obrigatorio: !!obrigatorio, multiplo: !!multiplo, minOpcoes: parseInt(minOpcoes) || 1, maxOpcoes: parseInt(maxOpcoes) || 1, ordem: parseInt(ordem) || 0 },
      include: { opcoes: true }
    });
    res.json(comp);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao atualizar composição', details: error.message });
  }
});

app.delete('/api/composicoes/:id', async (req, res) => {
  try {
    await prisma.composicaoProduto.delete({ where: { id: parseInt(req.params.id) } });
    res.json({ message: 'Composição excluída' });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao excluir composição', details: error.message });
  }
});

app.post('/api/composicoes/:id/opcoes', async (req, res) => {
  try {
    const { nome, valorExtra, disponivel, estoqueId } = req.body;
    if (!nome) return res.status(400).json({ error: 'Nome da opção é obrigatório' });
    const opcao = await prisma.composicaoOpcao.create({
      data: {
        composicaoId: parseInt(req.params.id),
        nome,
        valorExtra: parseFloat(valorExtra) || 0,
        disponivel: disponivel !== false,
        ...(estoqueId ? { estoqueId: parseInt(estoqueId) } : {})
      },
      include: { estoque: { select: { id: true, name: true, quantity: true } } }
    });
    res.status(201).json(opcao);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao criar opção', details: error.message });
  }
});

// Cria produto no catálogo + entrada no estoque + opção de composição em uma só transação
app.post('/api/composicoes/:id/opcao-estoque', async (req, res) => {
  try {
    const composicaoId = parseInt(req.params.id);
    const { nome, unit, quantity, value, valuecusto, categoryId, valorExtra } = req.body;
    if (!nome || !unit || quantity == null) {
      return res.status(400).json({ error: 'nome, unit e quantity são obrigatórios' });
    }
    const result = await prisma.$transaction(async (tx) => {
      // 1. Criar produto no catálogo
      const product = await tx.product.create({
        data: {
          name: nome,
          quantity: parseInt(quantity) || 0,
          unit,
          value: parseFloat(value) || 0,
          valuecusto: parseFloat(valuecusto) || 0,
          categoryId: categoryId ? parseInt(categoryId) : null
        }
      });
      // 2. Criar entrada no estoque
      const estoqueItem = await tx.estoque.create({
        data: {
          productId: product.id,
          name: nome,
          quantity: parseInt(quantity) || 0,
          unit,
          value: parseFloat(value) || 0,
          valuecusto: parseFloat(valuecusto) || 0,
          categoria_Id: categoryId ? parseInt(categoryId) : null
        }
      });
      // 3. Registrar movimentação inicial
      await tx.stockMovement.create({
        data: {
          estoqueId: estoqueItem.id,
          type: 'ENTRY',
          quantity: parseInt(quantity) || 0,
          previousStock: 0,
          newStock: parseInt(quantity) || 0,
          description: `Cadastro inicial — ${nome}`,
          referenceType: 'Manual'
        }
      });
      // 4. Criar opção de composição vinculada
      const opcao = await tx.composicaoOpcao.create({
        data: {
          composicaoId,
          nome,
          valorExtra: parseFloat(valorExtra) || 0,
          disponivel: true,
          estoqueId: estoqueItem.id
        },
        include: { estoque: { select: { id: true, name: true, quantity: true } } }
      });
      return { product, estoqueItem, opcao };
    });
    res.status(201).json(result);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao criar item de estoque e opção', details: error.message });
  }
});

// ROTAS DE DESPESAS PESSOAIS
app.get("/api/desp-pessoal", async (req, res) => {
  try {
    const despesas = await prisma.despPessoal.findMany({
      include: { categoria: true }
    });
    res.json(despesas);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar despesas pessoais", details: error.message });
  }
});

app.get("/api/desp-pessoal/:id", async (req, res) => {
  try {
    const despesa = await prisma.despPessoal.findUnique({
      where: { id: parseInt(req.params.id) },
      include: { categoria: true }
    });
    res.json(despesa || { error: "Despesa pessoal não encontrada" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar despesa pessoal", details: error.message });
  }
});

app.post("/api/desp-pessoal", async (req, res) => {
  try {
    const { nomeDespesa, valorDespesa, descDespesa, date, DespesaFixa, categoriaId, tipoMovimento, valeRelacionadoId, isVale } = req.body;
    console.log("Dados recebidos:", req.body);

    const parsedDate = new Date(date.replace(" ", "T"));

    const data = { 
      nomeDespesa, 
      date: parsedDate, 
      DespesaFixa,
      tipoMovimento: tipoMovimento || "GASTO"
    };
    
    // Adicionar categoria usando relação
    if (categoriaId) {
      data.categoria = { connect: { id: categoriaId } };
    }
    
    if (valorDespesa !== undefined) data.valorDespesa = valorDespesa;
    if (descDespesa !== undefined) data.descDespesa = descDespesa;
    if (valeRelacionadoId !== undefined) data.valeRelacionadoId = valeRelacionadoId;
    if (isVale !== undefined) data.isVale = isVale;

    const newDespesa = await prisma.despPessoal.create({
      data,
      include: { categoria: true }
    });
    res.status(201).json(newDespesa);
  } catch (error) {
    res.status(500).json({ error: "Erro ao criar despesa pessoal", details: error.message });
  }
});

app.put("/api/desp-pessoal/:id", async (req, res) => {
  try {
    const { nomeDespesa, valorDespesa, descDespesa, date, DespesaFixa, categoriaId, tipoMovimento, valeRelacionadoId, isVale } = req.body;
    
    const updateData = {};
    if (nomeDespesa !== undefined) updateData.nomeDespesa = nomeDespesa;
    if (valorDespesa !== undefined) updateData.valorDespesa = valorDespesa;
    if (descDespesa !== undefined) updateData.descDespesa = descDespesa;
    if (tipoMovimento !== undefined) updateData.tipoMovimento = tipoMovimento;
    if (valeRelacionadoId !== undefined) updateData.valeRelacionadoId = valeRelacionadoId;
    if (DespesaFixa !== undefined) updateData.DespesaFixa = DespesaFixa;
    if (isVale !== undefined) updateData.isVale = isVale;
    
    // Atualizar categoria usando relação
    if (categoriaId !== undefined) {
      if (categoriaId === null) {
        updateData.categoria = { disconnect: true };
      } else {
        updateData.categoria = { connect: { id: categoriaId } };
      }
    }
    
    // Processar data se fornecida
    if (date !== undefined) {
      const parsedDate = new Date(date.replace(" ", "T"));
      updateData.date = parsedDate;
    }
    
    const updatedDespesa = await prisma.despPessoal.update({
      where: { id: parseInt(req.params.id) },
      data: updateData,
      include: { categoria: true }
    });
    res.json(updatedDespesa);
  } catch (error) {
    res.status(500).json({ error: "Erro ao atualizar despesa pessoal", details: error.message });
  }
});

app.delete("/api/desp-pessoal/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({ error: "ID inválido" });
    }

    await prisma.despPessoal.delete({ where: { id } });
    res.json({ message: "Despesa pessoal excluída com sucesso" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao excluir despesa pessoal", details: error.message });
  }
});

// ROTAS DE CATEGORIAS DE DESPESAS PESSOAIS
app.get("/api/cat-desp-pessoal", async (req, res) => {
  try {
    const categorias = await prisma.catDespPessoal.findMany({
      include: { DespPessoal: true }
    });
    res.json(categorias);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar categorias de despesas pessoais", details: error.message });
  }
});

app.post("/api/cat-desp-pessoal", async (req, res) => {
  try {
    const { nomeCategoria } = req.body;
    const newCategoria = await prisma.catDespPessoal.create({
      data: { nomeCategoria }
    });
    res.status(201).json(newCategoria);
  } catch (error) {
    res.status(500).json({ error: "Erro ao criar categoria de despesa pessoal", details: error.message });
  }
});

app.put("/api/cat-desp-pessoal/:id", async (req, res) => {
  try {
    const { nomeCategoria } = req.body;
    const updatedCategoria = await prisma.catDespPessoal.update({
      where: { id: parseInt(req.params.id) },
      data: { nomeCategoria }
    });
    res.json(updatedCategoria);
  } catch (error) {
    res.status(500).json({ error: "Erro ao atualizar categoria de despesa pessoal", details: error.message });
  }
});

app.delete("/api/cat-desp-pessoal/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({ error: "ID inválido" });
    }

    await prisma.catDespPessoal.delete({ where: { id } });
    res.json({ message: "Categoria de despesa pessoal excluída com sucesso" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao excluir categoria de despesa pessoal", details: error.message });
  }
});

// ROTAS DE HISTÓRICO DE METAS DE FUNCIONÁRIOS
// GET - Buscar meta vigente para um funcionário em uma data específica
app.get("/api/employee-meta/:employeeId", async (req, res) => {
  try {
    const employeeId = parseInt(req.params.employeeId);
    const { date } = req.query; // formato: YYYY-MM-DD
    
    if (isNaN(employeeId)) {
      return res.status(400).json({ error: "ID do funcionário inválido" });
    }

    const targetDate = date ? new Date(date) : new Date();

    // Buscar meta vigente para a data
    const meta = await prisma.employeeMetaHistory.findFirst({
      where: {
        employeeId,
        validFrom: { lte: targetDate },
        OR: [
          { validUntil: null }, // Meta atual
          { validUntil: { gte: targetDate } } // Meta que estava vigente
        ]
      },
      orderBy: { validFrom: 'desc' }
    });

    if (!meta) {
      // Se não houver histórico, retornar valores do Employee
      const employee = await prisma.employee.findUnique({
        where: { id: employeeId },
        select: { valorHora: true, metaHoras: true, bonificacao: true }
      });
      
      return res.json({
        valorHora: employee?.valorHora || null,
        metaHoras: employee?.metaHoras || null,
        bonificacao: employee?.bonificacao || null,
        isFromHistory: false
      });
    }

    res.json({
      valorHora: meta.valorHora,
      metaHoras: meta.metaHoras,
      bonificacao: meta.bonificacao,
      validFrom: meta.validFrom,
      validUntil: meta.validUntil,
      isFromHistory: true
    });
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar meta do funcionário", details: error.message });
  }
});

// GET - Buscar todo o histórico de metas de um funcionário
app.get("/api/employee-meta-history/:employeeId", async (req, res) => {
  try {
    const employeeId = parseInt(req.params.employeeId);
    
    if (isNaN(employeeId)) {
      return res.status(400).json({ error: "ID do funcionário inválido" });
    }

    const history = await prisma.employeeMetaHistory.findMany({
      where: { employeeId },
      orderBy: { validFrom: 'desc' }
    });

    res.json(history);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar histórico de metas", details: error.message });
  }
});

// POST - Criar nova meta (ao alterar meta de funcionário)
app.post("/api/employee-meta", async (req, res) => {
  try {
    const { employeeId, valorHora, metaHoras, bonificacao, validFrom } = req.body;

    if (!employeeId || valorHora === undefined || metaHoras === undefined || bonificacao === undefined) {
      return res.status(400).json({ error: "Dados incompletos" });
    }

    const validFromDate = validFrom ? new Date(validFrom) : new Date();
    // Garantir que é o primeiro dia do mês
    validFromDate.setDate(1);
    validFromDate.setHours(0, 0, 0, 0);

    // Fechar meta anterior (se existir)
    const lastMeta = await prisma.employeeMetaHistory.findFirst({
      where: {
        employeeId,
        validUntil: null
      },
      orderBy: { validFrom: 'desc' }
    });

    if (lastMeta) {
      // Fechar a meta anterior no último dia do mês anterior
      const validUntil = new Date(validFromDate);
      validUntil.setDate(0); // Último dia do mês anterior
      validUntil.setHours(23, 59, 59, 999);

      await prisma.employeeMetaHistory.update({
        where: { id: lastMeta.id },
        data: { validUntil }
      });
    }

    // Criar nova meta
    const newMeta = await prisma.employeeMetaHistory.create({
      data: {
        employeeId,
        valorHora,
        metaHoras,
        bonificacao,
        validFrom: validFromDate,
        validUntil: null // Meta atual, sem data de fim
      }
    });

    // Atualizar valores atuais no Employee
    await prisma.employee.update({
      where: { id: employeeId },
      data: { valorHora, metaHoras, bonificacao }
    });

    res.status(201).json(newMeta);
  } catch (error) {
    res.status(500).json({ error: "Erro ao criar meta", details: error.message });
  }
});

// ROTAS DE METAS SEMANAIS DE FUNCIONÁRIOS
// GET - Buscar meta semanal para um funcionário em uma semana específica
app.get("/api/employee-weekly-meta/:employeeId", async (req, res) => {
  try {
    const employeeId = parseInt(req.params.employeeId);
    const { weekStart, year, month, date } = req.query;
    
    if (isNaN(employeeId)) {
      return res.status(400).json({ error: "ID do funcionário inválido" });
    }

    let where = { employeeId };
    
    if (weekStart) {
      // Buscar meta específica para uma semana pelo weekStart
      where.weekStart = new Date(weekStart);
      
      const meta = await prisma.employeeWeeklyMeta.findUnique({
        where: {
          employeeId_weekStart: {
            employeeId,
            weekStart: new Date(weekStart)
          }
        }
      });

      if (!meta) {
        // Se não existe meta específica, retornar valores padrão do funcionário
        const employee = await prisma.employee.findUnique({
          where: { id: employeeId },
          select: { valorHora: true, metaHoras: true, bonificacao: true, metasExtras: true }
        });
        
        return res.json({
          metaHoras: employee?.metaHoras || null,
          bonificacao: employee?.bonificacao || null,
          valorHora: employee?.valorHora || null,
          metasExtras: employee?.metasExtras ? JSON.parse(employee.metasExtras) : null,
          isDefault: true
        });
      }

      return res.json({
        ...meta,
        metasExtras: meta.metasExtras ? JSON.parse(meta.metasExtras) : null,
        isDefault: false
      });
    }
    
    if (date) {
      // Buscar meta para uma data específica (pode cair em qualquer dia da semana)
      const searchDate = new Date(date);
      searchDate.setHours(12, 0, 0, 0); // Meio-dia para evitar problemas de timezone
      
      const meta = await prisma.employeeWeeklyMeta.findFirst({
        where: {
          employeeId,
          weekStart: { lte: searchDate },
          weekEnd: { gte: searchDate }
        },
        orderBy: { weekStart: 'desc' }
      });

      if (!meta) {
        // Se não existe meta específica, retornar valores padrão do funcionário
        const employee = await prisma.employee.findUnique({
          where: { id: employeeId },
          select: { valorHora: true, metaHoras: true, bonificacao: true, metasExtras: true }
        });
        
        return res.json({
          metaHoras: employee?.metaHoras || null,
          bonificacao: employee?.bonificacao || null,
          valorHora: employee?.valorHora || null,
          metasExtras: employee?.metasExtras ? JSON.parse(employee.metasExtras) : null,
          isDefault: true
        });
      }

      return res.json({
        ...meta,
        metasExtras: meta.metasExtras ? JSON.parse(meta.metasExtras) : null,
        isDefault: false
      });
    }
    
    if (year && month) {
      // Buscar todas as metas de um mês
      where.year = parseInt(year);
      where.month = parseInt(month);
    }

    const metas = await prisma.employeeWeeklyMeta.findMany({
      where,
      orderBy: { weekStart: 'asc' }
    });

    res.json(metas);
  } catch (error) {
    console.error("Erro ao buscar meta semanal:", error);
    res.status(500).json({ error: "Erro ao buscar meta semanal", details: error.message });
  }
});

// POST - Criar ou atualizar meta semanal
app.post("/api/employee-weekly-meta", async (req, res) => {
  try {
    const { employeeId, weekStart, metaHoras, bonificacao, valorHora, year, month, metasExtras } = req.body;

    if (!employeeId || !weekStart || metaHoras === undefined || bonificacao === undefined || valorHora === undefined) {
      return res.status(400).json({ error: "Dados incompletos" });
    }

    const weekStartDate = new Date(weekStart);
    weekStartDate.setHours(0, 0, 0, 0);
    
    // Calcular weekEnd (domingo, 5 dias após a terça-feira)
    const weekEndDate = new Date(weekStartDate);
    weekEndDate.setDate(weekEndDate.getDate() + 5);
    weekEndDate.setHours(23, 59, 59, 999);

    // Verificar se já existe meta para esta semana
    const existingMeta = await prisma.employeeWeeklyMeta.findUnique({
      where: {
        employeeId_weekStart: {
          employeeId: parseInt(employeeId),
          weekStart: weekStartDate
        }
      }
    });

    const metasExtrasJson = metasExtras ? JSON.stringify(metasExtras) : null;

    let result;
    if (existingMeta) {
      // Atualizar meta existente
      result = await prisma.employeeWeeklyMeta.update({
        where: { id: existingMeta.id },
        data: {
          weekEnd: weekEndDate,
          metaHoras: parseFloat(metaHoras),
          bonificacao: parseFloat(bonificacao),
          valorHora: parseFloat(valorHora),
          metasExtras: metasExtrasJson
        }
      });
    } else {
      // Criar nova meta
      result = await prisma.employeeWeeklyMeta.create({
        data: {
          employeeId: parseInt(employeeId),
          weekStart: weekStartDate,
          weekEnd: weekEndDate,
          year: year || weekStartDate.getFullYear(),
          month: month || weekStartDate.getMonth() + 1,
          metaHoras: parseFloat(metaHoras),
          bonificacao: parseFloat(bonificacao),
          valorHora: parseFloat(valorHora),
          metasExtras: metasExtrasJson
        }
      });
    }

    res.status(201).json(result);
  } catch (error) {
    console.error("Erro ao salvar meta semanal:", error);
    res.status(500).json({ error: "Erro ao salvar meta semanal", details: error.message });
  }
});

// DELETE - Deletar meta semanal (volta a usar valores padrão do funcionário)
app.delete("/api/employee-weekly-meta/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    
    if (isNaN(id)) {
      return res.status(400).json({ error: "ID inválido" });
    }

    await prisma.employeeWeeklyMeta.delete({
      where: { id }
    });

    res.json({ message: "Meta semanal excluída com sucesso" });
  } catch (error) {
    console.error("Erro ao excluir meta semanal:", error);
    res.status(500).json({ error: "Erro ao excluir meta semanal", details: error.message });
  }
});

// POST - Migrar dados criando metas semanais específicas para todas as semanas com pontos
app.post("/api/migrate-employee-meta-history", async (req, res) => {
  try {
    console.log("Iniciando migração de metas semanais...");
    
    // Buscar todos os funcionários
    const employees = await prisma.employee.findMany({
      where: {
        ativo: true
      }
    });

    console.log(`Encontrados ${employees.length} funcionários ativos`);

    if (employees.length === 0) {
      return res.json({ 
        message: "Nenhum funcionário encontrado",
        totalEmployees: 0,
        totalWeeks: 0,
        created: 0,
        skipped: 0
      });
    }

    let totalWeeksCreated = 0;
    let totalWeeksSkipped = 0;
    const results = [];

    // Função auxiliar para calcular início e fim da semana (terça a domingo)
    const getWeekRange = (date) => {
      const currentDate = new Date(date);
      const dayOfWeek = currentDate.getDay();
      
      let tuesday = new Date(currentDate);
      if (dayOfWeek === 0) { // Domingo
        tuesday.setDate(tuesday.getDate() - 5);
      } else if (dayOfWeek === 1) { // Segunda
        tuesday.setDate(tuesday.getDate() - 6);
      } else if (dayOfWeek >= 2) { // Terça a sábado
        tuesday.setDate(tuesday.getDate() - (dayOfWeek - 2));
      }
      tuesday.setHours(0, 0, 0, 0);
      
      const sunday = new Date(tuesday);
      sunday.setDate(sunday.getDate() + 5);
      sunday.setHours(23, 59, 59, 999);
      
      return { weekStart: tuesday, weekEnd: sunday };
    };

    for (const employee of employees) {
      console.log(`Processando funcionário: ${employee.name} (ID: ${employee.id})`);
      
      // Buscar todos os pontos do funcionário
      const points = await prisma.dailyPoint.findMany({
        where: { 
          employeeId: employee.id,
          date: { not: null }
        },
        orderBy: { date: 'asc' }
      });

      console.log(`  - ${points.length} pontos encontrados`);

      if (points.length === 0) {
        results.push({
          employeeId: employee.id,
          name: employee.name,
          status: "no-points",
          weeksCreated: 0,
          weeksSkipped: 0,
          message: "Sem pontos registrados"
        });
        continue;
      }

      // Agrupar pontos por semana
      const weeklyGroups = new Map();
      
      points.forEach(point => {
        const pointDate = new Date(point.date);
        const dayOfWeek = pointDate.getDay();
        
        // Ignorar segundas-feiras
        if (dayOfWeek === 1) return;
        
        const { weekStart, weekEnd } = getWeekRange(pointDate);
        const weekKey = weekStart.toISOString().split('T')[0];
        
        if (!weeklyGroups.has(weekKey)) {
          weeklyGroups.set(weekKey, {
            weekStart,
            weekEnd,
            year: weekStart.getFullYear(),
            month: weekStart.getMonth() + 1
          });
        }
      });

      console.log(`  - ${weeklyGroups.size} semanas únicas identificadas`);

      let weeksCreated = 0;
      let weeksSkipped = 0;

      // Criar meta para cada semana
      for (const [weekKey, weekData] of weeklyGroups) {
        try {
          // Verificar se já existe meta para esta semana
          const existing = await prisma.employeeWeeklyMeta.findUnique({
            where: {
              employeeId_weekStart: {
                employeeId: employee.id,
                weekStart: weekData.weekStart
              }
            }
          });

          if (existing) {
            console.log(`  - Semana ${weekKey} já possui meta (pulando)`);
            weeksSkipped++;
            continue;
          }

          // Criar meta semanal com valores do funcionário
          const created = await prisma.employeeWeeklyMeta.create({
            data: {
              employeeId: employee.id,
              weekStart: weekData.weekStart,
              weekEnd: weekData.weekEnd,
              year: weekData.year,
              month: weekData.month,
              metaHoras: employee.metaHoras || 0,
              bonificacao: employee.bonificacao || 0,
              valorHora: employee.valorHora || 0
            }
          });

          console.log(`  - ✅ Semana ${weekKey} criada (ID: ${created.id})`);
          weeksCreated++;
          totalWeeksCreated++;
        } catch (error) {
          console.error(`  - ❌ Erro ao criar meta para semana ${weekKey}:`, error.message);
          weeksSkipped++;
        }
      }

      totalWeeksSkipped += weeksSkipped;

      console.log(`  - Resultado: ${weeksCreated} criadas, ${weeksSkipped} puladas`);

      results.push({
        employeeId: employee.id,
        name: employee.name,
        status: weeksCreated > 0 ? "migrated" : "skipped",
        weeksCreated,
        weeksSkipped,
        totalWeeks: weeklyGroups.size,
        valorHora: employee.valorHora,
        metaHoras: employee.metaHoras,
        bonificacao: employee.bonificacao
      });
    }

    console.log(`\n=== RESUMO DA MIGRAÇÃO ===`);
    console.log(`Total de funcionários: ${employees.length}`);
    console.log(`Total de semanas criadas: ${totalWeeksCreated}`);
    console.log(`Total de semanas puladas: ${totalWeeksSkipped}`);
    console.log(`Total de semanas: ${totalWeeksCreated + totalWeeksSkipped}`);

    res.json({
      message: "Migração de metas semanais concluída com sucesso",
      totalEmployees: employees.length,
      totalWeeksCreated,
      totalWeeksSkipped,
      totalWeeks: totalWeeksCreated + totalWeeksSkipped,
      details: results
    });
  } catch (error) {
    console.error("Erro ao migrar metas semanais:", error);
    res.status(500).json({ 
      error: "Erro ao migrar dados de metas semanais", 
      details: error.message 
    });
  }
});

// ROTAS DE PDV - MOVIMENTAÇÕES DE CAIXA

// Buscar origens configuradas
app.get("/api/pdv-origens", async (req, res) => {
  try {
    const origens = await prisma.pdvOrigemConfig.findMany({
      where: { ativo: true },
      orderBy: { nome: "asc" },
    });
    res.json(origens);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar origens", details: error.message });
  }
});

// Criar/gerenciar origens
app.post("/api/pdv-origens", async (req, res) => {
  try {
    const { nome } = req.body;
    const origem = await prisma.pdvOrigemConfig.create({ data: { nome } });
    res.status(201).json(origem);
  } catch (error) {
    res.status(500).json({ error: "Erro ao criar origem", details: error.message });
  }
});

app.delete("/api/pdv-origens/:id", async (req, res) => {
  try {
    await prisma.pdvOrigemConfig.delete({ where: { id: parseInt(req.params.id) } });
    res.json({ message: "Origem excluída com sucesso" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao excluir origem", details: error.message });
  }
});

// Registrar movimentação de caixa (ADD, SANGRIA, etc.)
app.post("/api/pdv-caixa-movimento", async (req, res) => {
  try {
    const { tipo, valor, origens, observacao } = req.body;

    // Extrair userId do token
    let userId = null;
    let userName = null;
    try {
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith("Bearer ")) {
        const token = authHeader.split(" ")[1];
        const decoded = jwt.verify(token, SECRET_KEY);
        userId = decoded.userId;
        const user = await prisma.user.findUnique({ where: { id: userId } });
        userName = user?.name || user?.username || null;
      }
    } catch (e) { /* ignora */ }

    const movimento = await prisma.pdvCaixaMovimento.create({
      data: {
        tipo,
        valor: parseFloat(valor),
        userId,
        userName,
        observacao: observacao || null,
        origens: {
          create: origens.map((o) => ({
            nome: o.nome,
            valor: parseFloat(o.valor),
          })),
        },
      },
      include: { origens: true },
    });

    res.status(201).json(movimento);
  } catch (error) {
    console.error("Erro ao registrar movimentação:", error);
    res.status(500).json({ error: "Erro ao registrar movimentação", details: error.message });
  }
});

// Registrar VALE (sangria / retirada de caixa)
app.post("/api/pdv-caixa-vale", async (req, res) => {
  try {
    const { valor, origens, observacao } = req.body;

    if (!valor || parseFloat(valor) <= 0) {
      return res.status(400).json({ error: "Valor inválido" });
    }

    // Extrair userId do token
    let userId = null;
    let userName = null;
    let isAdmin = false;
    try {
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith("Bearer ")) {
        const token = authHeader.split(" ")[1];
        const decoded = jwt.verify(token, SECRET_KEY);
        userId = decoded.userId;
        const user = await prisma.user.findUnique({ where: { id: userId } });
        userName = user?.name || user?.username || null;
        isAdmin = user?.acessos === true;
      }
    } catch (e) { /* ignora */ }

    const origensPreenchidas = (origens || []).filter((o) => o.nome && parseFloat(o.valor) > 0);

    // Criar movimento de caixa tipo VALE
    const movimento = await prisma.pdvCaixaMovimento.create({
      data: {
        tipo: "VALE",
        valor: parseFloat(valor),
        userId,
        userName,
        observacao: observacao || null,
        origens: origensPreenchidas.length > 0 ? {
          create: origensPreenchidas.map((o) => ({
            nome: o.nome,
            valor: parseFloat(o.valor),
          })),
        } : undefined,
      },
      include: { origens: true },
    });

    // Se é admin, criar registro de despesa no módulo PESSOAL
    let despesaPessoal = null;
    if (isAdmin) {
      const descParts = [];
      if (origensPreenchidas.length > 0) {
        descParts.push("Destino: " + origensPreenchidas.map(o => `${o.nome} (R$ ${parseFloat(o.valor).toFixed(2)})`).join(", "));
      }
      if (observacao) descParts.push(observacao);
      if (userName) descParts.push(`Realizado por: ${userName}`);

      despesaPessoal = await prisma.despPessoal.create({
        data: {
          nomeDespesa: "Vale / Sangria (PDV)",
          valorDespesa: parseFloat(valor),
          descDespesa: descParts.join(" | ") || null,
          date: new Date(),
          DespesaFixa: false,
          tipoMovimento: "GASTO",
          isVale: true,
        },
      });

      // Criar registro de GANHO correspondente (fluxo padrão do VALE no Pessoal)
      await prisma.despPessoal.create({
        data: {
          nomeDespesa: "VALE",
          valorDespesa: parseFloat(valor),
          descDespesa: `Vale referente a: Vale / Sangria (PDV)`,
          date: new Date(),
          DespesaFixa: false,
          tipoMovimento: "GANHO",
          isVale: true,
        },
      });
    }

    res.status(201).json({ movimento, despesaPessoal, isAdmin });
  } catch (error) {
    console.error("Erro ao registrar vale:", error);
    res.status(500).json({ error: "Erro ao registrar vale", details: error.message });
  }
});

// Buscar movimentações de caixa
app.get("/api/pdv-caixa-movimento", async (req, res) => {
  try {
    const { tipo, dataInicio, dataFim } = req.query;
    const where = {};
    if (tipo) where.tipo = tipo;
    if (dataInicio || dataFim) {
      where.createdAt = {};
      if (dataInicio) where.createdAt.gte = new Date(dataInicio);
      if (dataFim) {
        const fim = new Date(dataFim);
        fim.setHours(23, 59, 59, 999);
        where.createdAt.lte = fim;
      }
    }

    const movimentos = await prisma.pdvCaixaMovimento.findMany({
      where,
      include: { origens: true },
      orderBy: { createdAt: "desc" },
      take: 100,
    });
    res.json(movimentos);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar movimentações", details: error.message });
  }
});

// Inicializar origens padrão
app.post("/api/pdv-origens/init", async (req, res) => {
  try {
    const origensDefault = ["Cofre", "Banco", "Pessoal", "Troco Inicial"];
    const results = [];
    for (const nome of origensDefault) {
      const o = await prisma.pdvOrigemConfig.upsert({
        where: { nome },
        update: {},
        create: { nome, ativo: true },
      });
      results.push(o);
    }
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: "Erro ao inicializar origens", details: error.message });
  }
});

// ROTAS DE PRÊMIO (caça-níquel)
app.post("/api/pdv-premio", async (req, res) => {
  try {
    const { imagem1, imagem2, valor, origens, observacao } = req.body;

    if (!imagem1 || !imagem2) {
      return res.status(400).json({ error: "As duas imagens são obrigatórias" });
    }
    if (!valor || parseFloat(valor) <= 0) {
      return res.status(400).json({ error: "Valor inválido" });
    }

    // Extrair userId do token
    let userId = null;
    let userName = null;
    try {
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith("Bearer ")) {
        const token = authHeader.split(" ")[1];
        const decoded = jwt.verify(token, SECRET_KEY);
        userId = decoded.userId;
        const user = await prisma.user.findUnique({ where: { id: userId } });
        userName = user?.name || user?.username || null;
      }
    } catch (e) { /* ignora */ }

    const origensPreenchidas = (origens || []).filter((o) => o.nome && parseFloat(o.valor) > 0);

    const premio = await prisma.pdvPremio.create({
      data: {
        imagem1,
        imagem2,
        valor: parseFloat(valor),
        observacao: observacao || null,
        userId,
        userName,
        origens: origensPreenchidas.length > 0 ? {
          create: origensPreenchidas.map((o) => ({
            nome: o.nome,
            valor: parseFloat(o.valor),
          })),
        } : undefined,
      },
      include: { origens: true },
    });

    res.status(201).json(premio);
  } catch (error) {
    console.error("Erro ao registrar prêmio:", error);
    res.status(500).json({ error: "Erro ao registrar prêmio", details: error.message });
  }
});

app.get("/api/pdv-premio", async (req, res) => {
  try {
    const { dataInicio, dataFim } = req.query;
    const where = {};
    if (dataInicio || dataFim) {
      where.createdAt = {};
      if (dataInicio) where.createdAt.gte = new Date(dataInicio);
      if (dataFim) {
        const fim = new Date(dataFim);
        fim.setHours(23, 59, 59, 999);
        where.createdAt.lte = fim;
      }
    }

    const premios = await prisma.pdvPremio.findMany({
      where,
      include: { origens: true },
      orderBy: { createdAt: "desc" },
      take: 50,
    });
    // Retorna sem as imagens base64 no listing para performance
    const premiosResumo = premios.map(p => ({
      ...p,
      imagem1: p.imagem1 ? "[imagem]" : null,
      imagem2: p.imagem2 ? "[imagem]" : null,
    }));
    res.json(premiosResumo);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar prêmios", details: error.message });
  }
});

// ROTAS CONFIG VENDA — CUPONS
app.get("/api/pdv-cupons", async (req, res) => {
  try {
    const cupons = await prisma.pdvCupom.findMany({ orderBy: { createdAt: "desc" } });
    res.json(cupons);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar cupons", details: error.message });
  }
});

app.post("/api/pdv-cupons", async (req, res) => {
  try {
    const { codigo, tipo, valor, descricao, validoAte, limiteUso } = req.body;
    if (!codigo || !tipo || valor === undefined) {
      return res.status(400).json({ error: "Código, tipo e valor são obrigatórios" });
    }
    const cupom = await prisma.pdvCupom.create({
      data: {
        codigo: codigo.toUpperCase().trim(),
        tipo,
        valor: parseFloat(valor),
        descricao: descricao || null,
        validoAte: validoAte ? new Date(validoAte) : null,
        limiteUso: limiteUso ? parseInt(limiteUso) : null,
      },
    });
    res.status(201).json(cupom);
  } catch (error) {
    if (error.code === "P2002") {
      return res.status(400).json({ error: "Já existe um cupom com esse código" });
    }
    res.status(500).json({ error: "Erro ao criar cupom", details: error.message });
  }
});

app.put("/api/pdv-cupons/:id", async (req, res) => {
  try {
    const { ativo, codigo, tipo, valor, descricao, validoAte, limiteUso } = req.body;
    const updateData = {};
    if (ativo !== undefined) updateData.ativo = ativo;
    if (codigo !== undefined) updateData.codigo = codigo.toUpperCase().trim();
    if (tipo !== undefined) updateData.tipo = tipo;
    if (valor !== undefined) updateData.valor = parseFloat(valor);
    if (descricao !== undefined) updateData.descricao = descricao;
    if (validoAte !== undefined) updateData.validoAte = validoAte ? new Date(validoAte) : null;
    if (limiteUso !== undefined) updateData.limiteUso = limiteUso ? parseInt(limiteUso) : null;

    const cupom = await prisma.pdvCupom.update({
      where: { id: parseInt(req.params.id) },
      data: updateData,
    });
    res.json(cupom);
  } catch (error) {
    res.status(500).json({ error: "Erro ao atualizar cupom", details: error.message });
  }
});

app.delete("/api/pdv-cupons/:id", async (req, res) => {
  try {
    await prisma.pdvCupom.delete({ where: { id: parseInt(req.params.id) } });
    res.json({ message: "Cupom excluído" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao excluir cupom", details: error.message });
  }
});

// Validar cupom (para uso na venda)
app.post("/api/pdv-cupons/validar", async (req, res) => {
  try {
    const { codigo } = req.body;
    const cupom = await prisma.pdvCupom.findUnique({ where: { codigo: codigo.toUpperCase().trim() } });
    if (!cupom) return res.status(404).json({ error: "Cupom não encontrado" });
    if (!cupom.ativo) return res.status(400).json({ error: "Cupom desativado" });
    if (cupom.validoAte && new Date() > new Date(cupom.validoAte)) {
      return res.status(400).json({ error: "Cupom expirado" });
    }
    if (cupom.limiteUso && cupom.vezesUsado >= cupom.limiteUso) {
      return res.status(400).json({ error: "Cupom atingiu o limite de uso" });
    }
    res.json(cupom);
  } catch (error) {
    res.status(500).json({ error: "Erro ao validar cupom", details: error.message });
  }
});

// ROTAS CONFIG VENDA — TAXAS DE MÁQUINA
app.get("/api/pdv-taxas", async (req, res) => {
  try {
    const taxas = await prisma.pdvTaxaMaquina.findMany({ orderBy: { createdAt: "desc" } });
    res.json(taxas);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar taxas", details: error.message });
  }
});

app.post("/api/pdv-taxas", async (req, res) => {
  try {
    const { nome, tipo, valor } = req.body;
    if (!nome || !tipo || valor === undefined) {
      return res.status(400).json({ error: "Nome, tipo e valor são obrigatórios" });
    }
    const taxa = await prisma.pdvTaxaMaquina.create({
      data: { nome, tipo, valor: parseFloat(valor) },
    });
    res.status(201).json(taxa);
  } catch (error) {
    res.status(500).json({ error: "Erro ao criar taxa", details: error.message });
  }
});

app.put("/api/pdv-taxas/:id", async (req, res) => {
  try {
    const { nome, tipo, valor, ativo } = req.body;
    const updateData = {};
    if (nome !== undefined) updateData.nome = nome;
    if (tipo !== undefined) updateData.tipo = tipo;
    if (valor !== undefined) updateData.valor = parseFloat(valor);
    if (ativo !== undefined) updateData.ativo = ativo;
    const taxa = await prisma.pdvTaxaMaquina.update({
      where: { id: parseInt(req.params.id) },
      data: updateData,
    });
    res.json(taxa);
  } catch (error) {
    res.status(500).json({ error: "Erro ao atualizar taxa", details: error.message });
  }
});

app.delete("/api/pdv-taxas/:id", async (req, res) => {
  try {
    await prisma.pdvTaxaMaquina.delete({ where: { id: parseInt(req.params.id) } });
    res.json({ message: "Taxa excluída" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao excluir taxa", details: error.message });
  }
});

// ROTAS CONFIG VENDA — CONFIGURAÇÕES GERAIS (limites, etc)
app.get("/api/pdv-config", async (req, res) => {
  try {
    const configs = await prisma.pdvConfigVenda.findMany({ orderBy: { chave: "asc" } });
    res.json(configs);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar configurações", details: error.message });
  }
});

app.put("/api/pdv-config/:chave", async (req, res) => {
  try {
    const { valor } = req.body;
    const config = await prisma.pdvConfigVenda.upsert({
      where: { chave: req.params.chave },
      update: { valor: String(valor) },
      create: { chave: req.params.chave, valor: String(valor), descricao: req.body.descricao || null },
    });
    res.json(config);
  } catch (error) {
    res.status(500).json({ error: "Erro ao salvar configuração", details: error.message });
  }
});

app.post("/api/pdv-config/init", async (req, res) => {
  try {
    const defaults = [
      { chave: "limite_comanda", valor: "500", descricao: "Valor máximo permitido por comanda aberta (R$)" },
      { chave: "max_comandas_abertas", valor: "10", descricao: "Número máximo de comandas abertas simultaneamente" },
      { chave: "dias_vencimento_comanda", valor: "30", descricao: "Dias até uma comanda ser considerada vencida" },
    ];
    const results = [];
    for (const d of defaults) {
      const c = await prisma.pdvConfigVenda.upsert({
        where: { chave: d.chave },
        update: {},
        create: d,
      });
      results.push(c);
    }
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: "Erro ao inicializar configurações", details: error.message });
  }
});

// ROTAS CONFIG VENDA — FORMAS DE PAGAMENTO
app.get("/api/pdv-formas-pagamento", async (req, res) => {
  try {
    const formas = await prisma.pdvFormaPagamento.findMany({ orderBy: { nome: "asc" } });
    res.json(formas);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar formas de pagamento", details: error.message });
  }
});

app.post("/api/pdv-formas-pagamento", async (req, res) => {
  try {
    const { nome } = req.body;
    if (!nome || !nome.trim()) {
      return res.status(400).json({ error: "Nome é obrigatório" });
    }
    const valor = nome.trim().toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/\s+/g, "_");
    const forma = await prisma.pdvFormaPagamento.create({
      data: { nome: nome.trim(), valor },
    });
    res.status(201).json(forma);
  } catch (error) {
    if (error.code === "P2002") {
      return res.status(400).json({ error: "Já existe uma forma de pagamento com esse nome" });
    }
    res.status(500).json({ error: "Erro ao criar forma de pagamento", details: error.message });
  }
});

app.put("/api/pdv-formas-pagamento/:id", async (req, res) => {
  try {
    const { ativo } = req.body;
    const forma = await prisma.pdvFormaPagamento.update({
      where: { id: parseInt(req.params.id) },
      data: { ativo },
    });
    res.json(forma);
  } catch (error) {
    res.status(500).json({ error: "Erro ao atualizar forma de pagamento", details: error.message });
  }
});

app.delete("/api/pdv-formas-pagamento/:id", async (req, res) => {
  try {
    await prisma.pdvFormaPagamento.delete({ where: { id: parseInt(req.params.id) } });
    res.json({ message: "Forma de pagamento excluída" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao excluir forma de pagamento", details: error.message });
  }
});

app.post("/api/pdv-formas-pagamento/init", async (req, res) => {
  try {
    const defaults = [
      { nome: "Dinheiro", valor: "dinheiro" },
      { nome: "Cartão", valor: "cartao" },
      { nome: "PIX", valor: "pix" },
      { nome: "Fiado", valor: "fiado" },
    ];
    const results = [];
    for (const d of defaults) {
      const f = await prisma.pdvFormaPagamento.upsert({
        where: { nome: d.nome },
        update: {},
        create: { nome: d.nome, valor: d.valor, ativo: true },
      });
      results.push(f);
    }
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: "Erro ao inicializar formas de pagamento", details: error.message });
  }
});

// ========== ROTAS DE COMANDAS PDV ==========

// Converter comandas com 24h+ sem pagamento para fiado
const converterComandasExpiradas = async () => {
  try {
    const limite24h = new Date();
    limite24h.setHours(limite24h.getHours() - 24);

    const expiradas = await prisma.pdvComanda.findMany({
      where: { status: "ABERTA", createdAt: { lt: limite24h } },
      include: { items: true, client: true },
    });

    for (const comanda of expiradas) {
      await prisma.$transaction(async (tx) => {
        // Criar Purchase (fiado) para cada item da comanda
        for (const item of comanda.items) {
          await tx.purchase.create({
            data: {
              product: item.productName,
              quantity: item.quantity,
              total: item.total,
              date: comanda.createdAt.toISOString(),
              clientId: comanda.clientId,
            }
          });
        }
        // Atualizar totalDebt do cliente
        await tx.client.update({
          where: { id: comanda.clientId },
          data: { totalDebt: { increment: comanda.total } }
        });
        // Marcar comanda como FIADO
        await tx.pdvComanda.update({
          where: { id: comanda.id },
          data: { status: "FIADO" }
        });
      });
    }

    return expiradas.length;
  } catch (error) {
    console.error("Erro ao converter comandas expiradas:", error);
    return 0;
  }
};

// Buscar todas as comandas abertas (verifica expiradas antes)
app.get("/api/pdv-comandas", async (req, res) => {
  try {
    // Primeiro converte as expiradas
    await converterComandasExpiradas();

    const { status } = req.query;
    const where = {};
    if (status) {
      where.status = status;
    } else {
      where.status = "ABERTA";
    }

    const comandas = await prisma.pdvComanda.findMany({
      where,
      include: {
        client: true,
        items: true,
      },
      orderBy: { createdAt: "desc" },
    });
    res.json(comandas);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar comandas", details: error.message });
  }
});

// Buscar comanda específica
app.get("/api/pdv-comandas/:id", async (req, res) => {
  try {
    const comanda = await prisma.pdvComanda.findUnique({
      where: { id: parseInt(req.params.id) },
      include: { client: true, items: true },
    });
    if (!comanda) return res.status(404).json({ error: "Comanda não encontrada" });
    res.json(comanda);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar comanda", details: error.message });
  }
});

// Adicionar itens a uma comanda existente
app.post("/api/pdv-comandas/:id/items", async (req, res) => {
  try {
    const { items } = req.body;
    const comanda = await prisma.pdvComanda.findUnique({ where: { id: parseInt(req.params.id) } });
    if (!comanda) return res.status(404).json({ error: "Comanda não encontrada" });
    if (comanda.status !== "ABERTA") return res.status(400).json({ error: "Comanda já foi fechada" });

    const totalAdicionado = items.reduce((s, i) => s + (i.price * i.quantity), 0);

    const updated = await prisma.$transaction(async (tx) => {
      // Adicionar itens
      for (const item of items) {
        await tx.pdvComandaItem.create({
          data: {
            comandaId: comanda.id,
            productName: item.name,
            quantity: item.quantity,
            unitPrice: item.price,
            total: item.price * item.quantity,
            estoqueId: item.id || null,
          }
        });
        // Dar baixa no estoque
        if (item.id) {
          const estoqueItem = await tx.estoque.findUnique({ where: { id: item.id } });
          if (estoqueItem && estoqueItem.quantity >= item.quantity) {
            const prev = estoqueItem.quantity;
            const novo = prev - item.quantity;
            await tx.estoque.update({ where: { id: item.id }, data: { quantity: novo } });
            await tx.stockMovement.create({
              data: {
                estoqueId: item.id, type: 'SALE', quantity: -item.quantity,
                previousStock: prev, newStock: novo,
                description: `Comanda #${comanda.id} - ${item.name} (${item.quantity}x)`,
                referenceType: 'Comanda'
              }
            });
          }
        }
      }
      // Atualizar total da comanda
      return tx.pdvComanda.update({
        where: { id: comanda.id },
        data: { total: { increment: totalAdicionado } },
        include: { client: true, items: true },
      });
    });

    res.json(updated);
  } catch (error) {
    res.status(500).json({ error: "Erro ao adicionar itens", details: error.message });
  }
});

// Fechar/Pagar comanda
app.put("/api/pdv-comandas/:id/fechar", async (req, res) => {
  try {
    const { paymentMethod } = req.body;
    const comanda = await prisma.pdvComanda.findUnique({
      where: { id: parseInt(req.params.id) },
      include: { items: true, client: true },
    });
    if (!comanda) return res.status(404).json({ error: "Comanda não encontrada" });
    if (comanda.status !== "ABERTA") return res.status(400).json({ error: "Comanda já foi fechada" });

    const updated = await prisma.pdvComanda.update({
      where: { id: comanda.id },
      data: {
        status: "PAGA",
        paymentMethod: paymentMethod || "dinheiro",
        paidAt: new Date(),
      },
      include: { client: true, items: true },
    });

    res.json(updated);
  } catch (error) {
    res.status(500).json({ error: "Erro ao fechar comanda", details: error.message });
  }
});

// Buscar comandas abertas agrupadas por cliente (para o painel de config)
app.get("/api/pdv-comandas-pendentes", async (req, res) => {
  try {
    await converterComandasExpiradas();

    const comandas = await prisma.pdvComanda.findMany({
      where: { status: "ABERTA" },
      include: { client: true, items: true },
      orderBy: { createdAt: "desc" },
    });

    // Agrupar por cliente
    const clientMap = {};
    for (const c of comandas) {
      if (!c.client) continue; // Pular comandas sem cliente válido
      if (!clientMap[c.clientId]) {
        clientMap[c.clientId] = {
          id: c.clientId,
          name: c.client.name || "Cliente sem nome",
          totalDebt: c.client.totalDebt || 0,
          comandas: [],
          totalComandas: 0,
        };
      }
      clientMap[c.clientId].comandas.push(c);
      clientMap[c.clientId].totalComandas += c.total;
    }

    res.json(Object.values(clientMap));
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar comandas pendentes", details: error.message });
  }
});

// ===================== ROTAS CAIXA CONTROLE (PDV) =====================

// Obter caixa atual (aberto) ou último fechado
app.get("/api/pdv-caixa-controle/atual", async (req, res) => {
  try {
    const caixaAberto = await prisma.pdvCaixaControle.findFirst({
      where: { status: "ABERTO" },
      include: { transacoes: { orderBy: { createdAt: "desc" } } },
      orderBy: { abertoEm: "desc" },
    });
    if (caixaAberto) {
      // Calcular saldo atual
      const entradas = caixaAberto.transacoes.filter(t => t.tipo === "ENTRADA").reduce((s, t) => s + t.valor, 0);
      const saidas = caixaAberto.transacoes.filter(t => t.tipo === "SAIDA").reduce((s, t) => s + t.valor, 0);
      // saldoInicial já está incluído como transação ABERTURA (ENTRADA), não somar duas vezes
      const saldoAtual = entradas - saidas;
      const horasAberto = (new Date() - new Date(caixaAberto.abertoEm)) / (1000 * 60 * 60);
      return res.json({ ...caixaAberto, saldoAtual, totalEntradas: entradas, totalSaidas: saidas, horasAberto });
    }
    // Se não há caixa aberto, retorna o último fechado
    const ultimoFechado = await prisma.pdvCaixaControle.findFirst({
      where: { status: "FECHADO" },
      orderBy: { fechadoEm: "desc" },
    });
    res.json({ caixaAberto: null, ultimoFechado });
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar caixa atual", details: error.message });
  }
});

// Histórico de caixas
app.get("/api/pdv-caixa-controle/historico", async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const [caixas, total] = await Promise.all([
      prisma.pdvCaixaControle.findMany({
        orderBy: { abertoEm: "desc" },
        skip,
        take: parseInt(limit),
        include: { transacoes: { orderBy: { createdAt: "desc" } } },
      }),
      prisma.pdvCaixaControle.count(),
    ]);
    res.json({ caixas, total, pages: Math.ceil(total / parseInt(limit)) });
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar histórico", details: error.message });
  }
});

// Abrir novo caixa
app.post("/api/pdv-caixa-controle/abrir", async (req, res) => {
  try {
    const { saldoInicial, observacao } = req.body;

    // Verificar se já existe caixa aberto
    const caixaAberto = await prisma.pdvCaixaControle.findFirst({ where: { status: "ABERTO" } });
    if (caixaAberto) {
      return res.status(400).json({ error: "Já existe um caixa aberto! Feche-o antes de abrir um novo." });
    }

    // Extrair userId do token
    let userId = null;
    let userName = null;
    try {
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith("Bearer ")) {
        const token = authHeader.split(" ")[1];
        const decoded = jwt.verify(token, SECRET_KEY);
        userId = decoded.userId;
        const user = await prisma.user.findUnique({ where: { id: userId } });
        userName = user?.name || user?.username || null;
      }
    } catch (e) { /* ignora */ }

    const novoCaixa = await prisma.pdvCaixaControle.create({
      data: {
        saldoInicial: parseFloat(saldoInicial) || 0,
        observacao: observacao || null,
        abertoPorId: userId,
        abertoPorNome: userName,
        transacoes: parseFloat(saldoInicial) > 0 ? {
          create: {
            tipo: "ENTRADA",
            categoria: "ABERTURA",
            valor: parseFloat(saldoInicial),
            descricao: "Saldo inicial de abertura",
            userId,
            userName,
          }
        } : undefined,
      },
      include: { transacoes: true },
    });

    res.status(201).json(novoCaixa);
  } catch (error) {
    res.status(500).json({ error: "Erro ao abrir caixa", details: error.message });
  }
});

// Fechar caixa
app.put("/api/pdv-caixa-controle/fechar", async (req, res) => {
  try {
    const { observacao } = req.body;

    const caixaAberto = await prisma.pdvCaixaControle.findFirst({
      where: { status: "ABERTO" },
      include: { transacoes: true },
    });
    if (!caixaAberto) {
      return res.status(400).json({ error: "Nenhum caixa aberto para fechar." });
    }

    let userId = null;
    let userName = null;
    try {
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith("Bearer ")) {
        const token = authHeader.split(" ")[1];
        const decoded = jwt.verify(token, SECRET_KEY);
        userId = decoded.userId;
        const user = await prisma.user.findUnique({ where: { id: userId } });
        userName = user?.name || user?.username || null;
      }
    } catch (e) { /* ignora */ }

    const entradas = caixaAberto.transacoes.filter(t => t.tipo === "ENTRADA").reduce((s, t) => s + t.valor, 0);
    const saidas = caixaAberto.transacoes.filter(t => t.tipo === "SAIDA").reduce((s, t) => s + t.valor, 0);
    const saldoFinal = caixaAberto.saldoInicial + entradas - saidas;

    const caixaFechado = await prisma.pdvCaixaControle.update({
      where: { id: caixaAberto.id },
      data: {
        status: "FECHADO",
        saldoFinal,
        totalEntradas: entradas,
        totalSaidas: saidas,
        fechadoPorId: userId,
        fechadoPorNome: userName,
        fechadoEm: new Date(),
        observacao: observacao ? `${caixaAberto.observacao || ""} | Fechamento: ${observacao}`.trim() : caixaAberto.observacao,
      },
      include: { transacoes: true },
    });

    res.json(caixaFechado);
  } catch (error) {
    res.status(500).json({ error: "Erro ao fechar caixa", details: error.message });
  }
});

// Registrar transação no caixa aberto
app.post("/api/pdv-caixa-controle/transacao", async (req, res) => {
  try {
    const { tipo, categoria, valor, descricao } = req.body;

    if (!tipo || !categoria || !valor || parseFloat(valor) <= 0) {
      return res.status(400).json({ error: "Tipo, categoria e valor são obrigatórios." });
    }

    const caixaAberto = await prisma.pdvCaixaControle.findFirst({ where: { status: "ABERTO" } });
    if (!caixaAberto) {
      return res.status(400).json({ error: "Nenhum caixa aberto. Abra um caixa antes de registrar transações." });
    }

    let userId = null;
    let userName = null;
    try {
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith("Bearer ")) {
        const token = authHeader.split(" ")[1];
        const decoded = jwt.verify(token, SECRET_KEY);
        userId = decoded.userId;
        const user = await prisma.user.findUnique({ where: { id: userId } });
        userName = user?.name || user?.username || null;
      }
    } catch (e) { /* ignora */ }

    const transacao = await prisma.pdvCaixaTransacao.create({
      data: {
        caixaId: caixaAberto.id,
        tipo: tipo.toUpperCase(),
        categoria: categoria.toUpperCase(),
        valor: parseFloat(valor),
        descricao: descricao || null,
        userId,
        userName,
      },
    });

    res.status(201).json(transacao);
  } catch (error) {
    res.status(500).json({ error: "Erro ao registrar transação", details: error.message });
  }
});

// Obter transações do caixa atual
app.get("/api/pdv-caixa-controle/:id/transacoes", async (req, res) => {
  try {
    const transacoes = await prisma.pdvCaixaTransacao.findMany({
      where: { caixaId: parseInt(req.params.id) },
      orderBy: { createdAt: "desc" },
    });
    res.json(transacoes);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar transações", details: error.message });
  }
});

// ===================== ROTAS GASTOS BAR (PDV) =====================

// Listar gastos bar agrupados por semana
app.get("/api/pdv-gastos-bar", async (req, res) => {
  try {
    const { tipo, semanas = 8 } = req.query;
    const where = {};
    if (tipo) where.tipo = tipo;

    const gastos = await prisma.pdvGastoBar.findMany({
      where,
      orderBy: { createdAt: "desc" },
    });

    // Agrupar por semana (segunda a domingo)
    const getWeekKey = (date) => {
      const d = new Date(date);
      const day = d.getDay();
      const diff = d.getDate() - day + (day === 0 ? -6 : 1); // segunda
      const monday = new Date(d.setDate(diff));
      monday.setHours(0, 0, 0, 0);
      return monday.toISOString().split("T")[0];
    };

    const semanasMap = {};
    for (const g of gastos) {
      const weekKey = getWeekKey(g.createdAt);
      if (!semanasMap[weekKey]) semanasMap[weekKey] = { semana: weekKey, produtos: [], descontos: [], totalProdutos: 0, totalDescontos: 0, total: 0 };
      if (g.tipo === "PRODUTO") {
        semanasMap[weekKey].produtos.push(g);
        semanasMap[weekKey].totalProdutos += g.valorTotal;
      } else {
        semanasMap[weekKey].descontos.push(g);
        semanasMap[weekKey].totalDescontos += g.valorTotal;
      }
      semanasMap[weekKey].total += g.valorTotal;
    }

    const result = Object.values(semanasMap)
      .sort((a, b) => b.semana.localeCompare(a.semana))
      .slice(0, parseInt(semanas));

    res.json(result);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar gastos bar", details: error.message });
  }
});

// Registrar gasto bar (produto pego por funcionário ou desconto dado)
app.post("/api/pdv-gastos-bar", async (req, res) => {
  try {
    const { tipo, funcionario, funcionarioId, descricao, quantidade, valorUnitario, valorTotal, saleId } = req.body;

    if (!tipo || !funcionario || !valorTotal) {
      return res.status(400).json({ error: "Tipo, funcionário e valor total são obrigatórios." });
    }

    const gasto = await prisma.pdvGastoBar.create({
      data: {
        tipo,
        funcionario,
        funcionarioId: funcionarioId || null,
        descricao: descricao || null,
        quantidade: quantidade ? parseFloat(quantidade) : null,
        valorUnitario: valorUnitario ? parseFloat(valorUnitario) : null,
        valorTotal: parseFloat(valorTotal),
        saleId: saleId || null,
      },
    });

    res.status(201).json(gasto);
  } catch (error) {
    res.status(500).json({ error: "Erro ao registrar gasto bar", details: error.message });
  }
});

// Excluir gasto bar
app.delete("/api/pdv-gastos-bar/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    await prisma.pdvGastoBar.delete({ where: { id } });
    res.json({ message: "Gasto excluído com sucesso" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao excluir gasto", details: error.message });
  }
});

// Resumo por funcionário
app.get("/api/pdv-gastos-bar/resumo", async (req, res) => {
  try {
    const { de, ate } = req.query;
    const where = {};
    if (de || ate) {
      where.createdAt = {};
      if (de) where.createdAt.gte = new Date(de);
      if (ate) where.createdAt.lte = new Date(ate + "T23:59:59.999Z");
    }

    const gastos = await prisma.pdvGastoBar.findMany({ where, orderBy: { createdAt: "desc" } });

    const porFunc = {};
    for (const g of gastos) {
      if (!porFunc[g.funcionario]) porFunc[g.funcionario] = { funcionario: g.funcionario, totalProdutos: 0, totalDescontos: 0, total: 0, itens: [] };
      porFunc[g.funcionario].itens.push(g);
      if (g.tipo === "PRODUTO") porFunc[g.funcionario].totalProdutos += g.valorTotal;
      else porFunc[g.funcionario].totalDescontos += g.valorTotal;
      porFunc[g.funcionario].total += g.valorTotal;
    }

    res.json(Object.values(porFunc).sort((a, b) => b.total - a.total));
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar resumo", details: error.message });
  }
});

// ROTAS DE AUDITORIA
app.get("/api/auditoria", async (req, res) => {
  try {
    const { modulo, acao, userId, userName, dataInicio, dataFim, page = 1, limit = 50 } = req.query;
    const where = {};

    if (modulo) where.modulo = modulo;
    if (acao) where.acao = acao;
    if (userId) where.userId = parseInt(userId);
    if (userName) where.userName = { contains: userName, mode: "insensitive" };
    if (dataInicio || dataFim) {
      where.createdAt = {};
      if (dataInicio) where.createdAt.gte = new Date(dataInicio);
      if (dataFim) {
        const fim = new Date(dataFim);
        fim.setHours(23, 59, 59, 999);
        where.createdAt.lte = fim;
      }
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const [registros, total] = await Promise.all([
      prisma.auditoria.findMany({
        where,
        orderBy: { createdAt: "desc" },
        skip,
        take: parseInt(limit),
      }),
      prisma.auditoria.count({ where }),
    ]);

    res.json({
      registros,
      total,
      page: parseInt(page),
      totalPages: Math.ceil(total / parseInt(limit)),
    });
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar auditoria", details: error.message });
  }
});

// Retorna lista de módulos distintos para filtro
app.get("/api/auditoria/modulos", async (req, res) => {
  try {
    const modulos = await prisma.auditoria.findMany({
      select: { modulo: true },
      distinct: ["modulo"],
      orderBy: { modulo: "asc" },
    });
    res.json(modulos.map((m) => m.modulo));
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar módulos", details: error.message });
  }
});

// Retorna lista de usuários distintos para filtro
app.get("/api/auditoria/usuarios", async (req, res) => {
  try {
    const usuarios = await prisma.auditoria.findMany({
      select: { userId: true, userName: true },
      distinct: ["userId"],
      where: { userId: { not: null } },
      orderBy: { userName: "asc" },
    });
    res.json(usuarios);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar usuários da auditoria", details: error.message });
  }
});

// Estatísticas de auditoria
app.get("/api/auditoria/stats", async (req, res) => {
  try {
    const { dataInicio, dataFim } = req.query;
    const where = {};
    if (dataInicio || dataFim) {
      where.createdAt = {};
      if (dataInicio) where.createdAt.gte = new Date(dataInicio);
      if (dataFim) {
        const fim = new Date(dataFim);
        fim.setHours(23, 59, 59, 999);
        where.createdAt.lte = fim;
      }
    }

    const [totalRegistros, porModulo, porAcao, porUsuario] = await Promise.all([
      prisma.auditoria.count({ where }),
      prisma.auditoria.groupBy({ by: ["modulo"], _count: { id: true }, where, orderBy: { _count: { id: "desc" } } }),
      prisma.auditoria.groupBy({ by: ["acao"], _count: { id: true }, where, orderBy: { _count: { id: "desc" } } }),
      prisma.auditoria.groupBy({ by: ["userName"], _count: { id: true }, where: { ...where, userName: { not: null } }, orderBy: { _count: { id: "desc" } }, take: 10 }),
    ]);

    res.json({
      totalRegistros,
      porModulo: porModulo.map((m) => ({ modulo: m.modulo, count: m._count.id })),
      porAcao: porAcao.map((a) => ({ acao: a.acao, count: a._count.id })),
      porUsuario: porUsuario.map((u) => ({ userName: u.userName, count: u._count.id })),
    });
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar estatísticas", details: error.message });
  }
});

// ROTAS DE CONFIGURAÇÃO DE AUDITORIA
app.get("/api/auditoria-config", async (req, res) => {
  try {
    const configs = await prisma.auditoriaConfig.findMany({ orderBy: { modulo: "asc" } });
    res.json(configs);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar configurações de auditoria", details: error.message });
  }
});

app.put("/api/auditoria-config/:modulo", async (req, res) => {
  try {
    const { modulo } = req.params;
    const { ativo } = req.body;
    const config = await prisma.auditoriaConfig.upsert({
      where: { modulo },
      update: { ativo },
      create: { modulo, ativo },
    });
    res.json(config);
  } catch (error) {
    res.status(500).json({ error: "Erro ao atualizar configuração de auditoria", details: error.message });
  }
});

// Inicializa configurações de auditoria padrão
app.post("/api/auditoria-config/init", async (req, res) => {
  try {
    const modulos = ["caixa", "pdv", "produtos", "estoque", "maquinas", "fiado", "despesas", "pessoal", "ponto", "acessos", "autenticacao", "outro"];
    const results = [];
    for (const modulo of modulos) {
      const config = await prisma.auditoriaConfig.upsert({
        where: { modulo },
        update: {},
        create: { modulo, ativo: true },
      });
      results.push(config);
    }
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: "Erro ao inicializar configurações", details: error.message });
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

// Limpeza automática de auditoria (mantém apenas 30 dias)
const limparAuditoriaAntiga = async () => {
  try {
    const dataLimite = new Date();
    dataLimite.setDate(dataLimite.getDate() - 30);
    const resultado = await prisma.auditoria.deleteMany({
      where: { createdAt: { lt: dataLimite } },
    });
    if (resultado.count > 0) {
      console.log(`[Auditoria] ${resultado.count} registros com mais de 30 dias removidos.`);
    }
  } catch (err) {
    console.error("[Auditoria] Erro ao limpar registros antigos:", err.message);
  }
};

// Executa limpeza ao iniciar o servidor e depois a cada 24h
limparAuditoriaAntiga();
setInterval(limparAuditoriaAntiga, 24 * 60 * 60 * 1000);

// Verifica comandas expiradas ao iniciar e a cada 1h
converterComandasExpiradas().then(n => { if (n > 0) console.log(`[Comandas] ${n} comandas convertidas para fiado.`); });
setInterval(() => converterComandasExpiradas(), 60 * 60 * 1000);

app.listen(port, () => {
  console.log(`Server tá on krai --> http://localhost:${port}`);
});
