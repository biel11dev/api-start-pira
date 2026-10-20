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
const axios = require("axios");
const crypto = require("crypto");

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        connectSrc: ["'self'", "https://api-start-pira.vercel.app", "https://api-start-pira-qa.vercel.app"],
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
  if (rota.includes("/api/pdv-caixa") || rota.includes("/api/pdv-origens") || rota.includes("/api/pdv-origem-saldo")) return "pdv";
  if (rota.includes("/api/point")) return "pdv";
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
  if (rota.includes("/api/login") || rota.includes("/api/logout")) return "autenticacao";
  return "outro";
};

// Identifica o dispositivo/origem da ação a partir do header customizado ou do User-Agent
const resolveDispositivo = (clientHeader, userAgent) => {
  // Cliente customizado enviado pelo app mobile (X-Client)
  if (clientHeader) {
    const c = String(clientHeader).toLowerCase();
    if (c.includes("mobile") || c.includes("app") || c.includes("expo")) return "Aplicativo Mobile";
  }
  if (!userAgent) return "Desconhecido";
  const ua = userAgent.toLowerCase();
  if (ua.includes("expo") || ua.includes("okhttp") || ua.includes("cfnetwork") || ua.includes("start_pira") || ua.includes("startpira")) return "Aplicativo Mobile";
  if (ua.includes("android")) return "Android (navegador)";
  if (ua.includes("iphone") || ua.includes("ipad") || ua.includes("ios")) return "iPhone/iPad (navegador)";
  if (ua.includes("windows")) return "Windows (navegador)";
  if (ua.includes("macintosh") || ua.includes("mac os")) return "Mac (navegador)";
  if (ua.includes("linux")) return "Linux (navegador)";
  return "Outro navegador";
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

      const userAgent = req.headers["user-agent"] || null;
      const dispositivo = resolveDispositivo(req.headers["x-client"], userAgent);

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
          dispositivo,
          userAgent: userAgent ? userAgent.substring(0, 500) : null,
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

  const resetLink = `https://start-pira-qa.vercel.app/reset-password?token=${token}`;

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
  const { username, password, name, funcionario } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await prisma.user.create({
      data: {
        username,
        password: hashedPassword,
        name: name || null,
        funcionario: funcionario ?? false,
      },
    });

    // Se for funcionário, criar registro no Ponto (Employee) com valores padrão
    if (funcionario) {
      await prisma.employee.create({
        data: {
          name: name || username,
          position: null,
          carga: 0,
          valorHora: 0,
          metaHoras: null,
          bonificacao: null,
          contato: null,
          dataEntrada: new Date(),
          ativo: true,
        },
      });
    }

    res.json(newUser);
  } catch (error) {
    console.log("Dados recebidos:", req.body);
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

// ===== Ponto automático (login/logout) =====
// O Ponto guarda o horário local como se fosse UTC ("YYYY-MM-DDTHH:mm:00.000Z"), então usamos o fuso de Brasilía.
const PONTO_TZ = "America/Sao_Paulo";

const dataHoraLocal = (instante) => {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: PONTO_TZ,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  })
    .formatToParts(instante)
    .reduce((acc, p) => ({ ...acc, [p.type]: p.value }), {});
  return { date: `${parts.year}-${parts.month}-${parts.day}`, time: `${parts.hour}:${parts.minute}` };
};

// Funcionário ativo com ponto automático habilitado, relacionado ao usuário pelo nome (case-insensitive).
const buscarEmployeeAutoPonto = async (user) => {
  const nomes = [user.name, user.username].filter(Boolean).map((n) => n.trim().toLowerCase());
  if (nomes.length === 0) return null;
  const employees = await prisma.employee.findMany({ where: { autoPonto: true, ativo: true } });
  return employees.find((e) => nomes.includes((e.name || "").trim().toLowerCase())) || null;
};

const pontoDoDia = (employeeId, date) =>
  prisma.dailyPoint.findFirst({
    where: {
      employeeId,
      date: {
        gte: new Date(`${date}T00:00:00.000Z`),
        lt: new Date(`${date}T23:59:59.999Z`),
      },
    },
  });

// Grava entrada (login) e/ou saída (logout) no Ponto do dia, sem sobrescrever entrada já existente nem dias com falta.
const registrarPontoAutomatico = async (employee, { entrada, saida }) => {
  const hoje = dataHoraLocal(new Date()).date;
  const paraDateTime = (instante) => new Date(`${hoje}T${dataHoraLocal(instante).time}:00.000Z`);
  const existente = await pontoDoDia(employee.id, hoje);

  if (!existente) {
    await prisma.dailyPoint.create({
      data: {
        date: new Date(hoje),
        entry: entrada ? paraDateTime(entrada) : null,
        exit: saida ? paraDateTime(saida) : null,
        employeeId: employee.id,
      },
    });
    return;
  }
  if (existente.falta) return;

  const data = {};
  if (entrada && !existente.entry) data.entry = paraDateTime(entrada);
  if (saida) data.exit = paraDateTime(saida);
  if (Object.keys(data).length > 0) {
    await prisma.dailyPoint.update({ where: { id: existente.id }, data });
  }
};

const usuarioEhAdmin = async (req) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return false;
    const decoded = jwt.verify(token, SECRET_KEY);
    const user = await prisma.user.findUnique({ where: { id: decoded.userId } });
    return user?.acessos === true;
  } catch {
    return false;
  }
};

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await prisma.user.findUnique({ where: { username } });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "Usuário ou senha inválidos" });
  }

  // Registra o primeiro login do dia; falhas aqui nunca impedem o login.
  try {
    const agora = new Date();
    const mesmoDia = user.loginAt && dataHoraLocal(user.loginAt).date === dataHoraLocal(agora).date;
    const loginDoDia = mesmoDia ? user.loginAt : agora;
    if (!mesmoDia) {
      await prisma.user.update({ where: { id: user.id }, data: { loginAt: agora, logoutAt: null } });
    }
    const employee = await buscarEmployeeAutoPonto(user);
    if (employee) await registrarPontoAutomatico(employee, { entrada: loginDoDia });
  } catch (err) {
    console.error("Erro ao registrar login/ponto automático:", err.message);
  }

  const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: "12h" });
  // Inclua as permissões do usuário no retorno
  res.json({
    token,
    username: user.username,
    name: user.name,
    funcionario: user.funcionario,
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

// Informa se o logout do usuário precisa de confirmação (ponto automático) e o horário de saída atual.
app.get("/api/ponto-auto/status", authenticate, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.userId } });
    if (!user) return res.status(404).json({ error: "Usuário não encontrado" });
    const employee = await buscarEmployeeAutoPonto(user);
    res.json({ autoPonto: !!employee, exitTime: dataHoraLocal(new Date()).time });
  } catch (error) {
    res.status(500).json({ error: "Erro ao consultar ponto automático", details: error.message });
  }
});

// Registra o logout do dia; com ponto automático habilitado também grava a saída no Ponto.
app.post("/api/logout", authenticate, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.userId } });
    if (!user) return res.status(404).json({ error: "Usuário não encontrado" });

    const agora = new Date();
    await prisma.user.update({ where: { id: user.id }, data: { logoutAt: agora } });

    const employee = await buscarEmployeeAutoPonto(user);
    if (employee) {
      const loginHoje = user.loginAt && dataHoraLocal(user.loginAt).date === dataHoraLocal(agora).date ? user.loginAt : null;
      await registrarPontoAutomatico(employee, { entrada: loginHoje, saida: agora });
    }
    res.json({ ok: true, autoPonto: !!employee, exitTime: dataHoraLocal(agora).time });
  } catch (error) {
    res.status(500).json({ error: "Erro ao registrar logout", details: error.message });
  }
});

app.put("/api/users/:id", async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { name, funcionario, caixa, produtos, maquinas, fiado, despesas, ponto, acessos, base_produto, pdv, pessoal, auditoria } = req.body;

    const updateData = { funcionario, caixa, produtos, maquinas, fiado, despesas, ponto, acessos, base_produto, pdv, pessoal, auditoria };
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
// Um combo não tem estoque próprio: o disponível é derivado do estoque dos componentes.
// Opções marcadas como `base` entram em TODO combo, então cada uma limita o disponível
// individualmente (menor estoque manda). As demais são alternativas entre si e somam a
// quota que conseguem suprir para preencher o que sobra de `maxOpcoes`.
const calcularDisponibilidadeCombo = (item) => {
  const grupos = (item.composicoes || []).filter((c) => c.obrigatorio);
  if (grupos.length === 0) return 0;
  let disponivel = Infinity;
  for (const grupo of grupos) {
    const quotaPorCombo = Math.max(1, grupo.maxOpcoes || 1);
    const opcoes = (grupo.opcoes || []).filter((o) => o.disponivel && o.estoque);
    const bases = opcoes.filter((o) => o.base);
    const alternativas = opcoes.filter((o) => !o.base);

    let limiteGrupo = Infinity;
    for (const o of bases) {
      const consumo = Math.max(1, o.consomeQtd || 1);
      limiteGrupo = Math.min(limiteGrupo, Math.floor((o.estoque.quantity || 0) / consumo));
    }

    const quotaBase = bases.reduce((s, o) => s + Math.max(1, o.consomeQtd || 1), 0);
    const quotaRestante = Math.max(0, quotaPorCombo - quotaBase);
    if (quotaRestante > 0) {
      const quotaAlternativas = alternativas.reduce(
        (soma, o) => soma + (o.estoque.quantity || 0) * Math.max(1, o.consomeQtd || 1),
        0
      );
      limiteGrupo = Math.min(limiteGrupo, Math.floor(quotaAlternativas / quotaRestante));
    }

    disponivel = Math.min(disponivel, limiteGrupo === Infinity ? 0 : limiteGrupo);
  }
  return disponivel === Infinity ? 0 : Math.max(0, disponivel);
};

// Combos expõem o disponível calculado em `quantity` para que todas as telas
// (PDV, estoque, carrinho) enxerguem o mesmo número sem tratamento especial.
const comEstoqueDeCombo = (item) => {
  if (!item?.isCombo) return item;
  const disponivel = calcularDisponibilidadeCombo(item);
  return { ...item, quantity: disponivel, comboDisponivel: disponivel, quantidadePropria: item.quantity };
};

app.get("/api/estoque_prod", async (req, res) => {
  try {
    const produtos = await prisma.estoque.findMany({
      orderBy: [{ name: 'asc' }, { id: 'asc' }],
      include: {
        product: true,
        category: { include: { parent: true } },
        composicoes: { include: { opcoes: { include: { estoque: { select: { id: true, name: true, quantity: true, productId: true, unit: true, controlaMontante: true } } }, orderBy: { id: 'asc' } } }, orderBy: { ordem: 'asc' } },
        _count: { select: { composicaoOpcoes: true } }
      }
    });
    res.json(produtos.map(comEstoqueDeCombo));
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
        composicoes: { include: { opcoes: { include: { estoque: { select: { id: true, name: true, quantity: true, productId: true, unit: true, controlaMontante: true } } }, orderBy: { id: 'asc' } } }, orderBy: { ordem: 'asc' } }
      }
    });
    res.json(product ? comEstoqueDeCombo(product) : { error: "Produto não encontrado" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar produto", details: error.message });
  }
});

// Entrada de estoque - seleciona do catálogo, verifica se já existe, incrementa ou cria
app.post("/api/estoque_prod/entrada", async (req, res) => {
  try {
    const { productId, quantity, unit, value, valuecusto } = req.body;

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

    // Resolver valor de venda/custo desta unidade: body (editável) > unitPrices[unit] (cadastro) > produto
    const unitPriceCfg = catalogProduct.unitPrices && typeof catalogProduct.unitPrices === "object"
      ? catalogProduct.unitPrices[unit]
      : null;
    const bodyValue = value !== undefined && value !== null && value !== "" ? parseFloat(value) : null;
    const bodyCusto = valuecusto !== undefined && valuecusto !== null && valuecusto !== "" ? parseFloat(valuecusto) : null;
    const entradaValue = (bodyValue != null && !isNaN(bodyValue))
      ? bodyValue
      : (unitPriceCfg && unitPriceCfg.value != null ? Number(unitPriceCfg.value) : catalogProduct.value);
    const entradaCusto = (bodyCusto != null && !isNaN(bodyCusto))
      ? bodyCusto
      : (unitPriceCfg && unitPriceCfg.cost != null ? Number(unitPriceCfg.cost) : catalogProduct.valuecusto);

    // Verificar se já existe no estoque com mesmo productId e mesma unidade
    const existingStock = await prisma.estoque.findFirst({
      where: { productId: parseInt(productId), unit: unit }
    });

    const result = await prisma.$transaction(async (tx) => {
      let estoqueItem;

      // Produto controlado por montante: a entrada soma ML (garrafa = volume) e recalcula as unidades.
      const irmaControlada = await tx.estoque.findFirst({
        where: { productId: parseInt(productId), controlaMontante: true, isCombo: false }
      });
      if (irmaControlada) {
        let linha = existingStock;
        if (!linha) {
          linha = await tx.estoque.create({
            data: {
              productId: parseInt(productId),
              name: catalogProduct.name,
              quantity: 0,
              unit: unit,
              value: entradaValue,
              valuecusto: entradaCusto,
              categoria_Id: catalogProduct.categoryId || null,
              controlaMontante: true,
              montanteMl: irmaControlada.montanteMl
            }
          });
        } else if (!linha.controlaMontante) {
          linha = await tx.estoque.update({
            where: { id: linha.id },
            data: { controlaMontante: true, montanteMl: irmaControlada.montanteMl }
          });
        }
        const mov = await movimentarMontante(tx, linha, parsedQuantity);
        await tx.estoque.update({ where: { id: linha.id }, data: { value: entradaValue, valuecusto: entradaCusto } });
        await tx.stockMovement.create({
          data: {
            estoqueId: linha.id,
            type: 'ENTRY',
            quantity: parsedQuantity,
            previousStock: mov.previousStock,
            newStock: mov.newStock,
            description: `Entrada de ${parsedQuantity}x ${unit} - ${catalogProduct.name} (montante ${mov.montanteMl}ML)`,
            referenceType: 'Manual'
          }
        });
        return tx.estoque.findUnique({
          where: { id: linha.id },
          include: { product: true, category: { include: { parent: true } } }
        });
      }

      if (existingStock) {
        // Incrementar quantidade no registro existente
        const previousStock = existingStock.quantity;
        const newStock = previousStock + parsedQuantity;

        estoqueItem = await tx.estoque.update({
          where: { id: existingStock.id },
          data: { 
            quantity: newStock,
            value: entradaValue,
            valuecusto: entradaCusto
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
            value: entradaValue,
            valuecusto: entradaCusto,
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

    // Após a transação: checar EstoqueMinimo e gerenciar ListaCompras
    try {
      const minimo = await prisma.estoqueMinimo.findUnique({ where: { estoqueId: result.id } });
      if (minimo) {
        if (result.quantity > minimo.quantidadeMinima) {
          // Estoque voltou acima do mínimo → concluir entradas pendentes
          await prisma.listaCompras.updateMany({
            where: { estoqueId: result.id, status: "PENDENTE" },
            data: { status: "CONCLUIDO", concluidoEm: new Date() }
          });
        } else {
          // Ainda abaixo do mínimo → garantir que existe um registro PENDENTE
          const pendente = await prisma.listaCompras.findFirst({
            where: { estoqueId: result.id, status: "PENDENTE" }
          });
          if (!pendente) {
            await prisma.listaCompras.create({
              data: {
                estoqueId: result.id,
                nomeProduto: result.name,
                quantidadeAtual: result.quantity,
                quantidadeMinima: minimo.quantidadeMinima,
                status: "PENDENTE"
              }
            });
          } else {
            await prisma.listaCompras.update({
              where: { id: pendente.id },
              data: { quantidadeAtual: result.quantity }
            });
          }
        }
      }
    } catch (e) {
      console.error("Erro ao checar lista de compras após entrada:", e);
    }

    res.status(201).json(result);
  } catch (error) {
    console.error("Erro na entrada de estoque:", error);
    res.status(500).json({ error: "Erro ao registrar entrada no estoque", details: error.message });
  }
});

// ============================================================
// ESTOQUE MÍNIMO
// ============================================================

// Listar todos os mínimos
app.get("/api/estoque-minimo", async (req, res) => {
  try {
    const minimos = await prisma.estoqueMinimo.findMany({
      include: { estoque: { select: { id: true, name: true, unit: true, quantity: true } } }
    });
    res.json(minimos);
  } catch (e) {
    res.status(500).json({ error: "Erro ao buscar mínimos", details: e.message });
  }
});

// Criar ou atualizar mínimo de um item de estoque
app.post("/api/estoque-minimo", async (req, res) => {
  try {
    const { estoqueId, quantidadeMinima } = req.body;
    if (!estoqueId || quantidadeMinima == null) return res.status(400).json({ error: "estoqueId e quantidadeMinima são obrigatórios." });
    const minimo = await prisma.estoqueMinimo.upsert({
      where: { estoqueId: parseInt(estoqueId) },
      create: { estoqueId: parseInt(estoqueId), quantidadeMinima: parseFloat(quantidadeMinima) },
      update: { quantidadeMinima: parseFloat(quantidadeMinima) },
      include: { estoque: { select: { id: true, name: true, unit: true, quantity: true } } }
    });
    // Checar imediatamente se já está abaixo do mínimo
    if (minimo.estoque.quantity <= parseFloat(quantidadeMinima)) {
      const pendente = await prisma.listaCompras.findFirst({ where: { estoqueId: parseInt(estoqueId), status: "PENDENTE" } });
      if (!pendente) {
        await prisma.listaCompras.create({
          data: {
            estoqueId: parseInt(estoqueId),
            nomeProduto: minimo.estoque.name,
            quantidadeAtual: minimo.estoque.quantity,
            quantidadeMinima: parseFloat(quantidadeMinima),
            status: "PENDENTE"
          }
        });
      }
    }
    res.json(minimo);
  } catch (e) {
    res.status(500).json({ error: "Erro ao salvar mínimo", details: e.message });
  }
});

// Remover mínimo
app.delete("/api/estoque-minimo/:estoqueId", async (req, res) => {
  try {
    const estoqueId = parseInt(req.params.estoqueId);
    await prisma.estoqueMinimo.deleteMany({ where: { estoqueId } });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "Erro ao remover mínimo", details: e.message });
  }
});

// ============================================================
// LISTA DE COMPRAS
// ============================================================

// Listar (com filtro de status opcional)
app.get("/api/lista-compras", async (req, res) => {
  try {
    const { status } = req.query;
    const where = status ? { status } : {};
    const lista = await prisma.listaCompras.findMany({
      where,
      include: { estoque: { select: { id: true, name: true, unit: true, quantity: true, category: { include: { parent: true } } } } },
      orderBy: { createdAt: "desc" }
    });
    res.json(lista);
  } catch (e) {
    res.status(500).json({ error: "Erro ao buscar lista de compras", details: e.message });
  }
});

// Concluir manualmente um item
app.put("/api/lista-compras/:id/concluir", async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const item = await prisma.listaCompras.update({
      where: { id },
      data: { status: "CONCLUIDO", concluidoEm: new Date() }
    });
    res.json(item);
  } catch (e) {
    res.status(500).json({ error: "Erro ao concluir item", details: e.message });
  }
});

// Reabrir um item concluído
app.put("/api/lista-compras/:id/reabrir", async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const item = await prisma.listaCompras.update({
      where: { id },
      data: { status: "PENDENTE", concluidoEm: null }
    });
    res.json(item);
  } catch (e) {
    res.status(500).json({ error: "Erro ao reabrir item", details: e.message });
  }
});

// ============================================================
// HELPERS: ListaCompras e FollowUp
// ============================================================

// Retorna a semana ISO no formato "YYYY-Www"
function getISOWeekString(date = new Date()) {
  const d = new Date(date);
  d.setHours(0, 0, 0, 0);
  d.setDate(d.getDate() + 3 - ((d.getDay() + 6) % 7));
  const week1 = new Date(d.getFullYear(), 0, 4);
  const weekNum = 1 + Math.round(((d - week1) / 86400000 - 3 + ((week1.getDay() + 6) % 7)) / 7);
  return `${d.getFullYear()}-W${String(weekNum).padStart(2, "0")}`;
}

// Verifica se existe uma unidade de medida MAIOR (irmã) do mesmo produto com estoque
// disponível para conversão automática. Nesse caso o item NÃO está realmente em falta,
// pois a próxima venda converte a unidade maior sob demanda.
async function temUnidadeMaiorConvertivel(estoqueItem) {
  try {
    if (!estoqueItem?.productId) return false;
    if (estoqueItem.controlaMontante) return false; // montante já cobre todas as unidades
    const siblings = await prisma.estoque.findMany({
      where: { productId: estoqueItem.productId, id: { not: estoqueItem.id }, quantity: { gt: 0 } },
      orderBy: { id: 'asc' }
    });
    if (siblings.length === 0) return false;
    const eqs = await prisma.unitEquivalence.findMany();
    const eqMap = {};
    eqs.forEach(e => { eqMap[e.unitName] = e; });
    return irmaosConversiveis(estoqueItem, siblings, eqMap).some((c) => c.sibling.quantity >= 1);
  } catch {
    return false;
  }
}

// Verifica se o estoque atingiu o mínimo e cria/atualiza a ListaCompras
async function criarListaComprasSeNecessario(estoqueId, novaQuantidade) {
  try {
    const minimo = await prisma.estoqueMinimo.findUnique({ where: { estoqueId } });
    if (!minimo) return;
    const estoque = await prisma.estoque.findUnique({ where: { id: estoqueId }, select: { id: true, name: true, productId: true, unit: true, controlaMontante: true } });
    if (!estoque) return;
    if (novaQuantidade <= minimo.quantidadeMinima) {
      // Só é "falta" real se NÃO houver unidade de medida maior do mesmo produto para converter.
      // Se houver, o produto continua disponível (conversão automática na venda) → não registrar falta.
      const podeConverter = await temUnidadeMaiorConvertivel(estoque);
      if (podeConverter) {
        const pendente = await prisma.listaCompras.findFirst({ where: { estoqueId, status: "PENDENTE" } });
        if (pendente) {
          await prisma.listaCompras.update({ where: { id: pendente.id }, data: { status: "CONCLUIDO", concluidoEm: new Date() } });
        }
        return;
      }
      const pendente = await prisma.listaCompras.findFirst({ where: { estoqueId, status: "PENDENTE" } });
      if (pendente) {
        await prisma.listaCompras.update({ where: { id: pendente.id }, data: { quantidadeAtual: novaQuantidade } });
      } else {
        await prisma.listaCompras.create({
          data: { estoqueId, nomeProduto: estoque.name, quantidadeAtual: novaQuantidade, quantidadeMinima: minimo.quantidadeMinima, status: "PENDENTE" }
        });
      }
    } else {
      const pendente = await prisma.listaCompras.findFirst({ where: { estoqueId, status: "PENDENTE" } });
      if (pendente) {
        await prisma.listaCompras.update({ where: { id: pendente.id }, data: { status: "CONCLUIDO", concluidoEm: new Date() } });
      }
    }
  } catch (err) {
    console.error("Erro ao verificar lista de compras:", err.message);
  }
}

// ============================================================
// FOLLOW-UP
// ============================================================

// Gerar follow-ups da semana atual para todos os itens com contabiliza=false
app.post("/api/followup/gerar-semana", async (req, res) => {
  try {
    const semana = getISOWeekString();
    const itens = await prisma.estoque.findMany({ where: { contabiliza: false }, select: { id: true } });
    const criados = [];
    for (const item of itens) {
      try {
        const fu = await prisma.followUp.upsert({
          where: { estoqueId_semana: { estoqueId: item.id, semana } },
          update: {},
          create: { estoqueId: item.id, semana },
        });
        criados.push(fu);
      } catch (_) {}
    }
    res.json({ semana, total: criados.length });
  } catch (e) {
    res.status(500).json({ error: "Erro ao gerar follow-ups", details: e.message });
  }
});

// Buscar follow-ups pendentes da semana atual
app.get("/api/followup/pendentes", async (req, res) => {
  try {
    const semana = getISOWeekString();
    const pendentes = await prisma.followUp.findMany({
      where: { semana, temEstoque: null },
      include: { estoque: { select: { id: true, name: true, unit: true, quantity: true } } },
      orderBy: { createdAt: "asc" }
    });
    res.json(pendentes);
  } catch (e) {
    res.status(500).json({ error: "Erro ao buscar pendentes", details: e.message });
  }
});

// Responder um follow-up
app.put("/api/followup/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { temEstoque, quantidade, observacao, respondidoPor } = req.body;
    const fu = await prisma.followUp.update({
      where: { id },
      data: {
        temEstoque: typeof temEstoque === "boolean" ? temEstoque : null,
        quantidade: quantidade != null ? parseFloat(quantidade) : null,
        observacao: observacao || null,
        respondidoEm: new Date(),
        respondidoPor: respondidoPor || null,
      },
      include: { estoque: { select: { id: true, name: true, unit: true, quantity: true } } }
    });

         // Se SIM: atualizar estoque com a quantidade informada e checar mínimo
    if (temEstoque === true && quantidade != null) {
      const novaQtd = parseFloat(quantidade);
      await prisma.estoque.update({ where: { id: fu.estoqueId }, data: { quantity: novaQtd } });
      await criarListaComprasSeNecessario(fu.estoqueId, novaQtd);
    }

    // Se NÃO: zerar estoque e sempre garantir entrada na lista de compras (incondicional)
    if (temEstoque === false) {
      await prisma.estoque.update({ where: { id: fu.estoqueId }, data: { quantity: 0 } });
      const estoqueInfo = await prisma.estoque.findUnique({ where: { id: fu.estoqueId }, select: { name: true } });
      const minimoInfo = await prisma.estoqueMinimo.findUnique({ where: { estoqueId: fu.estoqueId } });
      const pendente = await prisma.listaCompras.findFirst({ where: { estoqueId: fu.estoqueId, status: "PENDENTE" } });
      if (pendente) {
        await prisma.listaCompras.update({ where: { id: pendente.id }, data: { quantidadeAtual: 0 } });
      } else if (estoqueInfo) {
        await prisma.listaCompras.create({
          data: {
            estoqueId: fu.estoqueId,
            nomeProduto: estoqueInfo.name,
            quantidadeAtual: 0,
            quantidadeMinima: minimoInfo?.quantidadeMinima || 0,
            status: "PENDENTE",
          },
        });
      }
    }


    res.json(fu);
  } catch (e) {
    res.status(500).json({ error: "Erro ao responder follow-up", details: e.message });
  }
});

// Histórico de follow-ups de um item
app.get("/api/followup/historico/:estoqueId", async (req, res) => {
  try {
    const estoqueId = parseInt(req.params.estoqueId);
    const historico = await prisma.followUp.findMany({
      where: { estoqueId },
      orderBy: { semana: "desc" },
      take: 52
    });
    res.json(historico);
  } catch (e) {
    res.status(500).json({ error: "Erro ao buscar histórico", details: e.message });
  }
});

// Monta um mapa { unitName -> objeto de equivalência } a partir da tabela global.
async function buildEqMap(client) {
  const all = await client.unitEquivalence.findMany();
  const map = {};
  all.forEach((e) => { map[e.unitName] = e; });
  return map;
}

// Retorna quantas "unidades base globais" uma unidade representa (não cadastradas = 1).
function unitValue(eqMap, unit) {
  return eqMap[unit]?.value ?? 1;
}

// Lista as unidades irmãs aptas a abastecer `estoqueItem` por conversão automática,
// ordenadas da melhor origem para a pior. Regras:
// - nunca converter a partir de outra unidade fracional (Dose → Dose);
// - quando o destino é fracional, só a unidade-pai de menor valor (ex.: Garrafa) é usada,
//   evitando consumir embalagens maiores (Fardo) e perder saldo;
// - a ordenação é determinística para que a baixa não varie entre vendas.
function irmaosConversiveis(estoqueItem, siblings, eqMap) {
  const currentEq = eqMap[estoqueItem.unit];
  const candidatos = [];
  for (const sib of siblings) {
    const sibEq = eqMap[sib.unit];
    if (sibEq?.isFractional) continue;
    // Combo é só uma variação de venda (sem estoque físico próprio): nunca serve de origem.
    if (sib.isCombo) continue;
    let ratio = null;
    if (currentEq?.isFractional && currentEq?.fractionalValue > 0) {
      ratio = currentEq.fractionalValue;
    } else {
      const currentVal = currentEq?.value || 1;
      const sibVal = sibEq?.value || 1;
      if (sibVal > currentVal) ratio = sibVal / currentVal;
    }
    if (!ratio || ratio <= 0) continue;
    candidatos.push({ sibling: sib, ratio, peso: sibEq?.value ?? 1 });
  }
  candidatos.sort((a, b) => a.peso - b.peso || a.sibling.id - b.sibling.id);
  if (currentEq?.isFractional && candidatos.length > 0) {
    const menorPeso = candidatos[0].peso;
    return candidatos.filter((c) => c.peso === menorPeso);
  }
  return candidatos;
}

// Resolve a unidade base (unitária = 1) de um produto.
// Usa product.baseUnit quando definido; caso contrário deduz a menor unidade
// cadastrada no estoque do produto (menor "value" nas equivalências globais).
async function resolveProductBaseUnit(client, productId, eqMap, explicitBaseUnit) {
  if (explicitBaseUnit) return explicitBaseUnit;
  const rows = await client.estoque.findMany({ where: { productId }, select: { unit: true } });
  let best = null;
  let bestVal = Infinity;
  for (const r of rows) {
    const eq = eqMap[r.unit];
    if (eq?.isFractional) continue; // unidades fracionais (Dose/Taça) não servem de base
    const val = eq?.value ?? 1; // unidades não cadastradas valem 1 (ex.: "Unidade", "Lata")
    if (val < bestVal) { bestVal = val; best = r.unit; }
  }
  return best || "Unidade";
}

// ===== Estoque por montante (ML) — opt-in por produto (Estoque.controlaMontante) =====
// Para produtos vendidos inteiros e em doses (ex.: aguardente), o saldo real é um único
// montante em ML. Garrafa e doses são derivadas dele (piso do montante / ML da unidade) e
// gravadas em `quantity`, então o restante do sistema segue lendo `quantity` normalmente.
// Produtos sem a flag não passam por nenhuma destas funções.

function parseMl(texto) {
  const m = /(\d+(?:[.,]\d+)?)\s*ml\b/i.exec(String(texto ?? ""));
  return m ? parseFloat(m[1].replace(",", ".")) : null;
}

// ML que uma linha de estoque representa: unidade ("Dose 80ML") ou, na garrafa, o volume do título.
function mlDaLinha(linha, nomeProduto) {
  return parseMl(linha?.unit) ?? parseMl(linha?.name) ?? parseMl(nomeProduto);
}

function quantidadeDoMontante(montanteMl, ml) {
  return Math.floor(montanteMl / ml + 1e-9);
}

// Linhas do produto elegíveis ao controle (variações de venda/combos ficam de fora).
function linhasDoProduto(client, productId, apenasControladas) {
  return client.estoque.findMany({
    where: { productId, isCombo: false, ...(apenasControladas ? { controlaMontante: true } : {}) },
    include: { product: { select: { name: true } } },
    orderBy: { id: "asc" },
  });
}

// Grava o montante e recalcula `quantity` de todas as linhas controladas do produto.
async function sincronizarMontante(tx, productId, montanteMl) {
  const linhas = await linhasDoProduto(tx, productId, true);
  for (const l of linhas) {
    const ml = mlDaLinha(l, l.product?.name);
    if (!ml) continue;
    await tx.estoque.update({
      where: { id: l.id },
      data: { montanteMl, quantity: quantidadeDoMontante(montanteMl, ml) },
    });
  }
}

// Aplica uma variação em unidades da linha ao montante (positivo = entrada, negativo = baixa).
async function movimentarMontante(tx, estoqueItem, deltaUnidades, rotuloErro) {
  const linhas = await linhasDoProduto(tx, estoqueItem.productId, true);
  const linha = linhas.find((l) => l.id === estoqueItem.id);
  const ml = linha ? mlDaLinha(linha, linha.product?.name) : null;
  if (!ml) {
    throw new Error(`Não foi possível identificar o volume (ML) de "${estoqueItem.name}" (${estoqueItem.unit}).`);
  }
  const deltaMl = deltaUnidades * ml;
  const alvo = { productId: estoqueItem.productId, controlaMontante: true, isCombo: false };

  if (deltaMl < 0) {
    const r = await tx.estoque.updateMany({
      where: { ...alvo, montanteMl: { gte: -deltaMl - 1e-6 } },
      data: { montanteMl: { increment: deltaMl } },
    });
    if (r.count === 0) {
      throw new Error(`Estoque insuficiente para ${rotuloErro || `"${estoqueItem.name}"`} (${estoqueItem.unit}). Disponível: ${linha.quantity}, Necessário: ${-deltaUnidades}.`);
    }
  } else if (deltaMl > 0) {
    await tx.estoque.updateMany({ where: alvo, data: { montanteMl: { increment: deltaMl } } });
  }

  const atual = await tx.estoque.findUnique({ where: { id: estoqueItem.id }, select: { montanteMl: true } });
  await sincronizarMontante(tx, estoqueItem.productId, atual.montanteMl);
  const depois = await tx.estoque.findUnique({ where: { id: estoqueItem.id }, select: { quantity: true } });
  return { previousStock: linha.quantity, newStock: depois.quantity, montanteMl: atual.montanteMl };
}

// Montante atual somando o que já existe em cada linha (garrafas x volume + doses x ML).
function calcularMontanteInicial(linhas) {
  let total = 0;
  const detalhes = linhas.map((l) => {
    const ml = mlDaLinha(l, l.product?.name);
    const subtotalMl = ml ? (l.quantity || 0) * ml : null;
    if (subtotalMl != null) total += subtotalMl;
    return { id: l.id, unit: l.unit, name: l.name, quantity: l.quantity, ml, subtotalMl, ativo: l.controlaMontante };
  });
  return { total, detalhes };
}

// Prévia: como ficam as quantidades se o controle por montante for ativado agora.
app.get("/api/estoque_prod/montante/preview/:productId", async (req, res) => {
  try {
    const productId = parseInt(req.params.productId, 10);
    if (isNaN(productId)) return res.status(400).json({ error: "productId inválido" });
    const linhas = await linhasDoProduto(prisma, productId, false);
    if (linhas.length === 0) return res.status(404).json({ error: "Produto sem itens no estoque." });
    const ativo = linhas.some((l) => l.controlaMontante);
    const controladas = linhas.filter((l) => l.controlaMontante);
    const base = ativo ? controladas : linhas;
    const { total, detalhes } = calcularMontanteInicial(base);
    const montanteMl = ativo ? Math.max(...controladas.map((l) => l.montanteMl || 0)) : total;
    const semMl = detalhes.filter((d) => !d.ml);
    const resultado = detalhes
      .filter((d) => d.ml)
      .map((d) => ({ id: d.id, unit: d.unit, ml: d.ml, quantidadeAtual: d.quantity, quantidadeNova: quantidadeDoMontante(montanteMl, d.ml) }));
    res.json({ productId, nome: linhas[0].product?.name || linhas[0].name, ativo, montanteMl, detalhes, resultado, semMl });
  } catch (error) {
    res.status(500).json({ error: "Erro ao gerar prévia do montante", details: error.message });
  }
});

// Ativa o controle por montante: converte o saldo atual em ML e recalcula as quantidades.
app.post("/api/estoque_prod/montante/ativar", async (req, res) => {
  try {
    const productId = parseInt(req.body.productId, 10);
    if (isNaN(productId)) return res.status(400).json({ error: "productId inválido" });
    const result = await prisma.$transaction(async (tx) => {
      const linhas = await linhasDoProduto(tx, productId, false);
      if (linhas.length === 0) throw new Error("Produto sem itens no estoque.");
      if (linhas.some((l) => l.controlaMontante)) throw new Error("Este produto já usa controle por montante.");
      const { total, detalhes } = calcularMontanteInicial(linhas);
      const semMl = detalhes.filter((d) => !d.ml);
      if (semMl.length > 0) {
        throw new Error(`Não foi possível identificar o ML de: ${semMl.map((d) => d.unit).join(", ")}. Inclua o volume (ex.: 80ML) na unidade ou no nome.`);
      }
      const antes = new Map(linhas.map((l) => [l.id, l.quantity]));
      await tx.estoque.updateMany({ where: { productId, isCombo: false }, data: { controlaMontante: true, montanteMl: total } });
      await sincronizarMontante(tx, productId, total);
      const depois = await linhasDoProduto(tx, productId, true);
      for (const l of depois) {
        if (l.quantity === antes.get(l.id)) continue;
        await tx.stockMovement.create({
          data: {
            estoqueId: l.id,
            type: "ADJUSTMENT",
            quantity: l.quantity - antes.get(l.id),
            previousStock: antes.get(l.id),
            newStock: l.quantity,
            description: `Controle por montante ativado (${total}ML)`,
            referenceType: "Manual",
          },
        });
      }
      return { montanteMl: total, linhas: depois.map((l) => ({ id: l.id, unit: l.unit, quantity: l.quantity })) };
    });
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Desativa: mantém as quantidades já calculadas e volta à lógica padrão de conversão.
app.post("/api/estoque_prod/montante/desativar", async (req, res) => {
  try {
    const productId = parseInt(req.body.productId, 10);
    if (isNaN(productId)) return res.status(400).json({ error: "productId inválido" });
    await prisma.estoque.updateMany({ where: { productId, controlaMontante: true }, data: { controlaMontante: false, montanteMl: 0 } });
    res.json({ message: "Controle por montante desativado." });
  } catch (error) {
    res.status(500).json({ error: "Erro ao desativar controle por montante", details: error.message });
  }
});

// Conversões manuais não se aplicam a itens controlados por montante.
const MSG_MONTANTE_SEM_CONVERSAO = "Este produto é controlado por montante (ML): não há conversão entre unidades.";

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
    if (estoqueItem.controlaMontante) {
      return res.status(400).json({ error: MSG_MONTANTE_SEM_CONVERSAO });
    }

    // Determinar a unidade base (unitária) do produto
    const eqMap = await buildEqMap(prisma);
    const baseUnit = await resolveProductBaseUnit(prisma, estoqueItem.productId, eqMap, estoqueItem.product?.baseUnit);

    if (estoqueItem.unit === baseUnit) {
      return res.status(400).json({ error: `Este item já está na unidade base ("${baseUnit}"), não é possível converter.` });
    }

    if (estoqueItem.quantity < parsedQty) {
      return res.status(400).json({ 
        error: `Quantidade insuficiente. Disponível: ${estoqueItem.quantity} ${estoqueItem.unit}(s)` 
      });
    }

    // Fator de conversão relativo à unidade base (ex.: Fardo(12) → Lata(1) = 12)
    const factor = unitValue(eqMap, estoqueItem.unit) / unitValue(eqMap, baseUnit);
    if (!(factor > 1)) {
      return res.status(400).json({ 
        error: `Não é possível converter "${estoqueItem.unit}" para a unidade base "${baseUnit}". Verifique as equivalências cadastradas.` 
      });
    }

    const unitsGenerated = parsedQty * factor;
    const unitValueSell = estoqueItem.value / factor;
    const unitValueCost = estoqueItem.valuecusto / factor;

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
          description: `Conversão: ${parsedQty}x ${estoqueItem.unit} → ${unitsGenerated}x ${baseUnit}`,
          referenceType: 'Conversion'
        }
      });

      // 2. Verificar se já existe registro na unidade base para este produto
      const existingUnitStock = await tx.estoque.findFirst({
        where: { productId: estoqueItem.productId, unit: baseUnit }
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
            description: `Conversão: ${parsedQty}x ${estoqueItem.unit} → ${unitsGenerated}x ${baseUnit}`,
            referenceType: 'Conversion'
          }
        });
      } else {
        unitEstoqueItem = await tx.estoque.create({
          data: {
            productId: estoqueItem.productId,
            name: estoqueItem.name,
            quantity: unitsGenerated,
            unit: baseUnit,
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
            description: `Conversão: ${parsedQty}x ${estoqueItem.unit} → ${unitsGenerated}x ${baseUnit} (novo registro)`,
            referenceType: 'Conversion'
          }
        });
      }

      return {
        origin: { id: estoqueItem.id, name: estoqueItem.name, unit: estoqueItem.unit, removed: parsedQty, remaining: newStock },
        destination: { id: unitEstoqueItem.id, name: estoqueItem.name, unit: baseUnit, added: unitsGenerated, total: unitEstoqueItem.quantity },
        conversionFactor: factor
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
    if (estoqueItem.controlaMontante) {
      return res.status(400).json({ error: MSG_MONTANTE_SEM_CONVERSAO });
    }

    // Determinar a unidade base (unitária) do produto
    const eqMap = await buildEqMap(prisma);
    const baseUnit = await resolveProductBaseUnit(prisma, estoqueItem.productId, eqMap, estoqueItem.product?.baseUnit);

    if (estoqueItem.unit !== baseUnit) {
      return res.status(400).json({ error: `Este item não está na unidade base ("${baseUnit}"). Use a conversão normal.` });
    }

    // Fator de conversão da unidade de destino relativo à base (ex.: Fardo(12) sobre Lata(1) = 12)
    const factor = unitValue(eqMap, targetUnit) / unitValue(eqMap, baseUnit);
    if (!(factor > 1)) {
      return res.status(400).json({
        error: `Não é possível empacotar "${baseUnit}" em "${targetUnit}". Verifique as equivalências cadastradas.`
      });
    }

    const unitsNeeded = parsedQty * factor;

    if (estoqueItem.quantity < unitsNeeded) {
      return res.status(400).json({
        error: `Unidades insuficientes. Necessário: ${unitsNeeded} ${baseUnit}. Disponível: ${estoqueItem.quantity} ${baseUnit}.`
      });
    }

    const packedValueSell = estoqueItem.value * factor;
    const packedValueCost = estoqueItem.valuecusto * factor;

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
          description: `Conversão reversa: ${unitsNeeded}x ${baseUnit} → ${parsedQty}x ${targetUnit}`,
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
            description: `Conversão reversa: ${unitsNeeded}x ${baseUnit} → ${parsedQty}x ${targetUnit}`,
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
            description: `Conversão reversa: ${unitsNeeded}x ${baseUnit} → ${parsedQty}x ${targetUnit} (novo registro)`,
            referenceType: 'Conversion'
          }
        });
      }

      return {
        origin: { id: estoqueItem.id, name: estoqueItem.name, unit: baseUnit, removed: unitsNeeded, remaining: newStock },
        destination: { id: packedEstoqueItem.id, name: estoqueItem.name, unit: targetUnit, added: parsedQty, total: packedEstoqueItem.quantity },
        conversionFactor: factor
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
    if (estoqueItem.controlaMontante) {
      return res.status(400).json({ error: MSG_MONTANTE_SEM_CONVERSAO });
    }
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
});

app.post("/api/estoque_prod", async (req, res) => {
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
    const { name, quantity, unit, value, valuecusto, categoryId, contabiliza, mostrarPdv, isCombo, comboNome } = req.body;

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

    // Item controlado por montante: a quantidade informada vira o novo montante (a sobra em ML é preservada).
    let quantidadeFinal = parsedQuantity;
    const itemAtual = await prisma.estoque.findUnique({ where: { id: parseInt(req.params.id) } });
    if (itemAtual?.controlaMontante && parsedQuantity !== itemAtual.quantity) {
      quantidadeFinal = await prisma.$transaction(async (tx) => {
        const linhas = await linhasDoProduto(tx, itemAtual.productId, true);
        const linha = linhas.find((l) => l.id === itemAtual.id);
        const ml = linha ? mlDaLinha(linha, linha.product?.name) : null;
        if (!ml) throw new Error(`Não foi possível identificar o volume (ML) de "${itemAtual.name}" (${itemAtual.unit}).`);
        const sobra = (itemAtual.montanteMl || 0) - quantidadeDoMontante(itemAtual.montanteMl || 0, ml) * ml;
        await sincronizarMontante(tx, itemAtual.productId, parsedQuantity * ml + sobra);
        return parsedQuantity;
      });
    }

    const updatedProduct = await prisma.estoque.update({
      where: { id: parseInt(req.params.id) },
      data: { 
        name, 
        quantity: quantidadeFinal, 
        unit, 
        value: parsedValue, 
        valuecusto: parsedValueCusto,
        categoria_Id: categoryId ? parseInt(categoryId) : null,
        ...(contabiliza !== undefined ? { contabiliza: Boolean(contabiliza) } : {}),
        ...(mostrarPdv !== undefined ? { mostrarPdv: Boolean(mostrarPdv) } : {}),
        ...(isCombo !== undefined ? { isCombo: Boolean(isCombo) } : {}),
        ...(comboNome !== undefined ? { comboNome: comboNome || null } : {})
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
    if (!password) {
      return res.status(400).json({ error: "Senha é obrigatória" });
    }

    // Identifica o usuário preferencialmente pelo token JWT (enviado no header).
    // Assim não depende do valor de "username" enviado pelo frontend, que pode
    // conter o nome de exibição em vez do login.
    let user = null;
    const authHeader = req.headers.authorization;
    if (authHeader) {
      try {
        const token = authHeader.split(" ")[1];
        const decoded = jwt.verify(token, SECRET_KEY);
        user = await prisma.user.findUnique({ where: { id: decoded.userId } });
      } catch (tokenErr) {
        // Token ausente/expirado: cai no fallback por username abaixo.
      }
    }

    // Fallback: identifica pelo username informado no corpo da requisição.
    if (!user && username) {
      user = await prisma.user.findUnique({ where: { username } });
    }

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
        },
        estoqueItems: { select: { unit: true } }
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
        },
        estoqueItems: { select: { unit: true } }
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
    const { name, unit, value, valuecusto, categoryId, baseUnit, pdvHiddenUnits, unitPrices } = req.body;

    if (!name || !unit) {
      return res.status(400).json({ error: "Nome e unidade são obrigatórios." });
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
        unit, 
        value: parsedValue, 
        valuecusto: parsedValueCusto,
        categoryId: categoryId || null,
        baseUnit: baseUnit || null,
        pdvHiddenUnits: Array.isArray(pdvHiddenUnits) ? pdvHiddenUnits : [],
        ...(unitPrices && typeof unitPrices === "object" ? { unitPrices } : {})
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
    const { name, quantity, unit, value, valuecusto, categoryId, baseUnit, pdvHiddenUnits, unitPrices } = req.body;

    if (!name || !unit) {
      return res.status(400).json({ error: "Todos os campos são obrigatórios." });
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
        unit, 
        value: parsedValue, 
        valuecusto: parsedValueCusto,
        categoryId: categoryId || null,
        baseUnit: baseUnit || null,
        ...(pdvHiddenUnits !== undefined ? { pdvHiddenUnits: Array.isArray(pdvHiddenUnits) ? pdvHiddenUnits : [] } : {}),
        ...(unitPrices !== undefined ? { unitPrices: unitPrices && typeof unitPrices === "object" ? unitPrices : null } : {})
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
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) return res.status(400).json({ error: "ID inválido" });

    const vinculo = await prisma.pdvCaixaControle.findFirst({ where: { balanceId: id } });
    if (vinculo) {
      return res.status(409).json({
        error: "Este registro está vinculado a um caixa fechado. Contate um administrador para realizar alterações.",
        caixaId: vinculo.id,
        fechadoEm: vinculo.fechadoEm,
      });
    }

    res.json(await prisma.balance.update({ where: { id }, data: req.body }));
  } catch (error) {
    res.status(500).json({ error: "Erro ao atualizar saldo", details: error.message });
  }
});

app.delete("/api/balances/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({ error: "ID inválido" });
    }

    // Verificar se existe sub-caixa fechado vinculado a este Balance
    const vinculo = await prisma.pdvCaixaControle.findFirst({ where: { balanceId: id } });
    if (vinculo) {
      return res.status(409).json({
        error: "Este caixa está fechado e vinculado a um fechamento de turno. Não é possível excluí-lo. Contate um administrador.",
        caixaId: vinculo.id,
        fechadoEm: vinculo.fechadoEm,
        fechadoPorNome: vinculo.fechadoPorNome,
      });
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
      ativo = true,
      autoPonto = false
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
        ativo,
        autoPonto: autoPonto === true && (await usuarioEhAdmin(req))
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
      ativo,
      autoPonto
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
    // Somente administrador altera o ponto automático; para os demais o campo é ignorado.
    if (autoPonto !== undefined && (await usuarioEhAdmin(req))) updateData.autoPonto = autoPonto === true;
    
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

// Baixa estoque de um item aplicando conversão automática de unidade irmã (mesma lógica dos itens de venda).
// Usado tanto para itens normais quanto para componentes de composição.
// Aceita o formato legado ({ grupoId: [opcaoId] }) e o novo com quantidade
// ({ grupoId: [{ id, qtd }] }), devolvendo sempre [{ opcaoId, qtd }].
function parseSelecoesComposicao(composicaoJSON) {
  let selections;
  try { selections = JSON.parse(composicaoJSON); } catch { return []; }
  if (!selections || typeof selections !== 'object') return [];
  const escolhas = [];
  for (const opcoes of Object.values(selections)) {
    if (!Array.isArray(opcoes)) continue;
    for (const opcao of opcoes) {
      if (opcao && typeof opcao === 'object') {
        const opcaoId = Number(opcao.id);
        if (opcaoId) escolhas.push({ opcaoId, qtd: Math.max(1, parseInt(opcao.qtd, 10) || 1) });
      } else {
        const opcaoId = Number(opcao);
        if (opcaoId) escolhas.push({ opcaoId, qtd: 1 });
      }
    }
  }
  return escolhas;
}

async function baixarEstoqueComConversao(tx, estoqueId, needed, eqMap, saleId, descricao, rotuloErro) {
  const estoqueItem = await tx.estoque.findUnique({ where: { id: estoqueId } });
  if (!estoqueItem) return;
  // Descartáveis (contabiliza=false) não baixam estoque
  if (estoqueItem.contabiliza === false) return;

  // Produto por montante: baixa em ML, sem conversão entre unidades
  if (estoqueItem.controlaMontante) {
    const mov = await movimentarMontante(tx, estoqueItem, -needed, rotuloErro);
    await tx.stockMovement.create({
      data: {
        estoqueId: estoqueItem.id,
        type: 'SALE',
        quantity: -needed,
        previousStock: mov.previousStock,
        newStock: mov.newStock,
        description: descricao,
        referenceId: saleId,
        referenceType: 'Sale'
      }
    });
    return;
  }

  let currentStock = estoqueItem.quantity;

  if (currentStock < needed) {
    const deficit = needed - currentStock;
    const siblings = await tx.estoque.findMany({
      where: { productId: estoqueItem.productId, id: { not: estoqueItem.id } },
      orderBy: { id: 'asc' }
    });
    let conversionDone = false;
    for (const { sibling, ratio } of irmaosConversiveis(estoqueItem, siblings, eqMap)) {
      const neededSiblings = Math.ceil(deficit / ratio);
      if (sibling.quantity < neededSiblings) continue;

      const gainedCurrentUnits = neededSiblings * ratio;
      const siblingPrevStock = sibling.quantity;
      const siblingNewStock = sibling.quantity - neededSiblings;

      await tx.estoque.update({ where: { id: sibling.id }, data: { quantity: siblingNewStock } });
      await tx.stockMovement.create({
        data: {
          estoqueId: sibling.id,
          type: 'CONVERSION',
          quantity: -neededSiblings,
          previousStock: siblingPrevStock,
          newStock: siblingNewStock,
          description: `Conversão automática p/ Venda #${saleId}: ${neededSiblings}x ${sibling.unit} → ${gainedCurrentUnits}x ${estoqueItem.unit} (${descricao})`,
          referenceId: saleId,
          referenceType: 'Sale'
        }
      });

      const stockAfterConversion = currentStock + gainedCurrentUnits;
      await tx.estoque.update({ where: { id: estoqueItem.id }, data: { quantity: stockAfterConversion } });
      await tx.stockMovement.create({
        data: {
          estoqueId: estoqueItem.id,
          type: 'CONVERSION',
          quantity: gainedCurrentUnits,
          previousStock: currentStock,
          newStock: stockAfterConversion,
          description: `Conversão automática de ${neededSiblings}x ${sibling.unit} → ${gainedCurrentUnits}x ${estoqueItem.unit} p/ Venda #${saleId}`,
          referenceId: saleId,
          referenceType: 'Sale'
        }
      });

      currentStock = stockAfterConversion;
      conversionDone = true;
      break;
    }

    if (!conversionDone) {
      throw new Error(`Estoque insuficiente para ${rotuloErro || `"${estoqueItem.name}"`} (${estoqueItem.unit}). Disponível: ${estoqueItem.quantity}, Necessário: ${needed}.`);
    }
  }

  const newStock = currentStock - needed;
  await tx.estoque.update({ where: { id: estoqueItem.id }, data: { quantity: newStock } });
  await tx.stockMovement.create({
    data: {
      estoqueId: estoqueItem.id,
      type: 'SALE',
      quantity: -needed,
      previousStock: currentStock,
      newStock: newStock,
      description: descricao,
      referenceId: saleId,
      referenceType: 'Sale'
    }
  });
}

// Rota para criar uma nova venda (PDV) com baixa de estoque
app.post('/api/sales', async (req, res) => {
  try {
    const { items, total, paymentMethod, customerName, amountReceived, change, date, discount, splitPayments: splitPay, pendente, vale, subtotal, finalTotal, origem, statusPedido, customerPhone, customerAddress, observacoes, saque } = req.body;

    // Saque junto da venda (dinheiro entregue ao cliente + taxa sobre o saque)
    const saqueValorNum = saque && parseFloat(saque.valor) > 0 ? parseFloat(saque.valor) : 0;
    const saqueTaxaNum = saqueValorNum > 0 ? (parseFloat(saque.taxa) || 0) : 0;
    const saqueFee = saqueValorNum > 0 ? saqueValorNum * (saqueTaxaNum / 100) : 0;

    // Se há saque, exige caixa aberto para registrar a saída do dinheiro
    if (saqueValorNum > 0) {
      const caixaSaque = await prisma.pdvCaixaControle.findFirst({ where: { status: "ABERTO" } });
      if (!caixaSaque) {
        return res.status(400).json({ error: "Nenhum caixa aberto. Abra o caixa antes de realizar um saque na venda." });
      }
    }


    // Identificar operador pelo token JWT
    let operatorName = null;
    try {
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith("Bearer ")) {
        const token = authHeader.split(" ")[1];
        const decoded = jwt.verify(token, SECRET_KEY);
        const user = await prisma.user.findUnique({ where: { id: decoded.userId }, select: { name: true, username: true } });
        if (user) operatorName = user.name || user.username;
      }
    } catch {}

    // Verificar estoque antes de prosseguir (verificação inicial rápida, considera conversão automática)
    const allEqsCheck = await prisma.unitEquivalence.findMany();
    const eqMapCheck = {};
    allEqsCheck.forEach(e => { eqMapCheck[e.unitName] = e; }); // mapa com objeto completo

    for (const item of items) {
      const estoqueItem = await prisma.estoque.findUnique({ where: { id: item.id } });
      if (!estoqueItem) {
        return res.status(400).json({ error: `Produto "${item.name}" não encontrado no estoque.` });
      }
      // Itens com contabiliza=false não precisam de verificação de estoque
      if (estoqueItem.contabiliza === false) continue;
      // Combos não têm estoque próprio: a disponibilidade vem dos componentes,
      // validados na baixa da composição dentro da transação.
      if (estoqueItem.isCombo) continue;
      if (estoqueItem.quantity < item.quantity) {
        // Verificar se há conversão automática possível a partir de unidade irmã
        const deficit = item.quantity - estoqueItem.quantity;
        const siblings = await prisma.estoque.findMany({
          where: { productId: estoqueItem.productId, id: { not: estoqueItem.id } },
          orderBy: { id: 'asc' }
        });
        const canConvert = !estoqueItem.controlaMontante && irmaosConversiveis(estoqueItem, siblings, eqMapCheck).some(
          ({ sibling, ratio }) => sibling.quantity >= Math.ceil(deficit / ratio)
        );
        if (!canConvert) {
          const lastMovement = await prisma.stockMovement.findFirst({
            where: { estoqueId: item.id, type: 'SALE' },
            orderBy: { createdAt: 'desc' }
          });
          const saleRef = lastMovement?.referenceId ? ` Último desconto registrado na Venda #${lastMovement.referenceId}.` : '';
          return res.status(400).json({
            error: `Estoque insuficiente para "${item.name}" (${estoqueItem.unit}). Disponível: ${estoqueItem.quantity}, Solicitado: ${item.quantity}.${saleRef}`
          });
        }
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

    const saleTotal = parseFloat(finalTotal || total) + saqueFee;

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
          operator: operatorName,
          origem: origem === 'ONLINE' ? 'ONLINE' : 'PDV',
          statusPedido: origem === 'ONLINE' ? (statusPedido || 'pending') : null,
          customerPhone: customerPhone || null,
          customerAddress: customerAddress || null,
          observacoes: observacoes || null,
          saqueValor: saqueValorNum,
          saqueTaxa: saqueTaxaNum,
          items: {
            create: items.map(item => ({
              estoqueId: item.id,
              productName: item.name,
              quantity: item.quantity,
              unitPrice: item.price,
              total: item.price * item.quantity,
              unit: item.unit || null,
              ...(item.composicao ? { composicao: item.composicao } : {})
            }))
          }
        },
        include: {
          items: true
        }
      });

      // 2. Dar baixa no ESTOQUE e registrar movimentações (com conversão automática de unidades)
      const allEqs = await tx.unitEquivalence.findMany();
      const eqMap = {};
      allEqs.forEach(e => { eqMap[e.unitName] = e; }); // mapa com objeto completo

      for (const item of items) {
        // Re-verificar estoque dentro da transação (proteção contra race condition)
        let estoqueItem = await tx.estoque.findUnique({ where: { id: item.id } });
        let currentStock = estoqueItem.quantity;

        // Itens com contabiliza=false NÃO baixam estoque automaticamente (follow-up semanal)
        if (estoqueItem.contabiliza === false) {
          continue; // pular atualização de estoque para descartáveis
        }

        // Combos não baixam estoque próprio — só os componentes selecionados.
        if (estoqueItem.isCombo) continue;

        // Produto por montante: baixa em ML direto, sem conversão entre unidades.
        if (estoqueItem.controlaMontante) {
          const mov = await movimentarMontante(tx, estoqueItem, -item.quantity, `"${item.name}"`);
          await tx.stockMovement.create({
            data: {
              estoqueId: item.id,
              type: 'SALE',
              quantity: -item.quantity,
              previousStock: mov.previousStock,
              newStock: mov.newStock,
              description: `Venda #${sale.id} - ${item.name} (${item.quantity}x)`,
              referenceId: sale.id,
              referenceType: 'Sale'
            }
          });
          continue;
        }

        // Se estoque insuficiente, tentar conversão automática de unidade irmã
        if (currentStock < item.quantity) {
          const deficit = item.quantity - currentStock;

          // Buscar itens do mesmo produto com unidade diferente
          const siblings = await tx.estoque.findMany({
            where: { productId: estoqueItem.productId, id: { not: estoqueItem.id } },
            orderBy: { id: 'asc' }
          });

          let conversionDone = false;
          for (const { sibling, ratio } of irmaosConversiveis(estoqueItem, siblings, eqMap)) {
            const neededSiblings = Math.ceil(deficit / ratio);

            if (sibling.quantity < neededSiblings) continue; // irmã também sem estoque suficiente

            const gainedCurrentUnits = neededSiblings * ratio;
            const siblingPrevStock = sibling.quantity;
            const siblingNewStock = sibling.quantity - neededSiblings;

            // Baixar da unidade irmã (maior)
            await tx.estoque.update({
              where: { id: sibling.id },
              data: { quantity: siblingNewStock }
            });

            // Registrar movimentação de conversão na unidade irmã
            await tx.stockMovement.create({
              data: {
                estoqueId: sibling.id,
                type: 'CONVERSION',
                quantity: -neededSiblings,
                previousStock: siblingPrevStock,
                newStock: siblingNewStock,
                description: `Conversão automática p/ Venda #${sale.id}: ${neededSiblings}x ${sibling.unit} → ${gainedCurrentUnits}x ${estoqueItem.unit} (${item.name})`,
                referenceId: sale.id,
                referenceType: 'Sale'
              }
            });

            // Adicionar unidades convertidas ao estoque atual antes de baixar a venda
            const stockAfterConversion = currentStock + gainedCurrentUnits;
            await tx.estoque.update({
              where: { id: item.id },
              data: { quantity: stockAfterConversion }
            });

            // Registrar movimentação de entrada pela conversão
            await tx.stockMovement.create({
              data: {
                estoqueId: item.id,
                type: 'CONVERSION',
                quantity: gainedCurrentUnits,
                previousStock: currentStock,
                newStock: stockAfterConversion,
                description: `Conversão automática de ${neededSiblings}x ${sibling.unit} → ${gainedCurrentUnits}x ${estoqueItem.unit} p/ Venda #${sale.id}`,
                referenceId: sale.id,
                referenceType: 'Sale'
              }
            });

            currentStock = stockAfterConversion;
            conversionDone = true;
            break;
          }

          if (!conversionDone) {
            const lastMovement = await tx.stockMovement.findFirst({
              where: { estoqueId: item.id, type: 'SALE' },
              orderBy: { createdAt: 'desc' }
            });
            const saleRef = lastMovement?.referenceId ? ` Último desconto registrado na Venda #${lastMovement.referenceId}.` : '';
            throw new Error(`Estoque insuficiente para "${item.name}" (${estoqueItem.unit}). Disponível: ${estoqueItem.quantity}, Solicitado: ${item.quantity}.${saleRef}`);
          }
        }

        const newStock = currentStock - item.quantity;

        // Baixar do estoque (após eventual conversão)
        await tx.estoque.update({
          where: { id: item.id },
          data: { quantity: newStock }
        });

        // Registrar movimentação de venda
        await tx.stockMovement.create({
          data: {
            estoqueId: item.id,
            type: 'SALE',
            quantity: -item.quantity,
            previousStock: currentStock,
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
        const escolhas = parseSelecoesComposicao(item.composicao);
        if (escolhas.length === 0) continue;
        const opcoes = await tx.composicaoOpcao.findMany({
          where: { id: { in: escolhas.map((e) => e.opcaoId) }, estoqueId: { not: null } }
        });
        for (const opcao of opcoes) {
          const escolhida = escolhas.find((e) => e.opcaoId === opcao.id);
          // Quantidade escolhida pelo cliente para este componente x itens vendidos
          const needed = item.quantity * (escolhida?.qtd || 1);
          // Aplica conversão automática de unidade irmã (ex.: baixa 1 Dose convertendo 1 Garrafa)
          await baixarEstoqueComConversao(
            tx,
            opcao.estoqueId,
            needed,
            eqMap,
            sale.id,
            `Venda #${sale.id} - Componente "${opcao.nome}" p/ ${item.name} (${needed}x)`,
            `o componente "${opcao.nome}"`
          );
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
    }, { timeout: 30000, maxWait: 30000 });

    // 5. Registrar entrada no caixa aberto (fora da transação para evitar isolamento)
    try {
      const caixaAberto = await prisma.pdvCaixaControle.findFirst({ where: { status: "ABERTO" } });
      if (caixaAberto) {
        // Não registrar vendas 100% pendentes (fiado) nem em Vale como entrada imediata no caixa.
        // Vale não entra no caixa: é descontado do pagamento do funcionário no fim da semana (Gastos Bar).
        const isPendenteTotal = !splitPay && paymentMethod?.toLowerCase().includes("pendente");
        const isValeTotal = !splitPay && ((vale && vale.password) || paymentMethod?.toLowerCase().includes("vale"));
        let valorEntrada = splitPay
          ? splitPay
              .filter(s => s.forma !== "pendente" && (s.forma || "").toLowerCase() !== "vale")
              .reduce((acc, s) => acc + (parseFloat(s.valor) || 0), 0)
          : (isPendenteTotal || isValeTotal) ? 0 : saleTotal;

        // Com saque: o cliente também paga o valor sacado na máquina, então a entrada
        // reflete o total cobrado (produtos + taxa + saque). A saída do dinheiro é lançada abaixo.
        if (saqueValorNum > 0 && !splitPay && !isPendenteTotal && !isValeTotal) {
          valorEntrada += saqueValorNum;
        }

        if (valorEntrada > 0) {
          const descricaoEntrada = `Venda #${result.id} — ${customerName || "Cliente não identificado"}` +
            (splitPay ? ` (${splitPay.map(s => `${s.forma}: R$${parseFloat(s.valor).toFixed(2)}`).join(", ")})` : ` — ${paymentMethod}`) +
            (saqueValorNum > 0 ? ` (inclui saque R$${saqueValorNum.toFixed(2)})` : "");

          await prisma.pdvCaixaTransacao.create({
            data: {
              caixaId: caixaAberto.id,
              tipo: "ENTRADA",
              categoria: "VENDA",
              valor: valorEntrada,
              descricao: descricaoEntrada,
              userId: null,
              userName: operatorName || null,
            },
          });
        }

        // Saída do dinheiro entregue ao cliente (saque junto da venda)
        if (saqueValorNum > 0) {
          await prisma.pdvCaixaTransacao.create({
            data: {
              caixaId: caixaAberto.id,
              tipo: "SAIDA",
              categoria: "SAQUE",
              valor: saqueValorNum,
              descricao: `Saque na Venda #${result.id} — R$${saqueValorNum.toFixed(2)} (taxa ${saqueTaxaNum}%, cobrado R$${(saqueValorNum + saqueFee).toFixed(2)})`,
              userId: null,
              userName: operatorName || null,
            },
          });
        }
      }
    } catch (caixaErr) {
      console.error("Erro ao registrar transação no caixa (não crítico):", caixaErr.message);
    }

    // 5b. Registrar lançamentos no Gastos Bar (venda em Vale => PRODUTO; desconto dado => DESCONTO).
    // Atribuído ao operador logado no PDV. Funciona para web, mobile e NET de forma centralizada.
    try {
      const funcionarioGB = operatorName || "Operador";
      const gastoBarCreates = [];

      // Vale: registra os itens consumidos (proporcional ao valor pago em vale)
      const valorVale = splitPay
        ? parseFloat((splitPay.find(s => (s.forma || "").toLowerCase() === "vale") || {}).valor || 0)
        : (((vale && vale.password) || paymentMethod?.toLowerCase().includes("vale")) ? parseFloat(finalTotal || total) || 0 : 0);

      if (valorVale > 0 && Array.isArray(items) && items.length > 0) {
        const totalItens = items.reduce((s, it) => s + ((parseFloat(it.price) || 0) * (parseFloat(it.quantity) || 0)), 0);
        if (totalItens > 0) {
          const proporcao = Math.min(valorVale / totalItens, 1);
          const valeParcial = proporcao < 0.999;
          for (const it of items) {
            const qtd = parseFloat(it.quantity) || 0;
            const valorBase = (parseFloat(it.price) || 0) * qtd;
            const valorTotalItem = parseFloat((valorBase * proporcao).toFixed(2));
            if (!qtd || !valorTotalItem) continue;
            gastoBarCreates.push(prisma.pdvGastoBar.create({
              data: {
                tipo: "PRODUTO",
                funcionario: funcionarioGB,
                descricao: valeParcial ? `${it.name} (Vale parcial)` : it.name,
                quantidade: qtd,
                valorUnitario: parseFloat((valorTotalItem / qtd).toFixed(2)),
                valorTotal: valorTotalItem,
                saleId: result.id,
              },
            }));
          }
        }
      }

      // Desconto concedido pelo operador na venda
      const valorDesconto = discount && parseFloat(discount.valor) > 0 ? parseFloat(discount.valor) : 0;
      if (valorDesconto > 0) {
        const nomesProdutos = items.map(it => `${it.quantity}x ${it.name}`).join(", ");
        gastoBarCreates.push(prisma.pdvGastoBar.create({
          data: {
            tipo: "DESCONTO",
            funcionario: funcionarioGB,
            descricao: `Desconto na Venda #${result.id} — ${nomesProdutos}`,
            valorTotal: valorDesconto,
            saleId: result.id,
          },
        }));
      }

      if (gastoBarCreates.length > 0) await Promise.all(gastoBarCreates);
    } catch (gbErr) {
      console.error("Erro ao registrar Gastos Bar (não crítico):", gbErr.message);
    }

    // 6. Verificar estoque mínimo e atualizar ListaCompras para itens que baixaram estoque
    try {
      for (const item of items) {
        const estoqueItem = await prisma.estoque.findUnique({ where: { id: item.id }, select: { quantity: true, contabiliza: true, isCombo: true } });
        if (estoqueItem && estoqueItem.contabiliza !== false && !estoqueItem.isCombo) {
          await criarListaComprasSeNecessario(item.id, estoqueItem.quantity);
        }
      }
    } catch (lcErr) {
      console.error("Erro ao verificar lista de compras (não crítico):", lcErr.message);
    }

    res.status(201).json(result);
  } catch (error) {
    console.error('Erro ao criar venda:', error);
    // Se for erro de negócio (estoque, comanda, etc), retornar mensagem legível
    const isBusinessError = error.message && (
      error.message.includes('Estoque insuficiente') ||
      error.message.includes('estoque') ||
      error.message.includes('Limite') ||
      error.message.includes('senha') ||
      error.message.includes('não encontrado')
    );
    if (isBusinessError) {
      return res.status(400).json({ error: error.message });
    }
    res.status(500).json({ error: 'Erro interno do servidor', details: error.message });
  }
});

// Rota para buscar vendas
app.get('/api/sales', async (req, res) => {
  try {
    const { dataInicio, dataFim } = req.query;
    const where = {};
    if (dataInicio || dataFim) {
      where.date = {};
      if (dataInicio) where.date.gte = new Date(dataInicio + 'T00:00:00');
      if (dataFim) {
        const fim = new Date(dataFim + 'T23:59:59');
        where.date.lte = fim;
      }
    }
    const sales = await prisma.sale.findMany({
      where,
      include: { items: true },
      orderBy: { date: 'desc' },
    });
    res.json(sales);
  } catch (error) {
    console.error('Erro ao buscar vendas:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// ===== PEDIDOS ONLINE (origem ONLINE, vindos do Start-Pira-Net) =====

// Status válidos e rótulos do fluxo de pedido online
const PEDIDO_STATUS_LABELS = {
  pending: 'Pendente',
  preparing: 'Em preparo',
  ready: 'Pronto para retirada',
  delivered: 'Entregue',
  cancelled: 'Cancelado'
};

// Normaliza telefone para o link wa.me (apenas dígitos, DDI 55 para BR)
const normalizarTelefonePedido = (telefone) => {
  if (!telefone) return null;
  let digitos = String(telefone).replace(/\D/g, '');
  if (!digitos) return null;
  if (digitos.length <= 11) digitos = `55${digitos}`;
  return digitos;
};

// Monta a mensagem de follow-up enviada ao cliente conforme a etapa
const montarMensagemPedido = (sale, status) => {
  const nome = sale.customerName || 'cliente';
  const pedido = `#${sale.id}`;
  const mensagens = {
    pending: `Olá, ${nome}! 😊 Recebemos o seu pedido ${pedido} e já estamos cuidando dele. Em breve avisamos as próximas etapas!`,
    preparing: `${nome}, seu pedido ${pedido} já está *em preparo*! 👩‍🍳 Logo logo fica pronto.`,
    ready: `Boa notícia, ${nome}! ✅ Seu pedido ${pedido} está *pronto para retirada*!`,
    delivered: `Pedido ${pedido} *entregue*! 🎉 Obrigado pela preferência, ${nome}. Bom apetite!`,
    cancelled: `${nome}, infelizmente seu pedido ${pedido} foi *cancelado*. Em caso de dúvidas, fale com a gente.`
  };
  return mensagens[status] || `Atualização do seu pedido ${pedido}: ${PEDIDO_STATUS_LABELS[status] || status}.`;
};

// Gera o link wa.me de follow-up para o cliente (ou null se não houver telefone)
const gerarLinkPedidoCliente = (sale, status) => {
  const telefone = normalizarTelefonePedido(sale.customerPhone);
  const mensagem = montarMensagemPedido(sale, status);
  if (!telefone) return { link: null, mensagem, hasPhone: false };
  return { link: `https://wa.me/${telefone}?text=${encodeURIComponent(mensagem)}`, mensagem, hasPhone: true };
};

// GET - Listar pedidos online (com filtro opcional por status)
app.get('/api/sales/online', async (req, res) => {
  try {
    const { status } = req.query;
    const where = { origem: 'ONLINE' };
    if (status && PEDIDO_STATUS_LABELS[status]) where.statusPedido = status;

    const pedidos = await prisma.sale.findMany({
      where,
      include: { items: true },
      orderBy: { date: 'desc' },
    });
    res.json(pedidos);
  } catch (error) {
    console.error('Erro ao buscar pedidos online:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// GET - Status (leve) de pedidos online por ids (ex: /api/sales/status?ids=1,2,3)
// Usado pela API pública (net) para sincronizar o andamento no histórico do cliente.
app.get('/api/sales/status', async (req, res) => {
  try {
    const idsParam = String(req.query.ids || '').trim();
    if (!idsParam) return res.json([]);

    const ids = idsParam
      .split(',')
      .map((v) => parseInt(v.trim(), 10))
      .filter((n) => Number.isInteger(n));
    if (ids.length === 0) return res.json([]);

    const pedidos = await prisma.sale.findMany({
      where: { id: { in: ids }, origem: 'ONLINE' },
      select: { id: true, statusPedido: true },
    });
    res.json(pedidos);
  } catch (error) {
    console.error('Erro ao buscar status de pedidos:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// PUT - Atualizar status de um pedido online (retorna link wa.me para o cliente)
app.put('/api/sales/:id/status', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'ID inválido' });

    const { status } = req.body;
    if (!status || !PEDIDO_STATUS_LABELS[status]) {
      return res.status(400).json({ error: 'Status inválido', validStatuses: Object.keys(PEDIDO_STATUS_LABELS) });
    }

    const existente = await prisma.sale.findUnique({ where: { id } });
    if (!existente) return res.status(404).json({ error: 'Pedido não encontrado' });
    if (existente.origem !== 'ONLINE') {
      return res.status(400).json({ error: 'Apenas pedidos online possuem status gerenciável' });
    }

    const pedido = await prisma.sale.update({
      where: { id },
      data: { statusPedido: status },
      include: { items: true },
    });

    const whatsapp = gerarLinkPedidoCliente(pedido, status);
    res.json({ ...pedido, whatsapp });
  } catch (error) {
    console.error('Erro ao atualizar status do pedido:', error);
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
      let newStock = previousStock + parsedQty; // positivo = entrada, negativo = saída

      if (newStock < 0) {
        throw new Error(`Estoque não pode ficar negativo. Estoque atual: ${previousStock}`);
      }

      // Atualizar quantidade no estoque (itens por montante recalculam todas as unidades)
      if (estoqueItem.controlaMontante) {
        newStock = (await movimentarMontante(tx, estoqueItem, parsedQty)).newStock;
      } else {
        await tx.estoque.update({
          where: { id: parseInt(estoqueId) },
          data: { quantity: newStock }
        });
      }

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
    const { unitName, value, isFractional, fractionalValue } = req.body;
    const isPorcao = isFractional === true || isFractional === 'true';

    if (!unitName) {
      return res.status(400).json({ error: 'Nome da unidade é obrigatório' });
    }
    if (!isPorcao && (value === undefined || value === null || parseFloat(value) < 0)) {
      return res.status(400).json({ error: 'Valor é obrigatório para unidades empacotadas' });
    }
    if (isPorcao && (!fractionalValue || parseFloat(fractionalValue) <= 0)) {
      return res.status(400).json({ error: 'Informe um valor maior que zero para a equivalência (ex: 0.5 para meia unidade ou 9 para 1 Garrafa → 9 Doses)' });
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
        value: isPorcao ? 1 : parseFloat(value),
        isFractional: isPorcao,
        fractionalValue: isPorcao ? parseFloat(fractionalValue) : null
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
    const { value, isFractional, fractionalValue } = req.body;
    const isPorcao = isFractional === true || isFractional === 'true';

    if (!isPorcao && (value === undefined || value === null || parseFloat(value) < 0)) {
      return res.status(400).json({ error: 'Valor é obrigatório para unidades empacotadas' });
    }
    if (isPorcao && (!fractionalValue || parseFloat(fractionalValue) <= 0)) {
      return res.status(400).json({ error: 'Informe um valor maior que zero para a equivalência (ex: 0.5 para meia unidade ou 9 para 1 Garrafa → 9 Doses)' });
    }

    const equivalence = await prisma.unitEquivalence.update({
      where: { unitName },
      data: { 
        value: isPorcao ? 1 : parseFloat(value),
        isFractional: isPorcao,
        fractionalValue: isPorcao ? parseFloat(fractionalValue) : null
      }
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
    const { nome, valorExtra, disponivel, estoqueId, exclusivo, consomeQtd, base } = req.body;
    const updateData = {};
    if (nome !== undefined) updateData.nome = nome;
    if (valorExtra !== undefined) updateData.valorExtra = parseFloat(valorExtra) || 0;
    if (disponivel !== undefined) updateData.disponivel = disponivel !== false && disponivel !== 0;
    if (estoqueId !== undefined) updateData.estoqueId = estoqueId ? parseInt(estoqueId) : null;
    if (exclusivo !== undefined) updateData.exclusivo = !!exclusivo;
    if (base !== undefined) updateData.base = !!base;
    if (consomeQtd !== undefined) updateData.consomeQtd = Math.max(1, parseInt(consomeQtd) || 1);
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
    const { estoqueId, nome, descricao, obrigatorio, multiplo, minOpcoes, maxOpcoes, ordem, porcoesGratis, valorAdicional, permiteQuantidade, exigeTotalExato } = req.body;
    if (!estoqueId || !nome) return res.status(400).json({ error: 'estoqueId e nome são obrigatórios' });
    const comp = await prisma.composicaoProduto.create({
      data: {
        estoqueId: parseInt(estoqueId), nome, descricao: descricao || null,
        obrigatorio: obrigatorio !== false, multiplo: !!multiplo,
        minOpcoes: parseInt(minOpcoes) || 1, maxOpcoes: parseInt(maxOpcoes) || 1,
        porcoesGratis: parseInt(porcoesGratis) || 0, valorAdicional: parseFloat(valorAdicional) || 0,
        permiteQuantidade: !!permiteQuantidade, exigeTotalExato: !!exigeTotalExato,
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
    const { nome, descricao, obrigatorio, multiplo, minOpcoes, maxOpcoes, ordem, porcoesGratis, valorAdicional, permiteQuantidade, exigeTotalExato } = req.body;
    const data = { nome, descricao, obrigatorio: !!obrigatorio, multiplo: !!multiplo, minOpcoes: parseInt(minOpcoes) || 1, maxOpcoes: parseInt(maxOpcoes) || 1, porcoesGratis: parseInt(porcoesGratis) || 0, valorAdicional: parseFloat(valorAdicional) || 0, ordem: parseInt(ordem) || 0 };
    if (permiteQuantidade !== undefined) data.permiteQuantidade = !!permiteQuantidade;
    if (exigeTotalExato !== undefined) data.exigeTotalExato = !!exigeTotalExato;
    const comp = await prisma.composicaoProduto.update({
      where: { id: parseInt(req.params.id) },
      data,
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
    const { nome, valorExtra, disponivel, estoqueId, exclusivo, consomeQtd, base } = req.body;
    if (!nome) return res.status(400).json({ error: 'Nome da opção é obrigatório' });
    const opcao = await prisma.composicaoOpcao.create({
      data: {
        composicaoId: parseInt(req.params.id),
        nome,
        valorExtra: parseFloat(valorExtra) || 0,
        disponivel: disponivel !== false,
        exclusivo: !!exclusivo,
        base: !!base,
        consomeQtd: Math.max(1, parseInt(consomeQtd) || 1),
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

// Marca/desmarca um item de estoque como variação de venda (combo) e define o rótulo.
app.patch('/api/estoque_prod/:id/combo', async (req, res) => {
  try {
    const { isCombo, comboNome } = req.body;
    const data = {};
    if (isCombo !== undefined) data.isCombo = Boolean(isCombo);
    if (comboNome !== undefined) data.comboNome = comboNome || null;
    const item = await prisma.estoque.update({
      where: { id: parseInt(req.params.id) },
      data,
      include: {
        composicoes: { include: { opcoes: { include: { estoque: { select: { id: true, name: true, quantity: true, productId: true, unit: true, controlaMontante: true } } }, orderBy: { id: 'asc' } } }, orderBy: { ordem: 'asc' } }
      }
    });
    res.json(comEstoqueDeCombo(item));
  } catch (error) {
    res.status(500).json({ error: 'Erro ao configurar combo', details: error.message });
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

    // Registrar no sub-caixa aberto (se houver)
    const caixaAberto = await prisma.pdvCaixaControle.findFirst({ where: { status: "ABERTO" } });
    if (caixaAberto) {
      const descOrigens = (origens || []).filter(o => o.nome).map(o => `${o.nome} (R$ ${parseFloat(o.valor).toFixed(2)})`).join(", ");
      await prisma.pdvCaixaTransacao.create({
        data: {
          caixaId: caixaAberto.id,
          tipo: "ENTRADA",
          categoria: "ADD",
          valor: parseFloat(valor),
          descricao: [descOrigens, observacao].filter(Boolean).join(" | ") || "Adição de dinheiro ao caixa",
          userId,
          userName,
        },
      });
    }

    // Descontar de cada origem de saldo (BAG / MÁQUINA / CAIXA) quando informada
    const ORIGENS_VALIDAS = ["BAG", "MÁQUINA", "CAIXA"];
    for (const og of (origens || []).filter(o => ORIGENS_VALIDAS.includes(o.nome) && parseFloat(o.valor) > 0)) {
      try {
        const origemReg = await prisma.pdvOrigemSaldo.findUnique({ where: { nome: og.nome } });
        if (origemReg) {
          const saldoAntes = origemReg.saldo;
          const saldoDepois = saldoAntes - parseFloat(og.valor);
          await prisma.$transaction([
            prisma.pdvOrigemSaldo.update({ where: { nome: og.nome }, data: { saldo: saldoDepois } }),
            prisma.pdvOrigemSaldoMovimento.create({
              data: {
                origemId: origemReg.id, tipo: "SAIDA", valor: parseFloat(og.valor),
                saldoAntes, saldoDepois,
                descricao: `ADD - ${observacao || "Adição ao caixa"}`,
                userId, userName,
              },
            }),
          ]);
        }
      } catch (e) { console.error("Erro ao descontar origem (ADD):", e.message); }
    }

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
    let isFuncionario = false;
    try {
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith("Bearer ")) {
        const token = authHeader.split(" ")[1];
        const decoded = jwt.verify(token, SECRET_KEY);
        userId = decoded.userId;
        const user = await prisma.user.findUnique({ where: { id: userId } });
        userName = user?.name || user?.username || null;
        isAdmin = user?.acessos === true;
        isFuncionario = user?.funcionario === true;
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

    // Lançar em GASTOS BAR (tipo VALE) o vale em dinheiro pego no PDV, atribuído a quem
    // realizou a ação (admin ou funcionário). Para funcionário é deduzido no Ponto.
    let gastoBar = null;
    if (userName) {
      let funcionarioId = null;
      try {
        const emp = await prisma.employee.findFirst({ where: { name: userName } });
        funcionarioId = emp?.id || null;
      } catch (e) { /* nome pode não bater com um funcionário do Ponto */ }

      const descVale = [
        origensPreenchidas.length > 0 ? "Origem: " + origensPreenchidas.map((o) => o.nome).join(", ") : null,
        observacao || null,
      ].filter(Boolean).join(" | ") || "Vale em dinheiro";

      gastoBar = await prisma.pdvGastoBar.create({
        data: {
          tipo: "VALE",
          funcionario: userName,
          funcionarioId,
          descricao: descVale,
          valorTotal: parseFloat(valor),
        },
      });
    }

    // Registrar no sub-caixa aberto (se houver)
    const caixaAberto = await prisma.pdvCaixaControle.findFirst({ where: { status: "ABERTO" } });
    if (caixaAberto) {
      const descOrigens = origensPreenchidas.map(o => `${o.nome} (R$ ${parseFloat(o.valor).toFixed(2)})`).join(", ");
      await prisma.pdvCaixaTransacao.create({
        data: {
          caixaId: caixaAberto.id,
          tipo: "SAIDA",
          categoria: "VALE",
          valor: parseFloat(valor),
          descricao: [descOrigens, observacao].filter(Boolean).join(" | ") || "Vale / Sangria",
          userId,
          userName,
        },
      });
    }

    // Descontar de cada origem de saldo (BAG / MÁQUINA / CAIXA) quando informada
    const ORIGENS_VALIDAS_VALE = ["BAG", "MÁQUINA", "CAIXA"];
    for (const og of origensPreenchidas.filter(o => ORIGENS_VALIDAS_VALE.includes(o.nome))) {
      try {
        const origemReg = await prisma.pdvOrigemSaldo.findUnique({ where: { nome: og.nome } });
        if (origemReg) {
          const saldoAntes = origemReg.saldo;
          const saldoDepois = saldoAntes - parseFloat(og.valor);
          await prisma.$transaction([
            prisma.pdvOrigemSaldo.update({ where: { nome: og.nome }, data: { saldo: saldoDepois } }),
            prisma.pdvOrigemSaldoMovimento.create({
              data: {
                origemId: origemReg.id, tipo: "SAIDA", valor: parseFloat(og.valor),
                saldoAntes, saldoDepois,
                descricao: `VALE - ${observacao || "Vale / Sangria"}`,
                userId, userName,
              },
            }),
          ]);
        }
      } catch (e) { console.error("Erro ao descontar origem (VALE):", e.message); }
    }

    res.status(201).json({ movimento, despesaPessoal, gastoBar, isAdmin, isFuncionario });
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

// ===================== ROTAS DE SALDO POR ORIGEM (BAG / MÁQUINA / CAIXA) =====================

// Buscar saldos de todas as origens
app.get("/api/pdv-origem-saldo", async (req, res) => {
  try {
    const origens = await prisma.pdvOrigemSaldo.findMany({
      orderBy: { nome: "asc" },
    });

    // Sincronizar origem "CAIXA" com o saldo real do caixa aberto
    const caixaAberto = await prisma.pdvCaixaControle.findFirst({
      where: { status: "ABERTO" },
      include: { transacoes: true },
    });

    const result = origens.map(o => {
      if (o.nome === "CAIXA") {
        if (caixaAberto) {
          const entradas = caixaAberto.transacoes.filter(t => t.tipo === "ENTRADA").reduce((s, t) => s + t.valor, 0);
          const saidas = caixaAberto.transacoes.filter(t => t.tipo === "SAIDA").reduce((s, t) => s + t.valor, 0);
          // saldoInicial já está incluído como transação ABERTURA (ENTRADA), não somar duas vezes
          const saldoAtual = parseFloat((entradas - saidas).toFixed(2));
          return { ...o, saldo: saldoAtual };
        } else {
          return { ...o, saldo: 0 };
        }
      }
      return o;
    });

    res.json(result);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar saldos", details: error.message });
  }
});

// Inicializar as 3 origens padrão (idempotente)
app.post("/api/pdv-origem-saldo/init", async (req, res) => {
  try {
    const origensDefault = ["BAG", "MÁQUINA", "CAIXA"];
    const results = [];
    for (const nome of origensDefault) {
      const o = await prisma.pdvOrigemSaldo.upsert({
        where: { nome },
        update: {},
        create: { nome, saldo: 0 },
      });
      results.push(o);
    }
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: "Erro ao inicializar origens de saldo", details: error.message });
  }
});

// Ajustar saldo de uma origem (ENTRADA, SAIDA ou AJUSTE direto)
app.post("/api/pdv-origem-saldo/:nome/movimentar", async (req, res) => {
  try {
    const { nome } = req.params;
    const { tipo, valor, descricao } = req.body;

    if (!tipo || !["ENTRADA", "SAIDA", "AJUSTE"].includes(tipo)) {
      return res.status(400).json({ error: "Tipo inválido. Use ENTRADA, SAIDA ou AJUSTE." });
    }
    const valorNum = parseFloat(valor);
    if (isNaN(valorNum) || valorNum <= 0) {
      return res.status(400).json({ error: "Valor inválido." });
    }

    // Extrair operador do token
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

    const origem = await prisma.pdvOrigemSaldo.findUnique({ where: { nome } });
    if (!origem) {
      return res.status(404).json({ error: `Origem "${nome}" não encontrada.` });
    }

    const saldoAntes = origem.saldo;
    let saldoDepois;
    if (tipo === "ENTRADA") saldoDepois = saldoAntes + valorNum;
    else if (tipo === "SAIDA") saldoDepois = saldoAntes - valorNum;
    else saldoDepois = valorNum; // AJUSTE = define diretamente

    const result = await prisma.$transaction(async (tx) => {
      const origemAtualizada = await tx.pdvOrigemSaldo.update({
        where: { nome },
        data: { saldo: saldoDepois },
      });
      const mov = await tx.pdvOrigemSaldoMovimento.create({
        data: {
          origemId: origem.id,
          tipo,
          valor: valorNum,
          saldoAntes,
          saldoDepois,
          descricao: descricao || null,
          userId,
          userName,
        },
      });
      return { origem: origemAtualizada, movimento: mov };
    });

    res.json(result);
  } catch (error) {
    res.status(500).json({ error: "Erro ao movimentar origem", details: error.message });
  }
});

// Transferir valor entre duas origens
app.post("/api/pdv-origem-saldo/transferir", async (req, res) => {
  try {
    const { origem: nomeOrigem, destino: nomeDestino, valor, descricao } = req.body;

    if (!nomeOrigem || !nomeDestino || nomeOrigem === nomeDestino) {
      return res.status(400).json({ error: "Origem e destino devem ser diferentes e informados." });
    }
    const valorNum = parseFloat(valor);
    if (isNaN(valorNum) || valorNum <= 0) {
      return res.status(400).json({ error: "Valor inválido." });
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

    const [fromOrigem, toOrigem] = await Promise.all([
      prisma.pdvOrigemSaldo.findUnique({ where: { nome: nomeOrigem } }),
      prisma.pdvOrigemSaldo.findUnique({ where: { nome: nomeDestino } }),
    ]);
    if (!fromOrigem) return res.status(404).json({ error: `Origem "${nomeOrigem}" não encontrada.` });
    if (!toOrigem) return res.status(404).json({ error: `Destino "${nomeDestino}" não encontrado.` });
    if (fromOrigem.saldo < valorNum) {
      return res.status(400).json({ error: `Saldo insuficiente em "${nomeOrigem}". Disponível: R$ ${fromOrigem.saldo.toFixed(2)}.` });
    }

    const novoSaldoFrom = fromOrigem.saldo - valorNum;
    const novoSaldoTo = toOrigem.saldo + valorNum;
    const desc = descricao || `Transferência de ${nomeOrigem} → ${nomeDestino}`;

    const result = await prisma.$transaction(async (tx) => {
      const [from, to] = await Promise.all([
        tx.pdvOrigemSaldo.update({ where: { nome: nomeOrigem }, data: { saldo: novoSaldoFrom } }),
        tx.pdvOrigemSaldo.update({ where: { nome: nomeDestino }, data: { saldo: novoSaldoTo } }),
      ]);
      await Promise.all([
        tx.pdvOrigemSaldoMovimento.create({
          data: { origemId: fromOrigem.id, tipo: "SAIDA", valor: valorNum, saldoAntes: fromOrigem.saldo, saldoDepois: novoSaldoFrom, descricao: desc, userId, userName },
        }),
        tx.pdvOrigemSaldoMovimento.create({
          data: { origemId: toOrigem.id, tipo: "ENTRADA", valor: valorNum, saldoAntes: toOrigem.saldo, saldoDepois: novoSaldoTo, descricao: desc, userId, userName },
        }),
      ]);
      return { from, to };
    });

    res.json(result);
  } catch (error) {
    res.status(500).json({ error: "Erro ao transferir entre origens", details: error.message });
  }
});

// Histórico de movimentos de uma origem
app.get("/api/pdv-origem-saldo/:nome/historico", async (req, res) => {
  try {
    const { nome } = req.params;
    const { limit = 50 } = req.query;

    // Origem CAIXA: o histórico vem das transações do caixa aberto (mesma fonte do saldo),
    // pois vendas/saque/abertura são registradas em pdvCaixaTransacao (e não em pdvOrigemSaldoMovimento).
    if (nome === "CAIXA") {
      const caixaAberto = await prisma.pdvCaixaControle.findFirst({
        where: { status: "ABERTO" },
        include: { transacoes: { orderBy: { createdAt: "asc" } } },
      });
      if (!caixaAberto) {
        return res.json({ origem: { nome: "CAIXA", saldo: 0 }, movimentos: [] });
      }
      let saldo = 0;
      const movsAsc = caixaAberto.transacoes.map((t) => {
        saldo += t.tipo === "ENTRADA" ? t.valor : -t.valor;
        return {
          id: t.id,
          tipo: t.tipo,
          valor: t.valor,
          saldoDepois: parseFloat(saldo.toFixed(2)),
          descricao: t.descricao,
          createdAt: t.createdAt,
        };
      });
      const movimentos = movsAsc.reverse().slice(0, parseInt(limit));
      return res.json({ origem: { nome: "CAIXA", saldo: parseFloat(saldo.toFixed(2)) }, movimentos });
    }

    const origem = await prisma.pdvOrigemSaldo.findUnique({ where: { nome } });
    if (!origem) return res.status(404).json({ error: `Origem "${nome}" não encontrada.` });

    const movimentos = await prisma.pdvOrigemSaldoMovimento.findMany({
      where: { origemId: origem.id },
      orderBy: { createdAt: "desc" },
      take: parseInt(limit),
    });
    res.json({ origem, movimentos });
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar histórico", details: error.message });
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

    // Registrar no sub-caixa aberto (se houver)
    const caixaAberto = await prisma.pdvCaixaControle.findFirst({ where: { status: "ABERTO" } });
    if (caixaAberto) {
      const descOrigens = origensPreenchidas.map(o => `${o.nome} (R$ ${parseFloat(o.valor).toFixed(2)})`).join(", ");
      await prisma.pdvCaixaTransacao.create({
        data: {
          caixaId: caixaAberto.id,
          tipo: "SAIDA",
          categoria: "PREMIO",
          valor: parseFloat(valor),
          descricao: [descOrigens, observacao].filter(Boolean).join(" | ") || "Prêmio de máquina",
          userId,
          userName,
        },
      });
    }

    // Descontar de cada origem de saldo (BAG / MÁQUINA / CAIXA) quando informada
    const ORIGENS_VALIDAS_PREMIO = ["BAG", "MÁQUINA", "CAIXA"];
    for (const og of origensPreenchidas.filter(o => ORIGENS_VALIDAS_PREMIO.includes(o.nome))) {
      try {
        const origemReg = await prisma.pdvOrigemSaldo.findUnique({ where: { nome: og.nome } });
        if (origemReg) {
          const saldoAntes = origemReg.saldo;
          const saldoDepois = saldoAntes - parseFloat(og.valor);
          await prisma.$transaction([
            prisma.pdvOrigemSaldo.update({ where: { nome: og.nome }, data: { saldo: saldoDepois } }),
            prisma.pdvOrigemSaldoMovimento.create({
              data: {
                origemId: origemReg.id, tipo: "SAIDA", valor: parseFloat(og.valor),
                saldoAntes, saldoDepois,
                descricao: `PRÊMIO - ${observacao || "Prêmio de máquina"}`,
                userId, userName,
              },
            }),
          ]);
        }
      } catch (e) { console.error("Erro ao descontar origem (PRÊMIO):", e.message); }
    }

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
    const { ativo, pointEnabled, pointType } = req.body;
    const data = {};
    if (ativo !== undefined) data.ativo = ativo;
    if (pointEnabled !== undefined) data.pointEnabled = !!pointEnabled;
    if (pointType !== undefined) data.pointType = pointType || null; // "credit_card" | "debit_card" | "pix" | "voucher" | null
    const forma = await prisma.pdvFormaPagamento.update({
      where: { id: parseInt(req.params.id) },
      data,
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
            let novo = prev - item.quantity;
            if (estoqueItem.controlaMontante) {
              novo = (await movimentarMontante(tx, estoqueItem, -item.quantity)).newStock;
            } else {
              await tx.estoque.update({ where: { id: item.id }, data: { quantity: novo } });
            }
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
      // ADD é reforço do caixa (não é receita): calculado separadamente para o display
      const totalAdd = caixaAberto.transacoes.filter(t => t.categoria === "ADD").reduce((s, t) => s + t.valor, 0);
      // saldoInicial já está incluído como transação ABERTURA (ENTRADA), não somar duas vezes
      const saldoAtual = entradas - saidas;
      const horasAberto = (new Date() - new Date(caixaAberto.abertoEm)) / (1000 * 60 * 60);
      return res.json({ ...caixaAberto, saldoAtual, totalEntradas: entradas, totalSaidas: saidas, totalAdd, horasAberto });
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

// Saque (troco via máquina): registra SAIDA do valor em dinheiro no sub-caixa
// Taxa de saque — GET e PUT
app.get("/api/pdv-saque/config", async (req, res) => {
  try {
    const config = await prisma.pdvConfigVenda.findUnique({ where: { chave: "taxa_saque_percentual" } });
    const taxa = config ? parseFloat(config.valor) : 30;
    res.json({ taxa });
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar taxa de saque", details: error.message });
  }
});

app.put("/api/pdv-saque/config", async (req, res) => {
  try {
    const { taxa } = req.body;
    const taxaNum = parseFloat(taxa);
    if (isNaN(taxaNum) || taxaNum < 0 || taxaNum > 100) {
      return res.status(400).json({ error: "Taxa inválida. Informe um percentual entre 0 e 100." });
    }
    const config = await prisma.pdvConfigVenda.upsert({
      where: { chave: "taxa_saque_percentual" },
      update: { valor: String(taxaNum) },
      create: { chave: "taxa_saque_percentual", valor: String(taxaNum), descricao: "Taxa percentual cobrada na máquina para saques (%)" },
    });
    res.json({ taxa: parseFloat(config.valor) });
  } catch (error) {
    res.status(500).json({ error: "Erro ao salvar taxa de saque", details: error.message });
  }
});

app.post("/api/pdv-saque", async (req, res) => {
  try {
    const { valor, observacao, formaPagamento, formaPagamentoNome } = req.body;
    if (!valor || parseFloat(valor) <= 0) {
      return res.status(400).json({ error: "Valor inválido para saque." });
    }
    const valorNum = parseFloat(valor);

    // Extrair operador do token
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

    const caixaAberto = await prisma.pdvCaixaControle.findFirst({ where: { status: "ABERTO" } });
    if (!caixaAberto) {
      return res.status(400).json({ error: "Nenhum caixa aberto. Abra o caixa antes de realizar um saque." });
    }

    // Buscar taxa configurada (default 30%)
    const taxaConfig = await prisma.pdvConfigVenda.findUnique({ where: { chave: "taxa_saque_percentual" } });
    const taxaPerc = taxaConfig ? parseFloat(taxaConfig.valor) : 30;
    const multiplicador = 1 + taxaPerc / 100;
    const maquinaValor = (valorNum * multiplicador).toFixed(2);
    const formaLabel = (formaPagamentoNome || formaPagamento || "").toString().trim();
    const partes = [`Saque R$${valorNum.toFixed(2)} (máquina: R$${maquinaValor}, taxa ${taxaPerc}%)`];
    if (formaLabel) partes.push(`Pagamento: ${formaLabel}`);
    if (observacao) partes.push(observacao);
    const descricao = partes.join(" — ");

    const transacao = await prisma.pdvCaixaTransacao.create({
      data: {
        caixaId: caixaAberto.id,
        tipo: "SAIDA",
        categoria: "SAQUE",
        valor: valorNum,
        descricao,
        userId,
        userName,
      },
    });

    res.status(201).json({ transacao, maquinaValor: parseFloat(maquinaValor), taxa: taxaPerc });
  } catch (error) {
    res.status(500).json({ error: "Erro ao registrar saque", details: error.message });
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
    const { saldoInicial, observacao, origemBAG, origemMAQUINA } = req.body;

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

    // Inicializar saldos de BAG e MÁQUINA se fornecidos
    const initOrigem = async (nome, valor) => {
      const reg = await prisma.pdvOrigemSaldo.findUnique({ where: { nome } });
      if (!reg) return;
      const saldoAntes = reg.saldo;
      const saldoDepois = parseFloat(valor);
      await prisma.$transaction([
        prisma.pdvOrigemSaldo.update({ where: { nome }, data: { saldo: saldoDepois } }),
        prisma.pdvOrigemSaldoMovimento.create({
          data: {
            origemId: reg.id,
            tipo: "AJUSTE",
            valor: Math.abs(saldoDepois - saldoAntes),
            saldoAntes,
            saldoDepois,
            descricao: "Saldo inicial de abertura do caixa",
            userId,
            userName,
          },
        }),
      ]);
    };

    if (origemBAG !== undefined && origemBAG !== null && origemBAG !== "") {
      await initOrigem("BAG", origemBAG);
    }
    if (origemMAQUINA !== undefined && origemMAQUINA !== null && origemMAQUINA !== "") {
      await initOrigem("MÁQUINA", origemMAQUINA);
    }

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
    // saldoInicial já está incluído como transação ABERTURA (ENTRADA), não somar duas vezes
    const saldoFinal = entradas - saidas;
    const fechadoEm = new Date();

    // Helpers de integração com Caixa Principal
    const parseValorBRL = (valorStr) => {
      if (!valorStr) return 0;
      const normalizado = String(valorStr).replace(/\./g, "").replace(",", ".");
      const v = parseFloat(normalizado);
      return Number.isFinite(v) ? v : 0;
    };

    const extrairTotaisPorForma = (sale) => {
      const payment = (sale.paymentMethod || "").trim();
      const totalVenda = parseFloat(sale.total) || 0;

      let dinheiro = 0;
      let cartao = 0;

      // Split gravado em string: "Dinheiro (R$ 10,00) + PIX (R$ 20,00)"
      const regexSplit = /([^+]+?)\s*\(R\$\s*([0-9\.,]+)\)/gi;
      let match;
      let encontrouSplit = false;

      while ((match = regexSplit.exec(payment)) !== null) {
        encontrouSplit = true;
        const nomeForma = (match[1] || "").toLowerCase().trim();
        const valorForma = parseValorBRL(match[2]);
        if (nomeForma.includes("dinheiro")) dinheiro += valorForma;
        else cartao += valorForma; // regra: tudo que não é dinheiro conta como cartão
      }

      if (!encontrouSplit) {
        if (payment.toLowerCase().includes("dinheiro")) dinheiro += totalVenda;
        else cartao += totalVenda; // regra: tudo que não é dinheiro conta como cartão
      }

      return { dinheiro, cartao };
    };

    const formatDateYMD = (dateObj) => {
      const y = dateObj.getFullYear();
      const m = String(dateObj.getMonth() + 1).padStart(2, "0");
      const d = String(dateObj.getDate()).padStart(2, "0");
      return `${y}-${m}-${d}`;
    };

    const caixaFechado = await prisma.pdvCaixaControle.update({
      where: { id: caixaAberto.id },
      data: {
        status: "FECHADO",
        saldoFinal,
        totalEntradas: entradas,
        totalSaidas: saidas,
        fechadoPorId: userId,
        fechadoPorNome: userName,
        fechadoEm,
        observacao: observacao ? `${caixaAberto.observacao || ""} | Fechamento: ${observacao}`.trim() : caixaAberto.observacao,
      },
      include: { transacoes: true },
    });

    // ================= INTEGRAÇÃO SUB-CAIXA (PDV) -> CAIXA PRINCIPAL =================
    // Período operacional do caixa: abertura (dia N) até fechamento (dia N+1)
    const vendasPeriodo = await prisma.sale.findMany({
      where: {
        date: {
          gte: new Date(caixaAberto.abertoEm),
          lte: fechadoEm,
        },
      },
      select: {
        id: true,
        total: true,
        paymentMethod: true,
      },
    });

    const totais = vendasPeriodo.reduce(
      (acc, sale) => {
        const { dinheiro, cartao } = extrairTotaisPorForma(sale);
        acc.dinheiro += dinheiro;
        acc.cartao += cartao;
        return acc;
      },
      { dinheiro: 0, cartao: 0 }
    );

    const valorDinheiroDia = parseFloat(totais.dinheiro.toFixed(2));
    const valorCartaoDia = parseFloat(totais.cartao.toFixed(2));
    const saldoInicialPrincipal = parseFloat((valorDinheiroDia + valorCartaoDia).toFixed(2));

    // Data do caixa principal segue o dia operacional de ABERTURA do sub-caixa
    const dataOperacional = formatDateYMD(new Date(caixaAberto.abertoEm));

    const balanceExistente = await prisma.balance.findFirst({
      where: { date: dataOperacional },
      orderBy: { id: "desc" },
    });

    const payloadBalance = {
      date: dataOperacional,
      cartao: valorCartaoDia,
      dinheiro: valorDinheiroDia,
      balance: parseFloat(caixaAberto.saldoInicial.toFixed(2)), // saldo de abertura do sub-caixa
      cartaofimcaixa: valorCartaoDia,
      dinheirofimcaixa: valorDinheiroDia,
      balancefim: parseFloat((valorDinheiroDia + valorCartaoDia).toFixed(2)),
      lucro: 0,
    };

    if (balanceExistente) {
      await prisma.balance.update({
        where: { id: balanceExistente.id },
        data: payloadBalance,
      });
      // Vincular sub-caixa ao Balance existente
      await prisma.pdvCaixaControle.update({
        where: { id: caixaFechado.id },
        data: { balanceId: balanceExistente.id },
      });
    } else {
      const novoBalance = await prisma.balance.create({ data: payloadBalance });
      // Vincular sub-caixa ao novo Balance
      await prisma.pdvCaixaControle.update({
        where: { id: caixaFechado.id },
        data: { balanceId: novoBalance.id },
      });
    }

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
      if (!semanasMap[weekKey]) semanasMap[weekKey] = { semana: weekKey, produtos: [], descontos: [], vales: [], totalProdutos: 0, totalDescontos: 0, totalVales: 0, total: 0 };
      if (g.tipo === "PRODUTO") {
        semanasMap[weekKey].produtos.push(g);
        semanasMap[weekKey].totalProdutos += g.valorTotal;
      } else if (g.tipo === "VALE") {
        semanasMap[weekKey].vales.push(g);
        semanasMap[weekKey].totalVales += g.valorTotal;
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
      if (!porFunc[g.funcionario]) porFunc[g.funcionario] = { funcionario: g.funcionario, totalProdutos: 0, totalDescontos: 0, totalVales: 0, total: 0, itens: [] };
      porFunc[g.funcionario].itens.push(g);
      if (g.tipo === "PRODUTO") porFunc[g.funcionario].totalProdutos += g.valorTotal;
      else if (g.tipo === "VALE") porFunc[g.funcionario].totalVales += g.valorTotal;
      else porFunc[g.funcionario].totalDescontos += g.valorTotal;
      porFunc[g.funcionario].total += g.valorTotal;
    }

    res.json(Object.values(porFunc).sort((a, b) => b.total - a.total));
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar resumo", details: error.message });
  }
});

// Total de Gastos Bar de um funcionário em um período (usado p/ deduzir do total a pagar no Ponto)
app.get("/api/pdv-gastos-bar/funcionario/:nome", async (req, res) => {
  try {
    const nome = decodeURIComponent(req.params.nome).trim();
    const { startDate, endDate } = req.query;
    // Match case-insensitive: o nome do Employee pode diferir em caixa/espaços
    // do funcionario gravado no PdvGastoBar (vindo do userName do PDV).
    const where = { funcionario: { equals: nome, mode: "insensitive" } };
    if (startDate || endDate) {
      where.createdAt = {};
      if (startDate) where.createdAt.gte = new Date(startDate);
      if (endDate) where.createdAt.lte = new Date(endDate);
    }
    const gastos = await prisma.pdvGastoBar.findMany({ where, orderBy: { createdAt: "desc" } });
    const total = gastos.reduce((s, g) => s + (g.valorTotal || 0), 0);
    const totalProdutos = gastos.filter((g) => g.tipo === "PRODUTO").reduce((s, g) => s + (g.valorTotal || 0), 0);
    const totalVales = gastos.filter((g) => g.tipo === "VALE").reduce((s, g) => s + (g.valorTotal || 0), 0);
    const totalDescontos = gastos.filter((g) => g.tipo === "DESCONTO").reduce((s, g) => s + (g.valorTotal || 0), 0);
    res.json({ funcionario: nome, total, totalProdutos, totalVales, totalDescontos, itens: gastos });
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar gastos do funcionário", details: error.message });
  }
});

// ROTAS DE AUDITORIA
app.get("/api/auditoria", async (req, res) => {
  try {
    const { modulo, acao, userId, userName, dataInicio, dataFim, dispositivo, page = 1, limit = 50 } = req.query;
    const where = {};

    if (modulo) where.modulo = modulo;
    if (acao) where.acao = acao;
    if (userId) where.userId = parseInt(userId);
    if (userName) where.userName = { contains: userName, mode: "insensitive" };
    if (dispositivo) where.dispositivo = dispositivo;
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

// Retorna lista de dispositivos distintos para filtro
app.get("/api/auditoria/dispositivos", async (req, res) => {
  try {
    const dispositivos = await prisma.auditoria.findMany({
      select: { dispositivo: true },
      distinct: ["dispositivo"],
      where: { dispositivo: { not: null } },
      orderBy: { dispositivo: "asc" },
    });
    res.json(dispositivos.map((d) => d.dispositivo));
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar dispositivos", details: error.message });
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

/* =========================================================================
 * MERCADO PAGO POINT (pagamento presencial na maquininha)
 * Integração via API de Orders unificada.
 * Docs: https://www.mercadopago.com.br/developers/pt/docs/mp-point/overview
 * ========================================================================= */

const MP_BASE = "https://api.mercadopago.com";
const POINT_CONFIG_KEYS = ["point_terminal_id", "point_print_on_terminal", "point_default_installments"];

// Cria um cliente axios autenticado para o Mercado Pago.
function mpClient() {
  const token = process.env.MP_ACCESS_TOKEN;
  if (!token) {
    const err = new Error("MP_ACCESS_TOKEN não configurado no servidor. Defina a variável de ambiente com o Access Token da sua aplicação Mercado Pago.");
    err.statusCode = 503;
    throw err;
  }
  return axios.create({
    baseURL: MP_BASE,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    timeout: 20000,
  });
}

// Normaliza mensagens de erro vindas do Mercado Pago.
function mpErrorPayload(error) {
  const status = error.response?.status || error.statusCode || 500;
  const data = error.response?.data;
  let message = data?.message || data?.error || error.message || "Erro ao comunicar com o Mercado Pago.";
  // A Orders API detalha os erros em arrays (errors[] ou cause[]). Extrai algo legível.
  const parts = [];
  if (Array.isArray(data?.errors)) {
    data.errors.forEach((e) => {
      const det = Array.isArray(e.details) ? e.details.join(", ") : (e.details || "");
      parts.push([e.code, e.message, det].filter(Boolean).join(": "));
    });
  }
  if (Array.isArray(data?.cause)) {
    data.cause.forEach((c) => parts.push([c.code, c.description].filter(Boolean).join(": ")));
  }
  if (parts.length) message = `${message} — ${parts.join(" | ")}`;
  return { status, message, details: data || null };
}

// Lê a configuração da Point a partir de PdvConfigVenda (com fallback para env).
async function getPointConfig() {
  const rows = await prisma.pdvConfigVenda.findMany({ where: { chave: { in: POINT_CONFIG_KEYS } } });
  const map = {};
  rows.forEach((r) => { map[r.chave] = r.valor; });
  return {
    terminalId: map.point_terminal_id || process.env.MP_TERMINAL_ID || "",
    printOnTerminal: ["seller_ticket", "no_ticket"].includes(map.point_print_on_terminal) ? map.point_print_on_terminal : "no_ticket",
    defaultInstallments: parseInt(map.point_default_installments || "1", 10) || 1,
  };
}

// Converte o status do Mercado Pago em um status normalizado para o PDV.
function normalizePointStatus(mpStatus, action) {
  const s = (action || mpStatus || "").toString().toLowerCase().replace("order.", "");
  if (["processed", "accredited", "approved"].includes(s)) return "processed";
  if (["canceled", "cancelled"].includes(s)) return "canceled";
  if (s === "refunded") return "refunded";
  if (s === "failed" || s === "rejected") return "failed";
  if (s === "expired") return "expired";
  if (s === "action_required") return "action_required";
  return "pending"; // created, at_terminal, opened, etc.
}

// Gera uma referência externa válida (letras, números, - e _; máx. 64 chars).
function buildExternalReference() {
  const raw = `PDV-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
  return raw.replace(/[^A-Za-z0-9_-]/g, "").slice(0, 64);
}

// Define quando a pré-seleção da modalidade deve usar a Payment Intents API.
// A Orders API (type "point") NÃO permite pré-selecionar a modalidade; apenas a
// Payment Intents API (legada) aceita payment.type = credit_card|debit_card para
// abrir o terminal já na modalidade escolhida. Pix/Voucher não têm pré-seleção
// via essa API, então caem no fluxo "point" (cliente escolhe no terminal).
function usesPaymentIntent(paymentType) {
  return paymentType === "credit_card" || paymentType === "debit_card";
}

// Normaliza o "state" da Payment Intents API para o status usado no PDV.
function normalizePointIntentState(state) {
  const s = (state || "").toString().toUpperCase();
  if (s === "FINISHED") return "processed";
  if (s === "CANCELED" || s === "ABANDONED") return "canceled";
  if (s === "ERROR" || s === "REJECTED") return "failed";
  if (s === "EXPIRED") return "expired";
  // OPEN, ON_TERMINAL, PROCESSING, etc.
  return "pending";
}

// GET config atual da Point + estado das credenciais.
app.get("/api/point/config", async (req, res) => {
  try {
    const config = await getPointConfig();
    res.json({
      configured: !!process.env.MP_ACCESS_TOKEN && !!config.terminalId,
      tokenConfigured: !!process.env.MP_ACCESS_TOKEN,
      webhookConfigured: !!process.env.MP_WEBHOOK_SECRET,
      terminal_id: config.terminalId,
      print_on_terminal: config.printOnTerminal,
      default_installments: config.defaultInstallments,
    });
  } catch (error) {
    res.status(500).json({ error: "Erro ao carregar configuração da Point", details: error.message });
  }
});

// PUT atualiza config da Point.
app.put("/api/point/config", async (req, res) => {
  try {
    const terminalId = req.body.terminalId ?? req.body.terminal_id;
    const printOnTerminal = req.body.printOnTerminal ?? req.body.print_on_terminal;
    const defaultInstallments = req.body.defaultInstallments ?? req.body.default_installments;
    const updates = [];
    if (terminalId !== undefined) updates.push(["point_terminal_id", String(terminalId)]);
    if (printOnTerminal !== undefined) updates.push(["point_print_on_terminal", String(printOnTerminal)]);
    if (defaultInstallments !== undefined) updates.push(["point_default_installments", String(defaultInstallments)]);
    for (const [chave, valor] of updates) {
      await prisma.pdvConfigVenda.upsert({
        where: { chave },
        update: { valor },
        create: { chave, valor, descricao: "Configuração Mercado Pago Point" },
      });
    }
    const config = await getPointConfig();
    res.json({
      configured: !!process.env.MP_ACCESS_TOKEN && !!config.terminalId,
      tokenConfigured: !!process.env.MP_ACCESS_TOKEN,
      webhookConfigured: !!process.env.MP_WEBHOOK_SECRET,
      terminal_id: config.terminalId,
      print_on_terminal: config.printOnTerminal,
      default_installments: config.defaultInstallments,
    });
  } catch (error) {
    res.status(500).json({ error: "Erro ao salvar configuração da Point", details: error.message });
  }
});

// GET lista de terminals Point vinculados à conta.
app.get("/api/point/terminals", async (req, res) => {
  try {
    const { data } = await mpClient().get("/terminals/v1/list", { params: { limit: 50 } });
    res.json({ terminals: data?.data?.terminals || [] });
  } catch (error) {
    const { status, message, details } = mpErrorPayload(error);
    res.status(status).json({ error: message, details });
  }
});

// POST ativa/desativa o modo de operação (PDV) de um terminal.
app.post("/api/point/terminals/mode", async (req, res) => {
  try {
    const { terminalId, mode } = req.body;
    if (!terminalId) return res.status(400).json({ error: "terminalId é obrigatório." });
    const operating_mode = (mode || "PDV").toUpperCase() === "STANDALONE" ? "STANDALONE" : "PDV";
    const { data } = await mpClient().patch("/terminals/v1/setup", {
      terminals: [{ id: terminalId, operating_mode }],
    });
    res.json(data);
  } catch (error) {
    const { status, message, details } = mpErrorPayload(error);
    res.status(status).json({ error: message, details });
  }
});

// POST cria uma order de pagamento na maquininha.
app.post("/api/point/orders", async (req, res) => {
  const config = await getPointConfig();
  const { amount, paymentType, installments, description } = req.body;
  const terminalId = req.body.terminalId || config.terminalId;
  const printOnTerminal = req.body.printOnTerminal || config.printOnTerminal;
  const parsedAmount = Number(amount);

  if (!terminalId) return res.status(400).json({ error: "Nenhum terminal Point configurado. Selecione um terminal nas configurações do PDV." });
  if (!Number.isFinite(parsedAmount) || parsedAmount <= 0) return res.status(400).json({ error: "Valor inválido para o pagamento." });

  // Identifica o operador pelo token JWT (quando presente).
  let operatorName = req.body.operator || null;
  try {
    const authHeader = req.headers.authorization;
    if (!operatorName && authHeader?.startsWith("Bearer ")) {
      const decoded = jwt.verify(authHeader.split(" ")[1], SECRET_KEY);
      const user = await prisma.user.findUnique({ where: { id: decoded.userId }, select: { name: true, username: true } });
      if (user) operatorName = user.name || user.username;
    }
  } catch { /* token opcional */ }

  const externalReference = buildExternalReference();
  const parcelas = parseInt(installments, 10) > 0 ? parseInt(installments, 10) : config.defaultInstallments;

  // Registra a intenção localmente antes de enviar ao Mercado Pago.
  const pointOrder = await prisma.pointOrder.create({
    data: {
      externalReference,
      terminalId,
      amount: parsedAmount,
      paymentType: paymentType || null,
      installments: parcelas,
      description: description || "Venda PDV",
      status: "created",
      operator: operatorName,
    },
  });

  // Para pré-selecionar a modalidade (crédito/débito) usamos a Payment Intents
  // API (POST /point/integration-api/devices/{device_id}/payment-intents), que é
  // a ÚNICA que aceita payment.type e faz o terminal abrir já na modalidade
  // escolhida. A Orders API (type "point") não tem esse recurso.
  if (usesPaymentIntent(paymentType)) {
    const paymentBlock = { type: paymentType };
    if (paymentType === "credit_card") {
      paymentBlock.installments = parcelas;
      paymentBlock.installments_cost = "seller";
    }
    const intentBody = {
      amount: Math.round(parsedAmount * 100), // menor unidade da moeda (centavos)
      description: description || "Venda PDV",
      additional_info: {
        external_reference: externalReference,
        print_on_terminal: printOnTerminal === "seller_ticket",
      },
      payment: paymentBlock,
    };

    try {
      const { data } = await mpClient().post(
        `/point/integration-api/devices/${terminalId}/payment-intents`,
        intentBody
      );
      const updated = await prisma.pointOrder.update({
        where: { id: pointOrder.id },
        data: {
          mpOrderId: data.id, // guardamos o payment_intent_id em mpOrderId
          status: normalizePointIntentState(data.state),
          statusDetail: data.state || null,
          rawPayload: JSON.stringify(data).slice(0, 4000),
        },
      });
      return res.status(201).json({
        id: updated.id,
        mpOrderId: updated.mpOrderId,
        externalReference: updated.externalReference,
        terminalId: updated.terminalId,
        amount: updated.amount,
        status: updated.status,
      });
    } catch (error) {
      const { status, message, details } = mpErrorPayload(error);
      console.error("Erro ao criar payment intent Point no Mercado Pago:", status, JSON.stringify(details || message));
      await prisma.pointOrder.update({
        where: { id: pointOrder.id },
        data: { status: "failed", statusDetail: message, rawPayload: JSON.stringify(details || {}).slice(0, 4000) },
      });
      return res.status(status).json({ error: message, details });
    }
  }

  // Fluxo padrão (Orders API, type "point"): o cliente escolhe a modalidade no
  // terminal. Usado quando não há pré-seleção (ou para Pix/Voucher, que não têm
  // pré-seleção via Payment Intents API).
  const mpBody = {
    type: "point",
    external_reference: externalReference,
    transactions: { payments: [{ amount: parsedAmount.toFixed(2) }] },
    config: {
      point: {
        terminal_id: terminalId,
        print_on_terminal: printOnTerminal || "no_ticket",
      },
    },
    description: description || "Venda PDV",
  };

  // Dados de integração opcionais (parceiro/integrador).
  if (process.env.MP_INTEGRATOR_ID || process.env.MP_PLATFORM_ID) {
    mpBody.integration_data = {
      ...(process.env.MP_PLATFORM_ID ? { platform_id: process.env.MP_PLATFORM_ID } : {}),
      ...(process.env.MP_INTEGRATOR_ID ? { integrator_id: process.env.MP_INTEGRATOR_ID } : {}),
    };
  }

  try {
    const { data } = await mpClient().post("/v1/orders", mpBody, {
      headers: { "X-Idempotency-Key": crypto.randomUUID() },
    });
    const updated = await prisma.pointOrder.update({
      where: { id: pointOrder.id },
      data: {
        mpOrderId: data.id,
        status: normalizePointStatus(data.status),
        statusDetail: data.status_detail || null,
        rawPayload: JSON.stringify(data).slice(0, 4000),
      },
    });
    res.status(201).json({
      id: updated.id,
      mpOrderId: updated.mpOrderId,
      externalReference: updated.externalReference,
      terminalId: updated.terminalId,
      amount: updated.amount,
      status: updated.status,
    });
  } catch (error) {
    const { status, message, details } = mpErrorPayload(error);
    console.error("Erro ao criar order Point no Mercado Pago:", status, JSON.stringify(details || message));
    await prisma.pointOrder.update({
      where: { id: pointOrder.id },
      data: { status: "failed", statusDetail: message, rawPayload: JSON.stringify(details || {}).slice(0, 4000) },
    });
    res.status(status).json({ error: message, details });
  }
});

// GET consulta o status de uma order (busca no Mercado Pago e atualiza o registro local).
app.get("/api/point/orders/:id", async (req, res) => {
  try {
    const pointOrder = await prisma.pointOrder.findUnique({ where: { id: parseInt(req.params.id, 10) } });
    if (!pointOrder) return res.status(404).json({ error: "Order não encontrada." });

    // Sem mpOrderId (falha na criação) ou em estado final: devolve o que temos.
    if (!pointOrder.mpOrderId) {
      return res.json(serializePointOrder(pointOrder));
    }

    // Caminho Payment Intents API (modalidade pré-selecionada: crédito/débito).
    if (usesPaymentIntent(pointOrder.paymentType)) {
      try {
        const { data } = await mpClient().get(`/point/integration-api/payment-intents/${pointOrder.mpOrderId}`);
        const updated = await prisma.pointOrder.update({
          where: { id: pointOrder.id },
          data: {
            status: normalizePointIntentState(data.state),
            statusDetail: data.state || null,
            mpPaymentId: data.payment?.id ? String(data.payment.id) : pointOrder.mpPaymentId,
            rawPayload: JSON.stringify(data).slice(0, 4000),
          },
        });
        return res.json(serializePointOrder(updated));
      } catch (mpError) {
        return res.json(serializePointOrder(pointOrder));
      }
    }

    try {
      const { data } = await mpClient().get(`/v1/orders/${pointOrder.mpOrderId}`);
      const payment = data.transactions?.payments?.[0] || null;
      const updated = await prisma.pointOrder.update({
        where: { id: pointOrder.id },
        data: {
          status: normalizePointStatus(data.status),
          statusDetail: data.status_detail || payment?.status_detail || null,
          mpPaymentId: payment?.id || pointOrder.mpPaymentId,
          rawPayload: JSON.stringify(data).slice(0, 4000),
        },
      });
      return res.json(serializePointOrder(updated, data));
    } catch (mpError) {
      // Falha ao consultar o MP: retorna o status local conhecido.
      return res.json(serializePointOrder(pointOrder));
    }
  } catch (error) {
    res.status(500).json({ error: "Erro ao consultar order", details: error.message });
  }
});

function serializePointOrder(order, mpData) {
  return {
    id: order.id,
    mpOrderId: order.mpOrderId,
    externalReference: order.externalReference,
    terminalId: order.terminalId,
    amount: order.amount,
    status: order.status,
    statusDetail: order.statusDetail,
    mpPaymentId: order.mpPaymentId,
    saleId: order.saleId,
    payment: mpData?.transactions?.payments?.[0] || null,
  };
}

// POST cancela uma order em andamento.
app.post("/api/point/orders/:id/cancel", async (req, res) => {
  try {
    const pointOrder = await prisma.pointOrder.findUnique({ where: { id: parseInt(req.params.id, 10) } });
    if (!pointOrder) return res.status(404).json({ error: "Order não encontrada." });
    if (pointOrder.mpOrderId) {
      try {
        if (usesPaymentIntent(pointOrder.paymentType)) {
          // Payment Intents API: cancelamento via DELETE no device.
          await mpClient().delete(`/point/integration-api/devices/${pointOrder.terminalId}/payment-intents/${pointOrder.mpOrderId}`);
        } else {
          await mpClient().post(`/v1/orders/${pointOrder.mpOrderId}/cancel`);
        }
      } catch (mpError) {
        const { status, message, details } = mpErrorPayload(mpError);
        // Se já estiver processada/cancelada, o MP retorna erro; propaga informação.
        return res.status(status).json({ error: message, details });
      }
    }
    const updated = await prisma.pointOrder.update({
      where: { id: pointOrder.id },
      data: { status: "canceled", statusDetail: "canceled_by_operator" },
    });
    res.json(serializePointOrder(updated));
  } catch (error) {
    res.status(500).json({ error: "Erro ao cancelar order", details: error.message });
  }
});

// PATCH vincula a venda gerada no PDV à order da Point (conciliação).
app.patch("/api/point/orders/:id", async (req, res) => {
  try {
    const { saleId } = req.body;
    const updated = await prisma.pointOrder.update({
      where: { id: parseInt(req.params.id, 10) },
      data: { ...(saleId !== undefined ? { saleId: parseInt(saleId, 10) } : {}) },
    });
    res.json(serializePointOrder(updated));
  } catch (error) {
    res.status(500).json({ error: "Erro ao vincular venda à order", details: error.message });
  }
});

/* -------------------------------------------------------------------------
 * PIX ONLINE (QR na tela do PDV)
 * Diferente da maquininha: gera um pagamento Pix via /v1/payments e retorna o
 * QR Code (imagem base64 + copia e cola) para exibir na tela. O PDV faz polling
 * até o Mercado Pago aprovar. Reutiliza o model PointOrder (terminalId fixo
 * "PIX_ONLINE", paymentType "pix_online", mpPaymentId = id do pagamento MP).
 * ------------------------------------------------------------------------- */

// POST cria uma cobrança Pix online e retorna o QR para exibir na tela.
app.post("/api/point/pix", async (req, res) => {
  const { amount, description } = req.body;
  const parsedAmount = Number(amount);

  if (!process.env.MP_ACCESS_TOKEN) return res.status(503).json({ error: "MP_ACCESS_TOKEN não configurado no servidor." });
  if (!Number.isFinite(parsedAmount) || parsedAmount <= 0) return res.status(400).json({ error: "Valor inválido para o pagamento." });

  // Identifica o operador pelo token JWT (quando presente).
  let operatorName = req.body.operator || null;
  try {
    const authHeader = req.headers.authorization;
    if (!operatorName && authHeader?.startsWith("Bearer ")) {
      const decoded = jwt.verify(authHeader.split(" ")[1], SECRET_KEY);
      const user = await prisma.user.findUnique({ where: { id: decoded.userId }, select: { name: true, username: true } });
      if (user) operatorName = user.name || user.username;
    }
  } catch { /* token opcional */ }

  const externalReference = buildExternalReference();
  const descricao = description || "Venda PDV (Pix)";

  // Registra a intenção localmente antes de enviar ao Mercado Pago.
  const pointOrder = await prisma.pointOrder.create({
    data: {
      externalReference,
      terminalId: "PIX_ONLINE",
      amount: parsedAmount,
      paymentType: "pix_online",
      description: descricao,
      status: "created",
      operator: operatorName,
    },
  });

  const expiracaoMin = parseInt(process.env.PIX_EXPIRACAO_MINUTOS || "30", 10) || 30;
  const expiracao = new Date(Date.now() + expiracaoMin * 60 * 1000);
  const body = {
    transaction_amount: Number(parsedAmount.toFixed(2)),
    description: descricao,
    payment_method_id: "pix",
    external_reference: externalReference,
    date_of_expiration: expiracao.toISOString().replace("Z", "-00:00"),
    payer: {
      email: req.body.payerEmail || "cliente@startpira.com.br",
      first_name: "Cliente",
    },
  };
  if (process.env.MP_WEBHOOK_URL) body.notification_url = process.env.MP_WEBHOOK_URL;

  try {
    const { data } = await mpClient().post("/v1/payments", body, {
      headers: { "X-Idempotency-Key": crypto.randomUUID() },
    });
    const tx = data?.point_of_interaction?.transaction_data || {};
    await prisma.pointOrder.update({
      where: { id: pointOrder.id },
      data: {
        mpPaymentId: String(data.id),
        status: normalizePointStatus(data.status),
        statusDetail: data.status_detail || null,
        rawPayload: JSON.stringify({ id: data.id, status: data.status }).slice(0, 4000),
      },
    });
    res.status(201).json({
      id: pointOrder.id,
      status: normalizePointStatus(data.status),
      amount: parsedAmount,
      qrCode: tx.qr_code || null,            // Pix copia e cola
      qrCodeBase64: tx.qr_code_base64 || null, // imagem do QR (base64)
      ticketUrl: tx.ticket_url || null,
      expiresAt: data.date_of_expiration || null,
    });
  } catch (error) {
    const { status, message, details } = mpErrorPayload(error);
    console.error("Erro ao criar Pix online no Mercado Pago:", status, JSON.stringify(details || message));
    await prisma.pointOrder.update({
      where: { id: pointOrder.id },
      data: { status: "failed", statusDetail: message, rawPayload: JSON.stringify(details || {}).slice(0, 4000) },
    }).catch(() => {});
    res.status(status).json({ error: message, details });
  }
});

// GET consulta o status do Pix online (polling do PDV).
app.get("/api/point/pix/:id", async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: "ID inválido." });

  const pointOrder = await prisma.pointOrder.findUnique({ where: { id } });
  if (!pointOrder) return res.status(404).json({ error: "Pagamento não encontrado." });

  // Já aprovado anteriormente.
  if (pointOrder.status === "processed") return res.json({ id, status: "processed" });
  if (!pointOrder.mpPaymentId) return res.json({ id, status: pointOrder.status });

  try {
    const { data } = await mpClient().get(`/v1/payments/${pointOrder.mpPaymentId}`);
    const status = normalizePointStatus(data.status);
    if (status !== pointOrder.status) {
      await prisma.pointOrder.update({
        where: { id },
        data: { status, statusDetail: data.status_detail || null },
      }).catch(() => {});
    }
    res.json({ id, status, statusDetail: data.status_detail || null });
  } catch (error) {
    const { status, message, details } = mpErrorPayload(error);
    res.status(status).json({ error: message, details });
  }
});

// Valida a assinatura (x-signature) das notificações webhook do Mercado Pago.
function validatePointWebhookSignature(req) {
  const secret = process.env.MP_WEBHOOK_SECRET;
  if (!secret) return true; // sem secret configurado (ambiente de desenvolvimento) -> não bloqueia
  const xSignature = req.headers["x-signature"];
  const xRequestId = req.headers["x-request-id"];
  if (!xSignature) return false;

  const parts = {};
  xSignature.split(",").forEach((p) => {
    const [k, v] = p.split("=");
    if (k && v) parts[k.trim()] = v.trim();
  });
  const ts = parts.ts;
  const receivedHash = parts.v1;
  if (!ts || !receivedHash) return false;

  const dataId = (req.query["data.id"] || req.query.id || req.body?.data?.id || "").toString();
  let manifest = "";
  if (dataId) manifest += `id:${dataId};`;
  if (xRequestId) manifest += `request-id:${xRequestId};`;
  manifest += `ts:${ts};`;

  const expected = crypto.createHmac("sha256", secret).update(manifest).digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(receivedHash));
  } catch {
    return false;
  }
}

// POST recebe as notificações de order do Mercado Pago Point.
app.post("/api/point/webhook", async (req, res) => {
  // Responde rápido; sempre 200 para evitar reenvios, mesmo em casos não tratados.
  try {
    if (!validatePointWebhookSignature(req)) {
      return res.status(401).json({ error: "Assinatura inválida." });
    }

    const action = req.body?.action || null;
    const mpOrderId = req.body?.data?.id || req.query["data.id"] || null;
    if (mpOrderId) {
      const existing = await prisma.pointOrder.findUnique({ where: { mpOrderId: String(mpOrderId) } });
      if (existing) {
        let status = normalizePointStatus(req.body?.data?.status, action);
        let statusDetail = req.body?.data?.status_detail || action || null;
        let mpPaymentId = req.body?.data?.transactions?.payments?.[0]?.id || existing.mpPaymentId;

        // Em caso de aprovação, busca a order completa para registrar o pagamento.
        if (status === "processed" && process.env.MP_ACCESS_TOKEN) {
          try {
            const { data } = await mpClient().get(`/v1/orders/${mpOrderId}`);
            const payment = data.transactions?.payments?.[0];
            status = normalizePointStatus(data.status, action);
            statusDetail = data.status_detail || statusDetail;
            mpPaymentId = payment?.id || mpPaymentId;
          } catch { /* mantém dados do webhook */ }
        }

        await prisma.pointOrder.update({
          where: { id: existing.id },
          data: {
            status,
            statusDetail,
            mpPaymentId,
            rawPayload: JSON.stringify(req.body).slice(0, 4000),
          },
        });
      }
    }
    return res.status(200).json({ received: true });
  } catch (error) {
    console.error("[Point webhook] erro:", error.message);
    // Responde 200 para não gerar reenvios em loop; erro já foi logado.
    return res.status(200).json({ received: true });
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
