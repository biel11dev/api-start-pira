require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const app = express();
const port = process.env.PORT || 3000;

// 🔐 Manter a SECRET_KEY no código
const SECRET_KEY = process.env.SECRET_KEY || "2a51f0c6b96167b01f59b41aa2407066735cc39ee71ebd041d8ff59b75c60c15";

// Middlewares
app.use(helmet());
app.use(cors({ origin: ["https://start-pira-ftd.vercel.app"] }));
app.use(express.json());
app.use(morgan("dev"));

// Middleware para tratamento de erros assíncronos
const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Middleware de autenticação
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token não fornecido" });

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(401).json({ error: "Token inválido" });
  }
};

// Rotas de Autenticação
app.post(
  "/register",
  asyncHandler(async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await prisma.user.create({
      data: { username, password: hashedPassword },
    });
    res.json(newUser);
  })
);

app.post(
  "/login",
  asyncHandler(async (req, res) => {
    const { username, password } = req.body;
    const user = await prisma.user.findUnique({ where: { username } });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Usuário ou senha inválidos" });
    }

    const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: "1h" });
    res.json({ token });
  })
);

app.get("/protected", authenticate, (req, res) => {
  res.json({ message: "Acesso autorizado" });
});

// CRUD Genérico para Models
const createCRUDRoutes = (modelName) => {
  const model = prisma[modelName];

  app.get(
    `/${modelName}`,
    asyncHandler(async (req, res) => {
      res.json(await model.findMany());
    })
  );

  app.get(
    `/${modelName}/:id`,
    asyncHandler(async (req, res) => {
      const item = await model.findUnique({
        where: { id: Number(req.params.id) },
      });
      item ? res.json(item) : res.status(404).json({ error: `${modelName} não encontrado` });
    })
  );

  app.post(
    `/${modelName}`,
    asyncHandler(async (req, res) => {
      res.json(await model.create({ data: req.body }));
    })
  );

  app.put(
    `/${modelName}/:id`,
    asyncHandler(async (req, res) => {
      res.json(
        await model.update({
          where: { id: Number(req.params.id) },
          data: req.body,
        })
      );
    })
  );

  app.delete(
    `/${modelName}/:id`,
    asyncHandler(async (req, res) => {
      await model.delete({ where: { id: Number(req.params.id) } });
      res.json({ message: `${modelName} excluído com sucesso` });
    })
  );
};

// Criando rotas para cada tabela do banco de dados
const models = ["client", "machine", "purchase", "payment", "product", "balance"];
models.forEach(createCRUDRoutes);

// Rotas Específicas
app.get(
  "/daily-readings",
  asyncHandler(async (req, res) => {
    const { machineId, date } = req.query;
    res.json(
      await prisma.dailyReading.findMany({
        where: { machineId: Number(machineId), date: { contains: date } },
      })
    );
  })
);

app.post(
  "/daily-readings",
  asyncHandler(async (req, res) => {
    const { date, value, machineId } = req.body;
    res.json(
      await prisma.dailyReading.create({
        data: { date: date.split("T")[0], value, machineId },
      })
    );
  })
);

app.delete(
  "/daily-readings/:id",
  asyncHandler(async (req, res) => {
    await prisma.dailyReading.delete({ where: { id: Number(req.params.id) } });
    res.json({ message: "Leitura diária excluída com sucesso" });
  })
);

// Middleware Global de Tratamento de Erros
app.use((err, req, res, next) => {
  console.error("Erro:", err);
  res.status(500).json({ error: "Erro interno do servidor" });
});

// Iniciando Servidor
app.listen(port, () => {
  console.log(`🚀 Server rodando em: http://localhost:${port}`);
});
