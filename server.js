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
    console.log("Dados recebidos:", req.body); // Log dos dados recebidos
    res.status(400).json({ error: "Erro ao registrar usuário", details: error.message });
  }
});

app.get("/users", async (req, res) => {
  try {
    const users = await prisma.user.findMany();
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar usuários", details: error.message });
  }
});

app.post("/login", async (req, res) => {
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
    },
  });
});

app.put("/users/:id", async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { caixa, produtos, maquinas, fiado, despesas, ponto, acessos } = req.body;

    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: { caixa, produtos, maquinas, fiado, despesas, ponto, acessos },
    });

    res.json(updatedUser);
  } catch (error) {
    res.status(500).json({ error: "Erro ao atualizar permissões do usuário", details: error.message });
  }
});

// ROTAS DE CLIENTES
app.get("/clients", async (req, res) => res.json(await prisma.client.findMany()));

app.get("/clients/:id", async (req, res) => {
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

app.post("/clients", async (req, res) => res.json(await prisma.client.create({ data: req.body })));

app.put("/clients/:id", async (req, res) => {
  res.json(await prisma.client.update({ where: { id: parseInt(req.params.id) }, data: req.body }));
});

app.delete("/clients/:id", async (req, res) => {
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
app.get("/machines", async (req, res) => res.json(await prisma.machine.findMany()));

app.get("/machines/:id", async (req, res) => {
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

app.post("/machines", async (req, res) => res.json(await prisma.machine.create({ data: req.body })));

app.put("/machines/:id", async (req, res) => {
  res.json(await prisma.machine.update({ where: { id: parseInt(req.params.id) }, data: req.body }));
});

app.delete("/machines/:id", async (req, res) => {
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
app.get("/purchases", async (req, res) => res.json(await prisma.purchase.findMany()));

app.get("/purchases/:id", async (req, res) => {
  const purchase = await prisma.purchase.findUnique({
    where: { id: parseInt(req.params.id) },
  });
  res.json(purchase || { error: "Compra não encontrada" });
});

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

app.put("/purchases/:id", async (req, res) => {
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

app.delete("/purchases/:id", async (req, res) => {
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
app.get("/payments", async (req, res) => res.json(await prisma.payment.findMany()));

app.get("/payments/:id", async (req, res) => {
  const payment = await prisma.payment.findUnique({
    where: { id: parseInt(req.params.id) },
  });
  res.json(payment || { error: "Pagamento não encontrado" });
});

app.post("/payments", async (req, res) => res.json(await prisma.payment.create({ data: req.body })));

app.put("/payments/:id", async (req, res) => {
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

app.delete("/payments/:id", async (req, res) => {
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
app.get("/daily-readings", async (req, res) => {
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

app.get("/daily-readings/:id", async (req, res) => {
  const dailyReading = await prisma.dailyReading.findUnique({
    where: { id: parseInt(req.params.id) },
  });
  res.json(dailyReading || { error: "Leitura diária não encontrada" });
});

app.post("/daily-readings", async (req, res) => {
  const { date, value, machineId } = req.body;
  res.json(await prisma.dailyReading.create({ data: { date: date, value, machineId } }));
});

app.put("/daily-readings/:id", async (req, res) => {
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

app.delete("/daily-readings/:id", async (req, res) => {
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
app.get("/products", async (req, res) => res.json(await prisma.product.findMany()));

app.get("/products/:id", async (req, res) => {
  const product = await prisma.product.findUnique({
    where: { id: parseInt(req.params.id) },
  });
  res.json(product || { error: "Produto não encontrado" });
});

app.post("/products", async (req, res) => {
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

app.put("/products/:id", async (req, res) => {
  try {
    const { name, quantity, unit, value, valuecusto } = req.body;

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

    const parsedValueCusto = parseInt(valuecusto, 10);
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

app.get("/balances/:id", async (req, res) => {
  const balance = await prisma.balance.findUnique({
    where: { id: parseInt(req.params.id) },
  });
  res.json(balance || { error: "Saldo não encontrado" });
});

app.post("/balances", async (req, res) => {
  const { date, balance, cartao, dinheiro } = req.body;
  res.json(await prisma.balance.create({ data: { date, balance, cartao, dinheiro } }));
});

app.put("/balances/:id", async (req, res) => {
  res.json(await prisma.balance.update({ where: { id: parseInt(req.params.id) }, data: req.body }));
});

app.delete("/balances/:id", async (req, res) => {
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
app.get("/despesas", async (req, res) => {
  try {
    const despesas = await prisma.despesa.findMany();
    res.json(despesas);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar despesas", details: error.message });
  }
});

app.get("/despesas/:id", async (req, res) => {
  try {
    const despesa = await prisma.despesa.findUnique({
      where: { id: parseInt(req.params.id) },
    });
    res.json(despesa || { error: "Despesa não encontrada" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar despesa", details: error.message });
  }
});

app.post("/despesas", async (req, res) => {
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

app.put("/despesas/:id", async (req, res) => {
  try {
    const { valorDespesa, descDespesa } = req.body;
    const updatedDespesa = await prisma.despesa.update({
      where: { id: parseInt(req.params.id) },
      data: { valorDespesa, descDespesa },
    });
    res.json(updatedDespesa);
  } catch (error) {
    res.status(500).json({ error: "Erro ao atualizar despesa", details: error.message });
  }
});

app.delete("/despesas/:id", async (req, res) => {
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
app.get("/employees", async (req, res) => {
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

app.get("/employees/:id", async (req, res) => {
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

app.post("/employees", async (req, res) => {
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

app.put("/employees/:id", async (req, res) => {
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

app.delete("/employees/:id", async (req, res) => {
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
app.get("/daily-points", async (req, res) => {
  try {
    const points = await prisma.dailyPoint.findMany({
      include: { employee: true }, // Inclui os dados do funcionário relacionado
    });
    res.json(points);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar pontos diários", details: error.message });
  }
});

app.get("/daily-points/:id", async (req, res) => {
  try {
    const point = await prisma.dailyPoint.findUnique({
      where: { id: parseInt(req.params.id) },
      include: { employee: true }, // Inclui os dados do funcionário relacionado
    });
    if (!point) {
      return res.status(404).json({ error: "Ponto diário não encontrado" });
    }
    res.json(point);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar ponto diário", details: error.message });
  }
});

app.post("/daily-points", async (req, res) => {
  try {
    const { date, entry, exit, gateOpen, employeeId } = req.body;
    const newPoint = await prisma.dailyPoint.create({
      data: {
        date: new Date(date),
        entry: new Date(entry),
        exit: new Date(exit),
        gateOpen: gateOpen ? new Date(gateOpen) : null,
        employeeId,
      },
    });
    res.status(201).json(newPoint);
  } catch (error) {
    res.status(500).json({ error: "Erro ao criar ponto diário", details: error.message });
  }
});

app.put("/daily-points/:id", async (req, res) => {
  try {
    const employeeId = parseInt(req.params.id); // ID do funcionário
    const { entry, exit, gateOpen } = req.body; // Horários enviados no formato HH:mm

    // Obter a data atual no formato ISO (apenas a parte da data)
    const currentDate = new Date().toISOString().split("T")[0];

    // Função para combinar a data atual com o horário fornecido
    const combineDateAndTime = (date, time) => {
      if (!time) return null; // Retorna null se o horário não for fornecido
      return new Date(`${date}T${time}:00.000Z`);
    };

    // Combina a data atual com os horários fornecidos
    const entryDateTime = combineDateAndTime(currentDate, entry);
    const exitDateTime = combineDateAndTime(currentDate, exit);
    const gateOpenDateTime = combineDateAndTime(currentDate, gateOpen);

    // Verifica se já existe um registro para o employeeId e a data atual
    let existingPoint = await prisma.dailyPoint.findFirst({
      where: {
        employeeId: employeeId,
        date: {
          gte: new Date(`${currentDate}T00:00:00.000Z`), // Data atual no início do dia
          lt: new Date(`${currentDate}T23:59:59.999Z`), // Data atual no final do dia
        },
      },
    });

    if (!existingPoint) {
      // Cria um novo registro se não existir
      existingPoint = await prisma.dailyPoint.create({
        data: {
          date: new Date(currentDate), // Data atual
          entry: entryDateTime,
          exit: exitDateTime,
          gateOpen: gateOpenDateTime,
          employeeId,
        },
      });

      return res.status(201).json({
        message: "Registro criado para o dia atual.",
        point: existingPoint,
      });
    }

    // Atualiza o registro existente
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

app.delete("/daily-points", async (req, res) => {
  const { employeeId } = req.query;

  try {
    await prisma.dailyPoint.deleteMany({
      where: { employeeId: parseInt(employeeId) },
    });
    res.json({ message: "Registros de DailyPoints excluídos com sucesso." });
  } catch (error) {
    console.error("Erro ao excluir registros de DailyPoints:", error);
    res.status(500).json({ error: "Erro ao excluir registros de DailyPoints", details: error.message });
  }
});

// MIDDLEWARE GLOBAL DE ERRO
app.use((err, req, res, next) => {
  console.error("Erro:", err);
  res.status(500).json({ error: "Erro interno do servidor", details: err.message });
});

app.listen(port, () => {
  console.log(`Server tá on krai --> http://localhost:${port}`);
});
