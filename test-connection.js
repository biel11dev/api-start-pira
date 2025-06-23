require("dotenv").config();
const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();

async function testConnection() {
  try {
    console.log("DATABASE_URL:", process.env.DATABASE_URL);
    console.log("Tentando conectar ao banco...");
    
    await prisma.$connect();
    console.log("✅ Conexão bem-sucedida!");
    
    const result = await prisma.$queryRaw`SELECT 1 as test`;
    console.log("✅ Query de teste executada:", result);
    
  } catch (error) {
    console.error("❌ Erro de conexão:", error.message);
    console.error("Detalhes:", error);
  } finally {
    await prisma.$disconnect();
  }
}

testConnection();
