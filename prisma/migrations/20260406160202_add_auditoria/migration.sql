-- AlterTable
ALTER TABLE "User" ADD COLUMN     "auditoria" BOOLEAN;

-- CreateTable
CREATE TABLE "Auditoria" (
    "id" SERIAL NOT NULL,
    "modulo" TEXT NOT NULL,
    "acao" TEXT NOT NULL,
    "descricao" TEXT,
    "rota" TEXT NOT NULL,
    "userId" INTEGER,
    "userName" TEXT,
    "ip" TEXT,
    "payload" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Auditoria_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditoriaConfig" (
    "id" SERIAL NOT NULL,
    "modulo" TEXT NOT NULL,
    "ativo" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AuditoriaConfig_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Auditoria_modulo_idx" ON "Auditoria"("modulo");

-- CreateIndex
CREATE INDEX "Auditoria_userId_idx" ON "Auditoria"("userId");

-- CreateIndex
CREATE INDEX "Auditoria_createdAt_idx" ON "Auditoria"("createdAt");

-- CreateIndex
CREATE INDEX "Auditoria_acao_idx" ON "Auditoria"("acao");

-- CreateIndex
CREATE UNIQUE INDEX "AuditoriaConfig_modulo_key" ON "AuditoriaConfig"("modulo");
