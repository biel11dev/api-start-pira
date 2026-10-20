-- AlterTable
ALTER TABLE "Product" ADD COLUMN     "baseUnit" TEXT,
ADD COLUMN     "pdvHiddenUnits" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "unitPrices" JSONB,
ALTER COLUMN "quantity" DROP NOT NULL;

-- AlterTable
ALTER TABLE "Estoque" ADD COLUMN     "comboNome" TEXT,
ADD COLUMN     "contabiliza" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "controlaMontante" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "isCombo" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "montanteMl" DOUBLE PRECISION NOT NULL DEFAULT 0,
ADD COLUMN     "mostrarPdv" BOOLEAN NOT NULL DEFAULT true;

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "funcionario" BOOLEAN DEFAULT false,
ADD COLUMN     "loginAt" TIMESTAMP(3),
ADD COLUMN     "logoutAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "Employee" ADD COLUMN     "autoPonto" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE "Sale" ADD COLUMN     "customerAddress" TEXT,
ADD COLUMN     "customerPhone" TEXT,
ADD COLUMN     "observacoes" TEXT,
ADD COLUMN     "operator" TEXT,
ADD COLUMN     "origem" TEXT NOT NULL DEFAULT 'PDV',
ADD COLUMN     "saqueTaxa" DOUBLE PRECISION NOT NULL DEFAULT 0,
ADD COLUMN     "saqueValor" DOUBLE PRECISION NOT NULL DEFAULT 0,
ADD COLUMN     "statusPedido" TEXT DEFAULT 'pending';

-- AlterTable
ALTER TABLE "SaleItem" ADD COLUMN     "unit" TEXT;

-- AlterTable
ALTER TABLE "UnitEquivalence" ADD COLUMN     "fractionalValue" DOUBLE PRECISION,
ADD COLUMN     "isFractional" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE "Auditoria" ADD COLUMN     "dispositivo" TEXT,
ADD COLUMN     "userAgent" TEXT;

-- AlterTable
ALTER TABLE "PdvFormaPagamento" ADD COLUMN     "pointEnabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "pointType" TEXT;

-- AlterTable
ALTER TABLE "PdvCaixaControle" ADD COLUMN     "balanceId" INTEGER;

-- AlterTable
ALTER TABLE "ComposicaoProduto" ADD COLUMN     "exigeTotalExato" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "permiteQuantidade" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "porcoesGratis" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "valorAdicional" DOUBLE PRECISION NOT NULL DEFAULT 0;

-- AlterTable
ALTER TABLE "ComposicaoOpcao" ADD COLUMN     "base" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "consomeQtd" INTEGER NOT NULL DEFAULT 1,
ADD COLUMN     "exclusivo" BOOLEAN NOT NULL DEFAULT false;

-- CreateTable
CREATE TABLE "EstoqueMinimo" (
    "id" SERIAL NOT NULL,
    "estoqueId" INTEGER NOT NULL,
    "quantidadeMinima" DOUBLE PRECISION NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EstoqueMinimo_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ListaCompras" (
    "id" SERIAL NOT NULL,
    "estoqueId" INTEGER NOT NULL,
    "nomeProduto" TEXT NOT NULL,
    "quantidadeAtual" DOUBLE PRECISION NOT NULL,
    "quantidadeMinima" DOUBLE PRECISION NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDENTE',
    "concluidoEm" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ListaCompras_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FollowUp" (
    "id" SERIAL NOT NULL,
    "estoqueId" INTEGER NOT NULL,
    "semana" TEXT NOT NULL,
    "temEstoque" BOOLEAN,
    "quantidade" DOUBLE PRECISION,
    "observacao" TEXT,
    "respondidoEm" TIMESTAMP(3),
    "respondidoPor" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "FollowUp_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PdvOrigemSaldo" (
    "id" SERIAL NOT NULL,
    "nome" TEXT NOT NULL,
    "saldo" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PdvOrigemSaldo_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PdvOrigemSaldoMovimento" (
    "id" SERIAL NOT NULL,
    "origemId" INTEGER NOT NULL,
    "tipo" TEXT NOT NULL,
    "valor" DOUBLE PRECISION NOT NULL,
    "saldoAntes" DOUBLE PRECISION NOT NULL,
    "saldoDepois" DOUBLE PRECISION NOT NULL,
    "descricao" TEXT,
    "userId" INTEGER,
    "userName" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PdvOrigemSaldoMovimento_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PointOrder" (
    "id" SERIAL NOT NULL,
    "mpOrderId" TEXT,
    "externalReference" TEXT NOT NULL,
    "terminalId" TEXT NOT NULL,
    "amount" DOUBLE PRECISION NOT NULL,
    "paymentType" TEXT,
    "installments" INTEGER NOT NULL DEFAULT 1,
    "description" TEXT,
    "status" TEXT NOT NULL DEFAULT 'created',
    "statusDetail" TEXT,
    "mpPaymentId" TEXT,
    "saleId" INTEGER,
    "operator" TEXT,
    "rawPayload" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PointOrder_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "EstoqueMinimo_estoqueId_key" ON "EstoqueMinimo"("estoqueId");

-- CreateIndex
CREATE INDEX "ListaCompras_estoqueId_idx" ON "ListaCompras"("estoqueId");

-- CreateIndex
CREATE INDEX "ListaCompras_status_idx" ON "ListaCompras"("status");

-- CreateIndex
CREATE INDEX "FollowUp_estoqueId_idx" ON "FollowUp"("estoqueId");

-- CreateIndex
CREATE INDEX "FollowUp_semana_idx" ON "FollowUp"("semana");

-- CreateIndex
CREATE INDEX "FollowUp_temEstoque_idx" ON "FollowUp"("temEstoque");

-- CreateIndex
CREATE UNIQUE INDEX "FollowUp_estoqueId_semana_key" ON "FollowUp"("estoqueId", "semana");

-- CreateIndex
CREATE UNIQUE INDEX "PdvOrigemSaldo_nome_key" ON "PdvOrigemSaldo"("nome");

-- CreateIndex
CREATE INDEX "PdvOrigemSaldo_nome_idx" ON "PdvOrigemSaldo"("nome");

-- CreateIndex
CREATE INDEX "PdvOrigemSaldoMovimento_origemId_idx" ON "PdvOrigemSaldoMovimento"("origemId");

-- CreateIndex
CREATE INDEX "PdvOrigemSaldoMovimento_createdAt_idx" ON "PdvOrigemSaldoMovimento"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "PointOrder_mpOrderId_key" ON "PointOrder"("mpOrderId");

-- CreateIndex
CREATE UNIQUE INDEX "PointOrder_externalReference_key" ON "PointOrder"("externalReference");

-- CreateIndex
CREATE INDEX "PointOrder_status_idx" ON "PointOrder"("status");

-- CreateIndex
CREATE INDEX "PointOrder_mpOrderId_idx" ON "PointOrder"("mpOrderId");

-- CreateIndex
CREATE INDEX "PointOrder_createdAt_idx" ON "PointOrder"("createdAt");

-- CreateIndex
CREATE INDEX "Sale_origem_idx" ON "Sale"("origem");

-- CreateIndex
CREATE INDEX "Sale_statusPedido_idx" ON "Sale"("statusPedido");

-- CreateIndex
CREATE INDEX "Auditoria_dispositivo_idx" ON "Auditoria"("dispositivo");

-- CreateIndex
CREATE INDEX "PdvCaixaControle_balanceId_idx" ON "PdvCaixaControle"("balanceId");

-- AddForeignKey
ALTER TABLE "PdvCaixaControle" ADD CONSTRAINT "PdvCaixaControle_balanceId_fkey" FOREIGN KEY ("balanceId") REFERENCES "Balance"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EstoqueMinimo" ADD CONSTRAINT "EstoqueMinimo_estoqueId_fkey" FOREIGN KEY ("estoqueId") REFERENCES "Estoque"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ListaCompras" ADD CONSTRAINT "ListaCompras_estoqueId_fkey" FOREIGN KEY ("estoqueId") REFERENCES "Estoque"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FollowUp" ADD CONSTRAINT "FollowUp_estoqueId_fkey" FOREIGN KEY ("estoqueId") REFERENCES "Estoque"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PdvOrigemSaldoMovimento" ADD CONSTRAINT "PdvOrigemSaldoMovimento_origemId_fkey" FOREIGN KEY ("origemId") REFERENCES "PdvOrigemSaldo"("id") ON DELETE CASCADE ON UPDATE CASCADE;

