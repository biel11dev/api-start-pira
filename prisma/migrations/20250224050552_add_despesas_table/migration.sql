-- AlterTable
ALTER TABLE "Balance" ALTER COLUMN "updatedAt" DROP NOT NULL;

-- CreateTable
CREATE TABLE "Despesa" (
    "id" SERIAL NOT NULL,
    "nomeDespesa" TEXT NOT NULL,
    "valorDespesa" DOUBLE PRECISION NOT NULL,
    "descDespesa" TEXT,
    "date" TIMESTAMP(3) NOT NULL,
    "DespesaFixa" BOOLEAN NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3),

    CONSTRAINT "Despesa_pkey" PRIMARY KEY ("id")
);
