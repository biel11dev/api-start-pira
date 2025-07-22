-- AlterTable
ALTER TABLE "User" ADD COLUMN     "pessoal" BOOLEAN;

-- CreateTable
CREATE TABLE "DespPessoal" (
    "id" SERIAL NOT NULL,
    "nomeDespesa" TEXT NOT NULL,
    "valorDespesa" DOUBLE PRECISION,
    "descDespesa" TEXT,
    "date" TIMESTAMP(3) NOT NULL,
    "DespesaFixa" BOOLEAN NOT NULL,
    "tipoMovimento" TEXT NOT NULL DEFAULT 'GASTO',
    "categoriaId" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3),

    CONSTRAINT "DespPessoal_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CatDespPessoal" (
    "id" SERIAL NOT NULL,
    "nomeCategoria" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CatDespPessoal_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "DespPessoal" ADD CONSTRAINT "DespPessoal_categoriaId_fkey" FOREIGN KEY ("categoriaId") REFERENCES "CatDespPessoal"("id") ON DELETE SET NULL ON UPDATE CASCADE;
