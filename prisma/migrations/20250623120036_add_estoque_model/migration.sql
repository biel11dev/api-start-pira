-- CreateTable
CREATE TABLE "Estoque" (
    "id" SERIAL NOT NULL,
    "name" TEXT NOT NULL,
    "quantity" INTEGER NOT NULL,
    "unit" TEXT NOT NULL,
    "categoria_Id" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3),
    "value" DOUBLE PRECISION NOT NULL,
    "valuecusto" DOUBLE PRECISION NOT NULL,

    CONSTRAINT "Estoque_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "Estoque" ADD CONSTRAINT "Estoque_categoria_Id_fkey" FOREIGN KEY ("categoria_Id") REFERENCES "Category"("id") ON DELETE SET NULL ON UPDATE CASCADE;
