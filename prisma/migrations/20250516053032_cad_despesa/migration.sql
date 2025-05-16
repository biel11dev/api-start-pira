-- CreateTable
CREATE TABLE "CadDespesa" (
    "id" SERIAL NOT NULL,
    "nomeDespesa" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CadDespesa_pkey" PRIMARY KEY ("id")
);
