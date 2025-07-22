-- CreateTable
CREATE TABLE "UnitEquivalence" (
    "id" SERIAL NOT NULL,
    "unitName" TEXT NOT NULL,
    "value" DOUBLE PRECISION NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "UnitEquivalence_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "UnitEquivalence_unitName_key" ON "UnitEquivalence"("unitName");
