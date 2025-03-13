/*
  Warnings:

  - Added the required column `valuecusto` to the `Product` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "Machine" ALTER COLUMN "updatedAt" DROP NOT NULL;

-- AlterTable
ALTER TABLE "Payment" ALTER COLUMN "updatedAt" DROP NOT NULL;

-- AlterTable
ALTER TABLE "Product" ADD COLUMN     "valuecusto" INTEGER NOT NULL,
ALTER COLUMN "updatedAt" DROP NOT NULL;
