-- AlterTable
ALTER TABLE "DailyPoint" ALTER COLUMN "date" DROP NOT NULL,
ALTER COLUMN "entry" DROP NOT NULL,
ALTER COLUMN "exit" DROP NOT NULL;

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "acessos" BOOLEAN,
ADD COLUMN     "caixa" BOOLEAN,
ADD COLUMN     "despesas" BOOLEAN,
ADD COLUMN     "fiado" BOOLEAN,
ADD COLUMN     "maquinas" BOOLEAN,
ADD COLUMN     "ponto" BOOLEAN,
ADD COLUMN     "produtos" BOOLEAN;
