-- CreateTable
CREATE TABLE "Employee" (
    "id" SERIAL NOT NULL,
    "name" TEXT NOT NULL,
    "position" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Employee_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DailyPoint" (
    "id" SERIAL NOT NULL,
    "date" TIMESTAMP(3) NOT NULL,
    "entry" TIMESTAMP(3) NOT NULL,
    "exit" TIMESTAMP(3) NOT NULL,
    "gateOpen" TIMESTAMP(3),
    "employeeId" INTEGER NOT NULL,

    CONSTRAINT "DailyPoint_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "DailyPoint" ADD CONSTRAINT "DailyPoint_employeeId_fkey" FOREIGN KEY ("employeeId") REFERENCES "Employee"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
