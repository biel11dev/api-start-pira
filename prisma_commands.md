# Comandos Prisma para Migration

## 1. Gerar migration inicial (se ainda não foi feita)
npx prisma migrate dev --name init

## 2. Aplicar migrations pendentes
npx prisma migrate deploy

## 3. Gerar cliente Prisma
npx prisma generate

## 4. Visualizar o banco de dados (Prisma Studio)
npx prisma studio

## 5. Reset do banco (CUIDADO: apaga todos os dados)
npx prisma migrate reset

## 6. Validar schema
npx prisma validate

## 7. Formatar schema
npx prisma format

## 8. Ver status das migrations
npx prisma migrate status

## 9. Criar nova migration após alterações no schema
npx prisma migrate dev --name [nome_da_migration]

## 10. Aplicar seed (se houver)
npx prisma db seed

## Sequência recomendada para setup inicial:
# 1. npx prisma migrate dev --name init
# 2. npx prisma generate
# 3. npx prisma studio (para verificar)

## Para produção (Vercel/deploy):
# npx prisma migrate deploy && npx prisma generate
