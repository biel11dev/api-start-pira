# Setup do Banco de Dados - API Start Pira

## Pré-requisitos
- Node.js instalado
- PostgreSQL configurado
- Arquivo `.env` com `DATABASE_URL` configurada

## Passos para configurar o banco de dados:

### 1. Instalar dependências
```bash
npm install
```
### 3. Executar migrations
```bash
# Para desenvolvimento (cria migration e aplica)
npm run db:migrate

# Para produção (apenas aplica migrations existentes)
npx prisma migrate deploy
```

### 4. Gerar cliente Prisma
```bash
npm run db:generate
```

### 5. Popular banco com dados iniciais (opcional)
```bash
npm run db:seed
```

### 6. Verificar banco de dados
```bash
npm run db:studio
```

## Comandos úteis:

### Desenvolvimento
- `npm run dev` - Inicia servidor de desenvolvimento
- `npm run db:studio` - Abre interface visual do banco
- `npm run db:migrate` - Cria nova migration
- `npm run db:generate` - Gera cliente Prisma

### Produção
- `npm start` - Inicia servidor de produção
- `npm run vercel-build` - Build para Vercel

### Manutenção
- `npm run db:reset` - Reset completo do banco (CUIDADO!)
- `npx prisma migrate status` - Verifica status das migrations
- `npx prisma validate` - Valida schema

### Cliente Prisma desatualizado:
1. Execute: `npx prisma generate`
2. Reinicie o servidor
