-- Padroniza (sem espaços nas pontas + MAIÚSCULAS) os textos de produtos/catálogo, funcionários e despesas.
-- UPPER é aplicado com tradução explícita dos acentos para não depender do locale do banco.
CREATE FUNCTION pg_temp.padroniza(t text) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT translate(
    UPPER(regexp_replace(t, E'^[[:space:]\u00a0]+|[[:space:]\u00a0]+$', '', 'g')),
    'áàâãäéèêëíìîïóòôõöúùûüçñ',
    'ÁÀÂÃÄÉÈÊËÍÌÎÏÓÒÔÕÖÚÙÛÜÇÑ'
  )
$$;

-- A unidade é única: se houver nomes iguais ignorando maiúsculas/minúsculas, unifique antes de aplicar.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM "UnitEquivalence" GROUP BY pg_temp.padroniza("unitName") HAVING COUNT(*) > 1
  ) THEN
    RAISE EXCEPTION 'Existem unidades duplicadas em "UnitEquivalence" ao ignorar maiúsculas/minúsculas. Unifique-as antes de aplicar esta migration.';
  END IF;
END $$;

UPDATE "UnitEquivalence" SET "unitName" = pg_temp.padroniza("unitName");

UPDATE "Product" SET
  "name" = pg_temp.padroniza("name"),
  "unit" = pg_temp.padroniza("unit"),
  "baseUnit" = pg_temp.padroniza("baseUnit"),
  "pdvHiddenUnits" = ARRAY(
    SELECT pg_temp.padroniza(t.u) FROM unnest("pdvHiddenUnits") WITH ORDINALITY AS t(u, i) ORDER BY t.i
  );

UPDATE "Product" SET "unitPrices" = (
  SELECT COALESCE(jsonb_object_agg(pg_temp.padroniza(e.k), e.v), '{}'::jsonb)
  FROM jsonb_each("unitPrices"::jsonb) AS e(k, v)
)
WHERE "unitPrices" IS NOT NULL AND jsonb_typeof("unitPrices"::jsonb) = 'object';

UPDATE "Category" SET "name" = pg_temp.padroniza("name");

UPDATE "Estoque" SET
  "name" = pg_temp.padroniza("name"),
  "unit" = pg_temp.padroniza("unit"),
  "comboNome" = pg_temp.padroniza("comboNome");

UPDATE "ComposicaoProduto" SET "nome" = pg_temp.padroniza("nome");
UPDATE "ComposicaoOpcao" SET "nome" = pg_temp.padroniza("nome");
UPDATE "ListaCompras" SET "nomeProduto" = pg_temp.padroniza("nomeProduto");

UPDATE "SaleItem" SET "productName" = pg_temp.padroniza("productName"), "unit" = pg_temp.padroniza("unit");
UPDATE "PdvComandaItem" SET "productName" = pg_temp.padroniza("productName");

UPDATE "Employee" SET "name" = pg_temp.padroniza("name");

UPDATE "Despesa" SET "nomeDespesa" = pg_temp.padroniza("nomeDespesa");
UPDATE "CadDespesa" SET "nomeDespesa" = pg_temp.padroniza("nomeDespesa");
UPDATE "DespPessoal" SET "nomeDespesa" = pg_temp.padroniza("nomeDespesa");
UPDATE "CatDespPessoal" SET "nomeCategoria" = pg_temp.padroniza("nomeCategoria");
