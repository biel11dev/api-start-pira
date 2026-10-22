// Padroniza as entradas de dados: trim em todos os textos e MAIÚSCULAS nos cadastros de
// produtos/catálogo, funcionários e despesas (nomes e unidades comparados por texto).
// Mantenha este arquivo idêntico nas APIs de QA e Produção.

// Senhas e tokens nunca são alterados.
const CHAVES_SEM_TRIM = /pass|senha|token|secret/i;

const maiusculo = (valor) => (typeof valor === "string" ? valor.trim().toUpperCase() : valor);

function trimProfundo(valor, chave) {
  if (typeof valor === "string") return CHAVES_SEM_TRIM.test(chave || "") ? valor : valor.trim();
  if (Array.isArray(valor)) return valor.map((v) => trimProfundo(v, chave));
  if (valor && typeof valor === "object") {
    for (const k of Object.keys(valor)) valor[k] = trimProfundo(valor[k], k);
  }
  return valor;
}

// Caminhos: "name", "items[].unit" (campo de cada item), "pdvHiddenUnits[]" (lista de textos)
// e "unitPrices{}" (chaves do objeto).
function aplicarMaiusculo(obj, caminho) {
  const [segmento, ...resto] = caminho.split(".");
  const lista = segmento.endsWith("[]");
  const mapa = segmento.endsWith("{}");
  const chave = lista || mapa ? segmento.slice(0, -2) : segmento;
  if (!obj || typeof obj !== "object" || !(chave in obj)) return;
  const alvo = obj[chave];

  if (resto.length === 0) {
    if (lista && Array.isArray(alvo)) obj[chave] = alvo.map(maiusculo);
    else if (mapa && alvo && typeof alvo === "object" && !Array.isArray(alvo)) {
      obj[chave] = Object.fromEntries(Object.entries(alvo).map(([k, v]) => [maiusculo(k), v]));
    } else if (!lista && !mapa) obj[chave] = maiusculo(alvo);
    return;
  }
  const filhos = lista ? (Array.isArray(alvo) ? alvo : []) : [alvo];
  filhos.forEach((filho) => aplicarMaiusculo(filho, resto.join(".")));
}

const REGRAS = [
  { rota: /^\/api\/products(\/\d+)?$/, campos: ["name", "unit", "baseUnit", "pdvHiddenUnits[]", "unitPrices{}"] },
  { rota: /^\/api\/categories(\/\d+)?$/, campos: ["name"] },
  { rota: /^\/api\/unit-equivalences$/, campos: ["unitName"] },
  { rota: /^\/api\/estoque_prod(\/\d+)?$/, campos: ["name", "unit", "comboNome"] },
  { rota: /^\/api\/estoque_prod\/\d+\/combo$/, campos: ["comboNome"] },
  { rota: /^\/api\/estoque_prod\/entrada$/, campos: ["unit"] },
  { rota: /^\/api\/estoque_prod\/converter-(reverso|dose)$/, campos: ["targetUnit"] },
  { rota: /^\/api\/composicoes(\/\d+)?$/, campos: ["nome"] },
  { rota: /^\/api\/composicoes\/(\d+\/opcoes|opcoes\/\d+)$/, campos: ["nome"] },
  { rota: /^\/api\/composicoes\/\d+\/opcao-estoque$/, campos: ["nome", "unit"] },
  { rota: /^\/api\/employees(\/\d+)?$/, campos: ["name"] },
  { rota: /^\/api\/(despesas|cadastrodesp|desp-pessoal)(\/\d+)?$/, campos: ["nomeDespesa"] },
  { rota: /^\/api\/cat-desp-pessoal(\/\d+)?$/, campos: ["nomeCategoria"] },
  { rota: /^\/api\/sales$/, campos: ["items[].name", "items[].unit"] },
  { rota: /^\/api\/pdv-comandas\/\d+\/items$/, campos: ["items[].name", "items[].unit"] },
];

const METODOS = new Set(["POST", "PUT", "PATCH"]);

function normalizarEntrada(req, res, next) {
  if (!METODOS.has(req.method) || !req.body || typeof req.body !== "object") return next();

  trimProfundo(req.body);
  const caminho = req.path.replace(/\/+$/, "");
  REGRAS.filter((r) => r.rota.test(caminho)).forEach((r) => r.campos.forEach((c) => aplicarMaiusculo(req.body, c)));
  next();
}

module.exports = { normalizarEntrada, maiusculo };
