const {Client} = require('@notionhq/client');
const fs = require('fs');
const path = require('path');
const os = require('os');
require('dotenv').config();

const notion = new Client({ auth: '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' });

// Função para criar o caminho da pasta Documentos
const getDocumentsPath = () => {
  const userHome = os.homedir();
  return path.join(userHome, 'Documents');
};

// Função para salvar conteúdo em arquivo
const saveToFile = (content, filename) => {
  try {
    const documentsPath = getDocumentsPath();
    const filePath = path.join(documentsPath, filename);
    
    fs.writeFileSync(filePath, content, 'utf8');
    console.log(`\n✅ Arquivo salvo com sucesso em: ${filePath}`);
    return filePath;
  } catch (error) {
    console.error('❌ Erro ao salvar arquivo:', error);
    throw error;
  }
};

// Função para listar todos os blocos de uma página
const listPageBlocks = async (page_id) => {
  let fileContent = '=== NOTION PAGE BLOCKS ===\n\n';
  
  try {
    const response = await notion.blocks.children.list({
      block_id: page_id,
      page_size: 100
    });
    
    console.log("Blocks retrieved successfully:");
    console.log("Total blocks:", response.results.length);
    
    fileContent += `Total de blocos encontrados: ${response.results.length}\n`;
    fileContent += `Data de extração: ${new Date().toLocaleString('pt-BR')}\n\n`;
    
    // Iterar sobre cada bloco e mostrar seu conteúdo
    response.results.forEach((block, index) => {
      const blockInfo = `\n--- Bloco ${index + 1} ---\n`;
      const typeInfo = `Tipo: ${block.type}\n`;
      const idInfo = `ID: ${block.id}\n`;
      
      console.log(blockInfo);
      console.log(typeInfo);
      console.log(idInfo);
      
      fileContent += blockInfo + typeInfo + idInfo;
      
      // Mostrar conteúdo baseado no tipo do bloco
      let contentInfo = '';
      switch (block.type) {
        case 'paragraph':
          const paragraphText = block.paragraph.rich_text.map(text => text.plain_text).join('');
          contentInfo = `Conteúdo: ${paragraphText}\n`;
          break;
          
        case 'heading_1':
          const h1Text = block.heading_1.rich_text.map(text => text.plain_text).join('');
          contentInfo = `Título 1: ${h1Text}\n`;
          break;
          
        case 'heading_2':
          const h2Text = block.heading_2.rich_text.map(text => text.plain_text).join('');
          contentInfo = `Título 2: ${h2Text}\n`;
          break;
          
        case 'heading_3':
          const h3Text = block.heading_3.rich_text.map(text => text.plain_text).join('');
          contentInfo = `Título 3: ${h3Text}\n`;
          break;
          
        case 'bulleted_list_item':
          const bulletText = block.bulleted_list_item.rich_text.map(text => text.plain_text).join('');
          contentInfo = `• ${bulletText}\n`;
          break;
          
        case 'numbered_list_item':
          const numberedText = block.numbered_list_item.rich_text.map(text => text.plain_text).join('');
          contentInfo = `1. ${numberedText}\n`;
          break;
          
        case 'to_do':
          const todoText = block.to_do.rich_text.map(text => text.plain_text).join('');
          const checked = block.to_do.checked ? '✅' : '☐';
          contentInfo = `${checked} ${todoText}\n`;
          break;
          
        case 'code':
          const codeText = block.code.rich_text.map(text => text.plain_text).join('');
          contentInfo = `Código (${block.code.language}): ${codeText}\n`;
          break;
          
        case 'quote':
          const quoteText = block.quote.rich_text.map(text => text.plain_text).join('');
          contentInfo = `Citação: "${quoteText}"\n`;
          break;
          
        case 'callout':
          const calloutText = block.callout.rich_text.map(text => text.plain_text).join('');
          contentInfo = `Destaque: ${calloutText}\n`;
          break;
          
        case 'table':
          contentInfo = `Tabela com ${block.table.table_width} colunas\n`;
          break;
          
        case 'image':
          if (block.image.type === 'file') {
            contentInfo = `Imagem: ${block.image.file.url}\n`;
          } else if (block.image.type === 'external') {
            contentInfo = `Imagem: ${block.image.external.url}\n`;
          }
          break;
          
        default:
          contentInfo = `Conteúdo: ${JSON.stringify(block[block.type], null, 2)}\n`;
      }
      
      console.log(contentInfo);
      fileContent += contentInfo;
    });
    
    // Se houver mais blocos (paginação)
    if (response.has_more) {
      const paginationInfo = "\n⚠️ Há mais blocos disponíveis. Use paginação para obter todos os blocos.\n";
      const cursorInfo = `Próximo cursor: ${response.next_cursor}\n`;
      
      console.log(paginationInfo);
      console.log(cursorInfo);
      
      fileContent += paginationInfo + cursorInfo;
    }
    
    // Salvar no arquivo
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0];
    const filename = `notion-blocks-${timestamp}.txt`;
    saveToFile(fileContent, filename);
    
    return response;
  } catch (error) {
    console.error("Error retrieving page blocks:", error);
    throw error;
  }
};

// Função para listar TODOS os blocos com paginação
const listAllPageBlocks = async (page_id) => {
  let allBlocks = [];
  let cursor = undefined;
  let fileContent = '=== TODOS OS BLOCOS DA PÁGINA NOTION ===\n\n';
  
  try {
    do {
      const response = await notion.blocks.children.list({
        block_id: page_id,
        page_size: 100,
        start_cursor: cursor
      });
      
      allBlocks = allBlocks.concat(response.results);
      cursor = response.has_more ? response.next_cursor : undefined;
      
    } while (cursor);
    
    console.log(`\n🎉 Retrieved all ${allBlocks.length} blocks from the page!`);
    
    fileContent += `Total de blocos recuperados: ${allBlocks.length}\n`;
    fileContent += `Data de extração: ${new Date().toLocaleString('pt-BR')}\n`;
    fileContent += `ID da página: ${page_id}\n\n`;
    
    // Processar todos os blocos
    allBlocks.forEach((block, index) => {
      const blockHeader = `\n--- Bloco ${index + 1} de ${allBlocks.length} ---\n`;
      const typeInfo = `Tipo: ${block.type}\n`;
      
      console.log(blockHeader);
      console.log(typeInfo);
      
      fileContent += blockHeader + typeInfo;
      
      // Extrair texto baseado no tipo
      const textContent = extractTextFromBlock(block);
      if (textContent) {
        const contentLine = `Conteúdo: ${textContent}\n`;
        console.log(contentLine);
        fileContent += contentLine;
      } else {
        const noContentLine = `Sem conteúdo de texto\n`;
        console.log(noContentLine);
        fileContent += noContentLine;
      }
    });
    
    // Salvar arquivo completo
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0];
    const filename = `notion-all-blocks-${timestamp}.txt`;
    saveToFile(fileContent, filename);
    
    return allBlocks;
  } catch (error) {
    console.error("Error retrieving all page blocks:", error);
    throw error;
  }
};

// Função helper para extrair texto de qualquer tipo de bloco
const extractTextFromBlock = (block) => {
  const blockType = block[block.type];
  
  if (blockType && blockType.rich_text) {
    return blockType.rich_text.map(text => text.plain_text).join('');
  }
  
  return null;
};

// Função para salvar apenas o texto limpo (sem formatação)
const saveCleanText = async (page_id) => {
  try {
    const response = await notion.blocks.children.list({
      block_id: page_id,
      page_size: 100
    });
    
    let cleanText = '';
    
    response.results.forEach((block) => {
      const textContent = extractTextFromBlock(block);
      if (textContent && textContent.trim()) {
        cleanText += textContent + '\n';
      }
    });
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0];
    const filename = `notion-clean-text-${timestamp}.txt`;
    saveToFile(cleanText, filename);
    
    console.log('📝 Texto limpo salvo com sucesso!');
    return cleanText;
  } catch (error) {
    console.error("Error saving clean text:", error);
    throw error;
  }
};

// Executar as funções
console.log("=== Listando primeiros 100 blocos ===");
listPageBlocks('133f158dc10c80549dd9d90ca9ba62db');

setTimeout(() => {
  console.log("\n\n=== Listando TODOS os blocos com paginação ===");
  listAllPageBlocks('133f158dc10c80549dd9d90ca9ba62db');
}, 3000);

setTimeout(() => {
  console.log("\n\n=== Salvando apenas texto limpo ===");
  saveCleanText('133f158dc10c80549dd9d90ca9ba62db');
}, 6000);


const navigateAllChildren = async (parent_id, depth = 0, family_path = []) => {
  const indent = '  '.repeat(depth); // Indentação baseada na profundidade
  let result = {
    block_id: parent_id,
    depth: depth,
    family_path: [...family_path],
    children: [],
    content: ''
  };
  
  try {
    // Buscar o bloco atual para obter informações
    const blockInfo = await notion.blocks.retrieve({ block_id: parent_id });
    result.type = blockInfo.type;
    result.has_children = blockInfo.has_children;
    
    // Extrair conteúdo se existir
    const textContent = extractTextFromBlock(blockInfo);
    if (textContent) {
      result.content = textContent;
    }
    
    console.log(`${indent}📁 [Nível ${depth}] ID: ${parent_id}`);
    console.log(`${indent}   Tipo: ${blockInfo.type}`);
    console.log(`${indent}   Tem filhos: ${blockInfo.has_children}`);
    if (textContent) {
      console.log(`${indent}   Conteúdo: ${textContent.substring(0, 100)}...`);
    }
    
    // Se tem filhos, buscar recursivamente
    if (blockInfo.has_children) {
      let cursor = undefined;
      let childIndex = 0;
      
      do {
        const childrenResponse = await notion.blocks.children.list({
          block_id: parent_id,
          page_size: 100,
          start_cursor: cursor
        });
        
        for (const child of childrenResponse.results) {
          const childPath = [...family_path, parent_id];
          const childResult = await navigateAllChildren(child.id, depth + 1, childPath);
          result.children.push(childResult);
          childIndex++;
        }
        
        cursor = childrenResponse.has_more ? childrenResponse.next_cursor : undefined;
      } while (cursor);
    }
    
    return result;
  } catch (error) {
    console.error(`${indent}❌ Erro ao acessar bloco ${parent_id}:`, error.message);
    result.error = error.message;
    return result;
  }
};

// Função para organizar por famílias
const organizeByFamilies = (navigationResult) => {
  const families = new Map();
  
  const processFamilies = (block, familyId = 'root') => {
    if (!families.has(familyId)) {
      families.set(familyId, {
        family_id: familyId,
        root_block: block.block_id,
        total_descendants: 0,
        max_depth: 0,
        blocks: []
      });
    }
    
    const family = families.get(familyId);
    family.blocks.push({
      id: block.block_id,
      type: block.type,
      depth: block.depth,
      content: block.content,
      has_children: block.has_children,
      children_count: block.children.length
    });
    
    family.total_descendants += block.children.length;
    family.max_depth = Math.max(family.max_depth, block.depth);
    
    // Processar filhos recursivamente
    block.children.forEach((child, index) => {
      if (child.has_children) {
        // Criar nova família para cada filho com filhos
        const childFamilyId = `${familyId}_child_${index}`;
        processFamilies(child, childFamilyId);
      } else {
        // Adicionar à família atual se não tem filhos
        processFamilies(child, familyId);
      }
    });
  };
  
  processFamilies(navigationResult);
  return families;
};

// Função para salvar navegação hierárquica
const saveHierarchicalNavigation = async (page_id) => {
  console.log('\n🔍 Iniciando navegação hierárquica completa...');
  
  try {
    const startTime = Date.now();
    const navigationResult = await navigateAllChildren(page_id);
    const endTime = Date.now();
    
    console.log(`\n✅ Navegação concluída em ${(endTime - startTime) / 1000} segundos`);
    
    // Organizar por famílias
    const families = organizeByFamilies(navigationResult);
    
    // Criar conteúdo do arquivo
    let fileContent = '=== NAVEGAÇÃO HIERÁRQUICA COMPLETA DA PÁGINA NOTION ===\n\n';
    fileContent += `Data de extração: ${new Date().toLocaleString('pt-BR')}\n`;
    fileContent += `ID da página raiz: ${page_id}\n`;
    fileContent += `Total de famílias encontradas: ${families.size}\n`;
    fileContent += `Tempo de processamento: ${(endTime - startTime) / 1000} segundos\n\n`;
    
    // Função recursiva para formatar hierarquia
    const formatHierarchy = (block, depth = 0) => {
      const indent = '  '.repeat(depth);
      let content = '';
      
      content += `${indent}📁 [Nível ${depth}] Bloco: ${block.block_id}\n`;
      content += `${indent}   └─ Tipo: ${block.type}\n`;
      content += `${indent}   └─ Tem filhos: ${block.has_children}\n`;
      content += `${indent}   └─ Quantidade de filhos: ${block.children.length}\n`;
      
      if (block.content) {
        content += `${indent}   └─ Conteúdo: ${block.content.substring(0, 200)}${block.content.length > 200 ? '...' : ''}\n`;
      }
      
      if (block.error) {
        content += `${indent}   └─ ❌ Erro: ${block.error}\n`;
      }
      
      content += '\n';
      
      // Processar filhos
      block.children.forEach((child, index) => {
        content += `${indent}├─ Filho ${index + 1}:\n`;
        content += formatHierarchy(child, depth + 1);
      });
      
      return content;
    };
    
    fileContent += '=== ESTRUTURA HIERÁRQUICA COMPLETA ===\n\n';
    fileContent += formatHierarchy(navigationResult);
    
    fileContent += '\n\n=== RESUMO POR FAMÍLIAS ===\n\n';
    
    families.forEach((family, familyId) => {
      fileContent += `🏠 FAMÍLIA: ${familyId}\n`;
      fileContent += `   └─ Bloco raiz: ${family.root_block}\n`;
      fileContent += `   └─ Total de descendentes: ${family.total_descendants}\n`;
      fileContent += `   └─ Profundidade máxima: ${family.max_depth}\n`;
      fileContent += `   └─ Total de blocos na família: ${family.blocks.length}\n\n`;
      
      fileContent += `   📋 Blocos da família:\n`;
      family.blocks.forEach((block, index) => {
        const indent = '     ' + '  '.repeat(block.depth);
        fileContent += `${indent}${index + 1}. ID: ${block.id} | Tipo: ${block.type} | Nível: ${block.depth}\n`;
        if (block.content) {
          fileContent += `${indent}   Conteúdo: ${block.content.substring(0, 100)}...\n`;
        }
      });
      fileContent += '\n';
    });
    
    // Estatísticas finais
    fileContent += '\n=== ESTATÍSTICAS GERAIS ===\n\n';
    const totalBlocks = countTotalBlocks(navigationResult);
    const blocksWithChildren = countBlocksWithChildren(navigationResult);
    const maxDepth = findMaxDepth(navigationResult);
    
    fileContent += `📊 Total de blocos processados: ${totalBlocks}\n`;
    fileContent += `📊 Blocos com filhos: ${blocksWithChildren}\n`;
    fileContent += `📊 Profundidade máxima encontrada: ${maxDepth}\n`;
    fileContent += `📊 Total de famílias: ${families.size}\n`;
    
    // Salvar arquivo
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0];
    const timeString = new Date().toISOString().replace(/[:.]/g, '-').split('T')[1].split('.')[0];
    const filename = `notion-hierarchical-navigation-${timestamp}-${timeString}.txt`;
    
    saveToFile(fileContent, filename);
    
    console.log(`\n📊 ESTATÍSTICAS FINAIS:`);
    console.log(`   Total de blocos: ${totalBlocks}`);
    console.log(`   Blocos com filhos: ${blocksWithChildren}`);
    console.log(`   Profundidade máxima: ${maxDepth}`);
    console.log(`   Total de famílias: ${families.size}`);
    
    return {
      navigationResult,
      families,
      stats: {
        totalBlocks,
        blocksWithChildren,
        maxDepth,
        totalFamilies: families.size,
        processingTime: (endTime - startTime) / 1000
      }
    };
    
  } catch (error) {
    console.error('❌ Erro durante navegação hierárquica:', error);
    throw error;
  }
};

// Funções auxiliares para estatísticas
const countTotalBlocks = (block) => {
  let count = 1;
  block.children.forEach(child => {
    count += countTotalBlocks(child);
  });
  return count;
};

const countBlocksWithChildren = (block) => {
  let count = block.has_children ? 1 : 0;
  block.children.forEach(child => {
    count += countBlocksWithChildren(child);
  });
  return count;
};

const findMaxDepth = (block) => {
  let maxDepth = block.depth;
  block.children.forEach(child => {
    maxDepth = Math.max(maxDepth, findMaxDepth(child));
  });
  return maxDepth;
};

// Função para criar um mapa visual da estrutura
const createVisualMap = async (page_id) => {
  console.log('\n🗺️  Criando mapa visual da estrutura...');
  
  const navigationResult = await navigateAllChildren(page_id);
  
  const createTreeStructure = (block, isLast = true, prefix = '') => {
    const connector = isLast ? '└── ' : '├── ';
    const nextPrefix = prefix + (isLast ? '    ' : '│   ');
    
    let tree = `${prefix}${connector}${block.type}`;
    if (block.content) {
      tree += ` (${block.content.substring(0, 30)}...)`;
    }
    tree += ` [${block.block_id.substring(0, 8)}...]`;
    if (block.has_children) {
      tree += ` 👥${block.children.length}`;
    }
    tree += '\n';
    
    block.children.forEach((child, index) => {
      const isLastChild = index === block.children.length - 1;
      tree += createTreeStructure(child, isLastChild, nextPrefix);
    });
    
    return tree;
  };
  
  const visualMap = createTreeStructure(navigationResult);
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0];
  const filename = `notion-visual-map-${timestamp}.txt`;
  
  let content = '=== MAPA VISUAL DA ESTRUTURA HIERÁRQUICA ===\n\n';
  content += `Página raiz: ${page_id}\n`;
  content += `Data: ${new Date().toLocaleString('pt-BR')}\n\n`;
  content += 'Legenda:\n';
  content += '├── ou └── : Conexão hierárquica\n';
  content += '👥N : Bloco tem N filhos\n';
  content += '[xxxxxxxx...] : ID do bloco (truncado)\n\n';
  content += visualMap;
  
  saveToFile(content, filename);
  console.log('🗺️  Mapa visual salvo!');
  
  return visualMap;
};

// ...existing code...

// Executar navegação hierárquica completa
console.log("=== EXECUTANDO NAVEGAÇÃO HIERÁRQUICA COMPLETA ===");
saveHierarchicalNavigation('133f158dc10c80549dd9d90ca9ba62db')
  .then(() => {
    console.log('\n🎉 Navegação hierárquica concluída com sucesso!');
    
    // Criar mapa visual após 2 segundos
    setTimeout(() => {
      createVisualMap('133f158dc10c80549dd9d90ca9ba62db')
        .then(() => {
          console.log('\n✅ Todos os processos concluídos!');
        });
    }, 2000);
  })
  .catch(error => {
    console.error('❌ Erro durante o processo:', error);
  });