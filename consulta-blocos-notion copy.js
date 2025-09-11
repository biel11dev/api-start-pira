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

// Função helper para extrair texto de qualquer tipo de bloco
const extractTextFromBlock = (block) => {
  const blockType = block[block.type];
  
  if (blockType && blockType.rich_text) {
    return blockType.rich_text.map(text => text.plain_text).join('');
  }
  
  // Para tipos específicos que não seguem o padrão rich_text
  switch (block.type) {
    case 'child_page':
      return block.child_page.title || '';
    case 'child_database':
      return block.child_database.title || '';
    case 'image':
      if (block.image.caption && block.image.caption.length > 0) {
        return block.image.caption.map(text => text.plain_text).join('');
      }
      return '';
    case 'file':
      if (block.file.caption && block.file.caption.length > 0) {
        return block.file.caption.map(text => text.plain_text).join('');
      }
      return block.file.name || '';
    case 'video':
      if (block.video.caption && block.video.caption.length > 0) {
        return block.video.caption.map(text => text.plain_text).join('');
      }
      return '';
    case 'audio':
      if (block.audio.caption && block.audio.caption.length > 0) {
        return block.audio.caption.map(text => text.plain_text).join('');
      }
      return '';
    case 'pdf':
      if (block.pdf.caption && block.pdf.caption.length > 0) {
        return block.pdf.caption.map(text => text.plain_text).join('');
      }
      return '';
    case 'embed':
      if (block.embed.caption && block.embed.caption.length > 0) {
        return block.embed.caption.map(text => text.plain_text).join('');
      }
      return block.embed.url || '';
    case 'bookmark':
      if (block.bookmark.caption && block.bookmark.caption.length > 0) {
        return block.bookmark.caption.map(text => text.plain_text).join('');
      }
      return block.bookmark.url || '';
    case 'equation':
      return block.equation.expression || '';
    case 'divider':
      return '---';
    case 'table_of_contents':
      return '[Índice]';
    case 'breadcrumb':
      return '[Breadcrumb]';
    default:
      return '';
  }
};

// Função para verificar se um bloco contém dados úteis
const hasUsefulData = (block) => {
  const textContent = extractTextFromBlock(block);
  return textContent && textContent.trim().length > 0;
};

// Função para classificar importância do bloco
const getBlockImportance = (block) => {
  const textContent = extractTextFromBlock(block);
  
  if (!textContent || textContent.trim().length === 0) {
    return 'empty'; // Bloco vazio
  }
  
  if (textContent.trim().length < 10) {
    return 'minimal'; // Dados mínimos
  }
  
  if (textContent.trim().length > 100) {
    return 'rich'; // Dados ricos
  }
  
  return 'standard'; // Dados padrão
};

// Função otimizada para navegar apenas pelos elementos com filhos até encontrar dados
const navigateToData = async (parent_id, depth = 0, dataPath = []) => {
  const indent = '  '.repeat(depth);
  
  try {
    // Buscar informações do bloco atual
    const blockInfo = await notion.blocks.retrieve({ block_id: parent_id });
    
    const currentPath = [...dataPath, {
      id: parent_id,
      type: blockInfo.type,
      depth: depth,
      hasChildren: blockInfo.has_children
    }];
    
    console.log(`${indent}🔍 [Nível ${depth}] Analisando: ${blockInfo.type} (${parent_id.substring(0, 8)}...)`);
    
    // Verificar se este bloco tem dados úteis
    const textContent = extractTextFromBlock(blockInfo);
    const importance = getBlockImportance(blockInfo);
    
    if (hasUsefulData(blockInfo)) {
      console.log(`${indent}📊 DADOS ENCONTRADOS! Importância: ${importance}`);
      console.log(`${indent}    Conteúdo: ${textContent.substring(0, 150)}...`);
      
      return {
        hasData: true,
        block: {
          id: parent_id,
          type: blockInfo.type,
          depth: depth,
          content: textContent,
          importance: importance,
          path: currentPath
        },
        children: [] // Se tem dados, não precisa ir mais fundo inicialmente
      };
    }
    
    // Se não tem dados mas tem filhos, continuar navegando
    if (blockInfo.has_children) {
      console.log(`${indent}📁 Tem filhos - Navegando mais fundo...`);
      
      let cursor = undefined;
      let dataResults = [];
      
      do {
        const childrenResponse = await notion.blocks.children.list({
          block_id: parent_id,
          page_size: 100,
          start_cursor: cursor
        });
        
        for (const child of childrenResponse.results) {
          const childResult = await navigateToData(child.id, depth + 1, currentPath);
          
          if (childResult.hasData) {
            dataResults.push(childResult);
          }
        }
        
        cursor = childrenResponse.has_more ? childrenResponse.next_cursor : undefined;
      } while (cursor);
      
      return {
        hasData: dataResults.length > 0,
        block: {
          id: parent_id,
          type: blockInfo.type,
          depth: depth,
          content: textContent || '',
          importance: 'container',
          path: currentPath
        },
        children: dataResults
      };
    } else {
      console.log(`${indent}🚫 Sem filhos e sem dados úteis`);
      return {
        hasData: false,
        block: {
          id: parent_id,
          type: blockInfo.type,
          depth: depth,
          content: textContent || '',
          importance: 'empty',
          path: currentPath
        },
        children: []
      };
    }
    
  } catch (error) {
    console.error(`${indent}❌ Erro ao acessar ${parent_id}:`, error.message);
    return {
      hasData: false,
      block: {
        id: parent_id,
        type: 'error',
        depth: depth,
        content: '',
        importance: 'error',
        path: dataPath, // Corrigido: usar dataPath no caso de erro
        error: error.message
      },
      children: []
    };
  }
};

// Função para coletar apenas dados úteis
const collectUsefulData = (navigationResult) => {
  const usefulData = [];
  
  const extractData = (result) => {
    if (result.hasData && result.block.importance !== 'container' && result.block.importance !== 'empty') {
      usefulData.push({
        id: result.block.id,
        type: result.block.type,
        depth: result.block.depth,
        content: result.block.content,
        importance: result.block.importance,
        pathLength: result.block.path.length,
        fullPath: result.block.path.map(p => `${p.type}(${p.id.substring(0, 8)})`).join(' → ')
      });
    }
    
    result.children.forEach(child => extractData(child));
  };
  
  extractData(navigationResult);
  return usefulData;
};

// Função para agrupar dados por tipo e importância
const groupDataByTypeAndImportance = (usefulData) => {
  const groups = {
    rich: [],      // Dados ricos (>100 chars)
    standard: [],  // Dados padrão (10-100 chars)
    minimal: []    // Dados mínimos (<10 chars)
  };
  
  usefulData.forEach(data => {
    if (groups[data.importance]) {
      groups[data.importance].push(data);
    }
  });
  
  return groups;
};

// Função principal otimizada para extrair dados
const extractDataOptimized = async (page_id) => {
  console.log('\n🎯 Iniciando extração otimizada de dados...');
  console.log('🔍 Navegando apenas por elementos com filhos até encontrar dados úteis\n');
  
  try {
    const startTime = Date.now();
    
    // Navegar até encontrar dados
    const navigationResult = await navigateToData(page_id);
    
    // Coletar apenas dados úteis
    const usefulData = collectUsefulData(navigationResult);
    
    // Agrupar por importância
    const groupedData = groupDataByTypeAndImportance(usefulData);
    
    const endTime = Date.now();
    const processingTime = (endTime - startTime) / 1000;
    
    console.log(`\n✅ Extração concluída em ${processingTime} segundos`);
    console.log(`📊 Total de dados úteis encontrados: ${usefulData.length}`);
    
    // Criar relatório focado nos dados
    let fileContent = '=== EXTRAÇÃO OTIMIZADA DE DADOS NOTION ===\n\n';
    fileContent += `Data de extração: ${new Date().toLocaleString('pt-BR')}\n`;
    fileContent += `ID da página: ${page_id}\n`;
    fileContent += `Tempo de processamento: ${processingTime} segundos\n`;
    fileContent += `Total de dados úteis: ${usefulData.length}\n\n`;
    
    // Relatório por importância
    fileContent += '=== DADOS ORGANIZADOS POR IMPORTÂNCIA ===\n\n';
    
    // Dados ricos
    if (groupedData.rich.length > 0) {
      fileContent += `🏆 DADOS RICOS (${groupedData.rich.length} itens):\n`;
      fileContent += '   ├─ Conteúdo extenso (>100 caracteres)\n';
      fileContent += '   └─ Maior valor informativo\n\n';
      
      groupedData.rich.forEach((data, index) => {
        fileContent += `   ${index + 1}. Tipo: ${data.type} | Profundidade: ${data.depth}\n`;
        fileContent += `      ID: ${data.id}\n`;
        fileContent += `      Caminho: ${data.fullPath}\n`;
        fileContent += `      Conteúdo: ${data.content.substring(0, 300)}${data.content.length > 300 ? '...' : ''}\n\n`;
      });
    }
    
    // Dados padrão
    if (groupedData.standard.length > 0) {
      fileContent += `📋 DADOS PADRÃO (${groupedData.standard.length} itens):\n`;
      fileContent += '   ├─ Conteúdo moderado (10-100 caracteres)\n';
      fileContent += '   └─ Informações relevantes\n\n';
      
      groupedData.standard.forEach((data, index) => {
        fileContent += `   ${index + 1}. ${data.type}: ${data.content}\n`;
        fileContent += `      └─ Caminho: ${data.fullPath}\n\n`;
      });
    }
    
    // Dados mínimos
    if (groupedData.minimal.length > 0) {
      fileContent += `📝 DADOS MÍNIMOS (${groupedData.minimal.length} itens):\n`;
      fileContent += '   ├─ Conteúdo breve (<10 caracteres)\n';
      fileContent += '   └─ Informações concisas\n\n';
      
      groupedData.minimal.forEach((data, index) => {
        fileContent += `   ${index + 1}. ${data.type}: "${data.content}"\n`;
      });
      fileContent += '\n';
    }
    
    // Estatísticas finais
    fileContent += '=== ESTATÍSTICAS DE EXTRAÇÃO ===\n\n';
    fileContent += `📊 Dados ricos: ${groupedData.rich.length}\n`;
    fileContent += `📊 Dados padrão: ${groupedData.standard.length}\n`;
    fileContent += `📊 Dados mínimos: ${groupedData.minimal.length}\n`;
    fileContent += `📊 Total de dados úteis: ${usefulData.length}\n`;
    fileContent += `📊 Tempo de processamento: ${processingTime}s\n`;
    
    // Lista apenas dos dados mais importantes (ricos)
    if (groupedData.rich.length > 0) {
      fileContent += '\n=== CONTEÚDO COMPLETO DOS DADOS RICOS ===\n\n';
      groupedData.rich.forEach((data, index) => {
        fileContent += `📄 DADOS RICOS ${index + 1}:\n`;
        fileContent += `   Tipo: ${data.type}\n`;
        fileContent += `   ID: ${data.id}\n`;
        fileContent += `   Profundidade: ${data.depth}\n`;
        fileContent += `   Caminho completo: ${data.fullPath}\n`;
        fileContent += `   Conteúdo completo:\n`;
        fileContent += `   ${'-'.repeat(50)}\n`;
        fileContent += `   ${data.content}\n`;
        fileContent += `   ${'-'.repeat(50)}\n\n`;
      });
    }
    
    // Salvar arquivo
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0];
    const timeString = new Date().toISOString().replace(/[:.]/g, '-').split('T')[1].split('.')[0];
    const filename = `notion-data-extraction-${timestamp}-${timeString}.txt`;
    
    saveToFile(fileContent, filename);
    
    // Salvar apenas conteúdo limpo dos dados ricos
    if (groupedData.rich.length > 0) {
      let cleanContent = '';
      groupedData.rich.forEach((data, index) => {
        cleanContent += `=== DADOS RICOS ${index + 1} ===\n`;
        cleanContent += data.content + '\n\n';
      });
      
      const cleanFilename = `notion-clean-data-${timestamp}-${timeString}.txt`;
      saveToFile(cleanContent, cleanFilename);
    }
    
    console.log(`\n📈 RESUMO FINAL:`);
    console.log(`   🏆 Dados ricos: ${groupedData.rich.length}`);
    console.log(`   📋 Dados padrão: ${groupedData.standard.length}`);
    console.log(`   📝 Dados mínimos: ${groupedData.minimal.length}`);
    console.log(`   ⚡ Tempo: ${processingTime}s`);
    
    return {
      usefulData,
      groupedData,
      stats: {
        totalUsefulData: usefulData.length,
        richData: groupedData.rich.length,
        standardData: groupedData.standard.length,
        minimalData: groupedData.minimal.length,
        processingTime
      }
    };
    
  } catch (error) {
    console.error('❌ Erro durante extração otimizada:', error);
    throw error;
  }
};

// Função para criar resumo executivo
const createExecutiveSummary = async (page_id) => {
  console.log('\n📋 Criando resumo executivo...');
  
  try {
    const result = await extractDataOptimized(page_id);
    
    let summary = '=== RESUMO EXECUTIVO - DADOS NOTION ===\n\n';
    summary += `Data: ${new Date().toLocaleString('pt-BR')}\n`;
    summary += `Página: ${page_id}\n\n`;
    
    summary += 'PRINCIPAIS ACHADOS:\n';
    summary += `├─ ${result.stats.richData} dados ricos encontrados\n`;
    summary += `├─ ${result.stats.standardData} dados padrão identificados\n`;
    summary += `├─ ${result.stats.minimalData} dados mínimos coletados\n`;
    summary += `└─ Processamento em ${result.stats.processingTime}s\n\n`;
    
    if (result.groupedData.rich.length > 0) {
      summary += 'CONTEÚDO MAIS RELEVANTE:\n';
      result.groupedData.rich.slice(0, 3).forEach((data, index) => {
        summary += `${index + 1}. ${data.type.toUpperCase()}: ${data.content.substring(0, 100)}...\n`;
      });
    }
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0];
    const filename = `notion-executive-summary-${timestamp}.txt`;
    saveToFile(summary, filename);
    
    console.log('📋 Resumo executivo criado!');
    return result;
  } catch (error) {
    console.error('❌ Erro ao criar resumo executivo:', error);
    throw error;
  }
};

// Executar extração otimizada
console.log("=== EXECUTANDO EXTRAÇÃO OTIMIZADA DE DADOS ===");
extractDataOptimized('133f158dc10c80549dd9d90ca9ba62db')
  .then(() => {
    console.log('\n🎯 Extração otimizada concluída!');
    
    // Criar resumo executivo
    setTimeout(() => {
      createExecutiveSummary('133f158dc10c80549dd9d90ca9ba62db')
        .then(() => {
          console.log('\n✅ Todos os processos otimizados concluídos!');
        })
        .catch(error => {
          console.error('❌ Erro no resumo:', error);
        });
    }, 1000);
  })
  .catch(error => {
    console.error('❌ Erro durante extração:', error);
  });