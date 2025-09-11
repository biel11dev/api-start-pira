const {Client} = require('@notionhq/client');

const notion = new Client({auth: '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'});

const retrieveNotionContent = async (block_id) => {
  try {
    const response = await notion.blocks.retrieve({block_id: block_id, page_size: 50});
    console.log("Notion content retrieved successfully:", response);
    return response;
  } catch (error) {
    console.error("Error retrieving Notion content:", error);
    throw error;
  }
};

retrieveNotionContent('133f158dc10c80549dd9d90ca9ba62db');