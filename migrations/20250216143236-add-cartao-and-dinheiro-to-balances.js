"use strict";
module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.addColumn("Balances", "cartao", {
      type: Sequelize.FLOAT,
      allowNull: true,
    });
    await queryInterface.addColumn("Balances", "dinheiro", {
      type: Sequelize.FLOAT,
      allowNull: true,
    });
  },
  down: async (queryInterface, Sequelize) => {
    await queryInterface.removeColumn("Balances", "cartao");
    await queryInterface.removeColumn("Balances", "dinheiro");
  },
};
