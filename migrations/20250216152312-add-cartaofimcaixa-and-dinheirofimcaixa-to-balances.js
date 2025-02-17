"use strict";
module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.addColumn("Balances", "cartaofimcaixa", {
      type: Sequelize.FLOAT,
      allowNull: true,
    });
    await queryInterface.addColumn("Balances", "dinheirofimcaixa", {
      type: Sequelize.FLOAT,
      allowNull: true,
    });
  },
  down: async (queryInterface, Sequelize) => {
    await queryInterface.removeColumn("Balances", "cartaofimcaixa");
    await queryInterface.removeColumn("Balances", "dinheirofimcaixa");
  },
};
