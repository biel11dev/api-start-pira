"use strict";
module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.addColumn("Balances", "balancefim", {
      type: Sequelize.FLOAT,
      allowNull: true,
    });
    await queryInterface.addColumn("Balances", "lucro", {
      type: Sequelize.FLOAT,
      allowNull: true,
    });
  },
  down: async (queryInterface, Sequelize) => {
    await queryInterface.removeColumn("Balances", "balancefim");
    await queryInterface.removeColumn("Balances", "lucro");
  },
};
