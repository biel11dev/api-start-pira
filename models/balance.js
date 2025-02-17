"use strict";
module.exports = (sequelize, DataTypes) => {
  const Balance = sequelize.define(
    "Balance",
    {
      date: DataTypes.STRING,
      balance: DataTypes.FLOAT,
      balancefim: DataTypes.FLOAT,
      lucro: DataTypes.FLOAT,
      cartao: DataTypes.FLOAT,
      dinheiro: DataTypes.FLOAT,
      cartaofimcaixa: DataTypes.FLOAT,
      dinheirofimcaixa: DataTypes.FLOAT,
    },
    {}
  );
  Balance.associate = function (models) {
    // associations can be defined here
  };
  return Balance;
};
