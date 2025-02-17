"use strict";
module.exports = (sequelize, DataTypes) => {
  const Product = sequelize.define(
    "Product",
    {
      name: DataTypes.STRING,
      quantity: DataTypes.INTEGER,
      unit: DataTypes.STRING,
    },
    {}
  );
  Product.associate = function (models) {
    // associations can be defined here
  };
  return Product;
};
