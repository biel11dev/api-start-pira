"use strict";
const { Model } = require("sequelize");
module.exports = (sequelize, DataTypes) => {
  class DailyReading extends Model {
    static associate(models) {
      DailyReading.belongsTo(models.Machine, { foreignKey: "machineId" });
    }
  }
  DailyReading.init(
    {
      date: DataTypes.STRING,
      value: DataTypes.FLOAT,
      machineId: DataTypes.INTEGER,
    },
    {
      sequelize,
      modelName: "DailyReading",
    }
  );
  return DailyReading;
};
