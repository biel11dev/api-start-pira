"use strict";
const { Model } = require("sequelize");
module.exports = (sequelize, DataTypes) => {
  class Machine extends Model {
    static associate(models) {
      Machine.hasMany(models.DailyReading, { foreignKey: "machineId" });
    }
  }
  Machine.init(
    {
      name: DataTypes.STRING,
    },
    {
      sequelize,
      modelName: "Machine",
    }
  );
  return Machine;
};
