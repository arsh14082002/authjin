import { DataTypes } from 'sequelize';
import { sequelize } from '../config/mysqlConfig.js';

const User = sequelize.define(
  'User',
  {
    username: { type: DataTypes.STRING, allowNull: false, unique: true },
    email: { type: DataTypes.STRING, allowNull: false, unique: true },
    password: { type: DataTypes.STRING, allowNull: false },
    mobile: { type: DataTypes.STRING },
  },
  { timestamps: true }
);

export default User;
