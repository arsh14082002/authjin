import fs from 'fs-extra';
import path from 'path';

export async function createDB(dir, dbType, useTypescript) {
  const fileContentMap = {
    mongoConfig: {
      path: path.join(dir, 'src/config/db.js'),
      content: `
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import apiConfig from './apiConfig.js';
dotenv.config();

const mongoURI = apiConfig.mongoDB;

export async function connectDB() {
  try {
    mongoose.set('strictQuery', true);
    mongoose.connection("connected",()=>{
      console.log("MongoDB connected");
    })

    mongoose.connection.on("error",(error)=>{
      console.log("MongoDB disconnected");
    })
    await mongoose.connect(mongoURI);
    console.log('MongoDB connected');
  } catch (error) {
    console.error('MongoDB connection failed:', error);
    process.exit(1);
  }
}
`,
    },
    mysqlConfig: {
      path: path.join(dir, 'src/config/mysqlConfig.js'),
      content: `
     // models/User.js
import { DataTypes } from 'sequelize';
import sequelize from '../config/database.js';

const User = sequelize.define('User', {
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  mobile: {
    type: DataTypes.STRING,
    allowNull: true,
    unique: true,
  },
  emailVerificationToken: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  isVerified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
  },
  resetPasswordToken: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  resetPasswordExpire: {
    type: DataTypes.DATE,
    allowNull: true,
  },
  mobileOtp: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  mobileOtpExpire: {
    type: DataTypes.DATE,
    allowNull: true,
  },
});

export default User;
 
      `,
    },
  };

  // Create MongoDB or MySQL config file based on dbType
  if (dbType === 'MongoDB') {
    await fs.outputFile(
      fileContentMap.mongoConfig.path,
      fileContentMap.mongoConfig.content
    );
  } else if (dbType === 'MySQL') {
    await fs.outputFile(
      fileContentMap.mysqlConfig.path,
      fileContentMap.mysqlConfig.content
    );
  }

  // Conditionally create TypeScript configuration file
  if (useTypescript) {
    // Assuming there's a typescriptConfig object defined elsewhere in the file
    // If not, you need to define it or remove this block
    await fs.outputFile(
      fileContentMap.typescriptConfig.path,
      fileContentMap.typescriptConfig.content
    );
  }

  console.log('Files created based on configuration');
}
