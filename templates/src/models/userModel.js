import path from 'path';
import fs from 'fs-extra';

export async function createModel(dir, modelName, dbType, useTypescript) {
  const filePath = path.join(
    dir,
    'src',
    'models',
    `${modelName}.${useTypescript ? 'ts' : 'js'}`
  );

  const modelContentMap = {
    MongoDB: {
      js: `
	import mongoose from 'mongoose';

const userSchema = new mongoose.Schema(
  {
     username: { type: String, required: true,unique:true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  mobile: { type: String },
  isVerified: { type: Boolean, default: false }, // New field for verification status
  emailVerificationToken: { type: String }, // Field to store the email OTP
  resetPasswordToken: { type: String },
  resetPasswordExpire: { type: Date },
  },
  { timestamps: true },
);

const User = mongoose.model('User', userSchema);
export default User;

      `,
      ts: `
import mongoose, { Document, Schema } from 'mongoose';

interface ${modelName}Document extends Document {
  username: string;
  email: string;
  password: string;
  mobile?: string;
}

const ${modelName}Schema = new Schema<${modelName}Document>({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  mobile: { type: String },
}, { timestamps: true });

const ${modelName} = mongoose.model<${modelName}Document>('${modelName}', ${modelName}Schema);
export default ${modelName};
      `,
    },
    MySQL: {
      js: `
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
      ts: `
import { DataTypes, Model, Optional } from 'sequelize';
import { sequelize } from '../config/mysqlConfig';

interface ${modelName}Attributes {
  id: number;
  username: string;
  email: string;
  password: string;
  mobile?: string;
}

interface ${modelName}CreationAttributes extends Optional<${modelName}Attributes, 'id'> {}

class ${modelName} extends Model<${modelName}Attributes, ${modelName}CreationAttributes> implements ${modelName}Attributes {
  public id!: number;
  public username!: string;
  public email!: string;
  public password!: string;
  public mobile?: string;
}

${modelName}.init({
  username: { type: DataTypes.STRING, allowNull: false, unique: true },
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  password: { type: DataTypes.STRING, allowNull: false },
  mobile: { type: DataTypes.STRING },
}, {
  sequelize,
  modelName: '${modelName}',
  timestamps: true
});

export default ${modelName};
      `,
    },
  };

  const content = modelContentMap[dbType][useTypescript ? 'ts' : 'js'];
  await fs.outputFile(filePath, content.trim());
  console.log(`${modelName} model created at ${filePath}`);
}
