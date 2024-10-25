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

const ${modelName}Schema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  mobile: { type: String },
}, { timestamps: true });

const ${modelName} = mongoose.model('${modelName}', ${modelName}Schema);
export default ${modelName};
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
import { DataTypes } from 'sequelize';
import { sequelize } from '../config/mysqlConfig.js';

const ${modelName} = sequelize.define('${modelName}', {
  username: { type: DataTypes.STRING, allowNull: false, unique: true },
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  password: { type: DataTypes.STRING, allowNull: false },
  mobile: { type: DataTypes.STRING },
}, { timestamps: true });

export default ${modelName};
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
