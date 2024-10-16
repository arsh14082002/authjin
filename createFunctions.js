import fs from 'fs-extra';
import path from 'path';
import inquirer from 'inquirer';
import { createPackageJson } from './createFunctions/createPackage.js';
import { createTsConfig } from './createFunctions/createTsConfig.js';
import { copyFileFromTemplate } from './createFunctions/copyFileFromTemplate.js';

export async function createProject(name) {
  const { useTypescript } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'useTypescript',
      message: 'Would you like to use TypeScript?',
      default: false,
    },
  ]);

  const dir = path.resolve(`./${name}`);
  await fs.ensureDir(dir);

  // Create folder structure
  await fs.ensureDir(`${dir}/public`);
  await fs.ensureDir(`${dir}/src/config`);
  await fs.ensureDir(`${dir}/src/controllers`);
  await fs.ensureDir(`${dir}/src/models`);
  await fs.ensureDir(`${dir}/src/routes`);
  await fs.ensureDir(`${dir}/src/middlewares`);

  // Create package.json and copy files
  await createPackageJson(dir, name, useTypescript);
  await copyFileFromTemplate(dir, 'eslint.config.js', useTypescript); // Copy ESLint config
  await copyFileFromTemplate(dir, '.prettierrc', useTypescript);    // Copy Prettier config
  
  await copyFileFromTemplate(dir, 'src/app.js', useTypescript);
  await copyFileFromTemplate(dir, 'server.js', useTypescript);
  await copyFileFromTemplate(dir, 'src/config/db.js', useTypescript);
  await copyFileFromTemplate(dir, 'src/routes/userRoute.js', useTypescript);
  await copyFileFromTemplate(dir, 'src/controllers/userController.js', useTypescript);
  await copyFileFromTemplate(dir, 'src/models/userModel.js', useTypescript);
  await copyFileFromTemplate(dir, 'src/middlewares/authMiddleware.js', useTypescript);
  await copyFileFromTemplate(dir, 'src/config/apiConfig.js', useTypescript); // Corrected to use .js extension

  if (useTypescript) {
    await createTsConfig(dir);
  }

  console.log(`Project ${name} created successfully!\n`);
  console.log('Run "npm install" to install dependencies.');
}
