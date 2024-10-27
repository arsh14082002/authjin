import fs from 'fs-extra';
import path from 'path';
import { createPackageJson } from './createFunctions/createPackage.js';
import { copyFileFromTemplate } from './createFunctions/copyFileFromTemplate.js';
import ora from 'ora';
import inquirer from 'inquirer';
import { createDB } from './templates/src/config/db.js';
import { createModel } from './templates/src/models/userModel.js';
import { createController } from './templates/src/controllers/userController.js';

export async function createProject(name, useTypescript = false) {
  const dir = path.resolve(`./${name}`);

  // Prompt for database type
  const { dbType } = await inquirer.prompt([
    {
      type: 'list',
      name: 'dbType',
      message: 'Which database would you like to use?',
      choices: ['MongoDB', 'MySQL'],
    },
  ]);

  console.log('DB Type:', dbType);

  const spinner = ora('Creating project directories...').start();

  try {
    await fs.ensureDir(dir);
    await fs.ensureDir(`${dir}/public`);
    await fs.ensureDir(`${dir}/src/config`);
    await fs.ensureDir(`${dir}/src/controllers`);
    await fs.ensureDir(`${dir}/src/models`);
    await fs.ensureDir(`${dir}/src/routes`);
    await fs.ensureDir(`${dir}/src/middlewares`);
    spinner.succeed('Project directories created successfully.');
  } catch (error) {
    spinner.fail('Failed to create project directories.');
    console.error(error);
    return;
  }

  spinner.start('Creating your project files...');

  try {
    // Pass dbType to createPackageJson function
    await createPackageJson(dir, name, useTypescript, dbType);
    await createDB(dir, dbType, useTypescript);
    await createModel(dir, 'User', dbType, useTypescript);

    // Create the controller based on the selected DB type
    await createController(dir, dbType, useTypescript);

    // Copy other template files
    await copyFileFromTemplate(dir, 'eslint.config.js', useTypescript);
    await copyFileFromTemplate(dir, '.prettierrc', useTypescript);
    await copyFileFromTemplate(dir, '.gitignore', useTypescript);
    await copyFileFromTemplate(dir, 'server.js', useTypescript);
    await copyFileFromTemplate(dir, 'src/app.js', useTypescript);
    await copyFileFromTemplate(dir, 'src/routes/userRoute.js', useTypescript);
    await copyFileFromTemplate(dir, 'src/middlewares/authMiddleware.js', useTypescript);
    await copyFileFromTemplate(dir, 'src/config/apiConfig.js', useTypescript);

    if (useTypescript) {
      await createTsConfig(dir);
    }

    spinner.succeed('Package.json and template files copied successfully.');
  } catch (error) {
    spinner.fail('Failed to create package.json or copy template files.');
    console.error(error);
    return;
  }

  console.log(`\nProject ${name} created successfully!\n`);
  console.log('Run "npm install" to install dependencies.');
}
