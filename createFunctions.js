import fs from 'fs-extra';
import path from 'path';
import { createPackageJson } from './createFunctions/createPackage.js';
import { createTsConfig } from './createFunctions/createTsConfig.js';
import { copyFileFromTemplate } from './createFunctions/copyFileFromTemplate.js';
import  ora  from 'ora'; // Import the ora package for loading spinner

export async function createProject(name, useTypescript = false) {
  const dir = path.resolve(`./${name}`);

  const spinner = ora('Creating project directories...').start(); // Start spinner

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

  // Create package.json and copy files
  spinner.start('Creating your project files...');
  
  try {
    await createPackageJson(dir, name, useTypescript);
    await copyFileFromTemplate(dir, 'eslint.config.js', useTypescript); // Copy ESLint config
    await copyFileFromTemplate(dir, '.prettierrc', useTypescript);    // Copy Prettier config
    await copyFileFromTemplate(dir, '.gitignore', useTypescript); // Corrected to use .js extension
    await copyFileFromTemplate(dir, 'server.js', useTypescript);

    await copyFileFromTemplate(dir, 'src/app.js', useTypescript);
    await copyFileFromTemplate(dir, 'src/config/db.js', useTypescript);
    await copyFileFromTemplate(dir, 'src/routes/userRoute.js', useTypescript);
    await copyFileFromTemplate(dir, 'src/controllers/userController.js', useTypescript);
    await copyFileFromTemplate(dir, 'src/models/userModel.js', useTypescript);
    await copyFileFromTemplate(dir, 'src/middlewares/authMiddleware.js', useTypescript);
    await copyFileFromTemplate(dir, 'src/config/apiConfig.js', useTypescript); // Corrected to use .js extension

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
