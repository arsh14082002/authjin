import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import inquirer from 'inquirer';
import { createPackageJson } from './createFunctions/createPackage.js';
import { createTsConfig } from './createFunctions/createTsConfig.js';

// Get the current directory in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Function to copy files from templates based on whether TypeScript is used
export async function copyFileFromTemplate(dir, filePath, useTypescript) {
  const ext = useTypescript ? '.ts' : '.js'; // Use .ts for TypeScript, .js otherwise
  const srcTemplatePath = path.join(__dirname, 'templates', filePath); // Path to the template file
  const destPath = path.join(dir, filePath.replace('.js', ext)); // Replace .js extension based on useTypescript flag

  try {
    if (await fs.pathExists(srcTemplatePath)) {
      await fs.copy(srcTemplatePath, destPath); // Copy the file to the destination
      console.log(`${filePath} copied to ${destPath} with ${ext} extension`);
    } else {
      console.error(`Template ${filePath} not found at ${srcTemplatePath}!`); // Error if the template file doesn't exist
    }
  } catch (error) {
    console.error(`Error copying ${filePath}:`, error); // Catch any errors during the copying process
  }
}

// Main function to create the project structure
export async function createProject(name) {
  const { useTypescript } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'useTypescript',
      message: 'Would you like to use TypeScript?',
      default: false,
    },
  ]);

  const dir = path.resolve(`./${name}`); // Resolve the directory path
  await fs.ensureDir(dir); // Ensure the project directory exists

  // Create folder structure
  await fs.ensureDir(`${dir}/public`);
  await fs.ensureDir(`${dir}/src/config`);
  await fs.ensureDir(`${dir}/src/controllers`);
  await fs.ensureDir(`${dir}/src/models`);
  await fs.ensureDir(`${dir}/src/routes`);
  await fs.ensureDir(`${dir}/src/middlewares`);

  // Create files
  await createPackageJson(dir, name, useTypescript); // Create package.json file

  // Copy required files to the project structure
  await copyFileFromTemplate(dir, 'src/app.js', useTypescript);
  await copyFileFromTemplate(dir, 'server.js', useTypescript);
  await copyFileFromTemplate(dir, 'src/config/db.js', useTypescript); // Corrected destination

  // Copy additional templates for routes, controllers, etc.
  await copyFileFromTemplate(dir, 'src/routes/userRoute.js', useTypescript);
  await copyFileFromTemplate(dir, 'src/controllers/userController.js', useTypescript);
  await copyFileFromTemplate(dir, 'src/models/userModel.js', useTypescript);
  await copyFileFromTemplate(dir, 'src/middlewares/authMiddleware.js', useTypescript);

  // Create tsconfig.json if TypeScript is selected
  if (useTypescript) {
    await createTsConfig(dir);
  }

  console.log(`Project ${name} created successfully!\n`);
  console.log('Run "npm install" to install dependencies.');
}
