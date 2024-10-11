import fs from 'fs-extra';
import path from 'path';
import inquirer from 'inquirer';

export async function createProject(name) {
  const { useTypescript } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'useTypescript',
      message: 'Would you like to use TypeScript?',
      default: false,
    },
  ]);

  const dir = `./${name}`;
  await fs.ensureDir(dir);

  // Create folder structure
  await fs.ensureDir(`${dir}/public`);
  await fs.ensureDir(`${dir}/src/config`);
  await fs.ensureDir(`${dir}/src/controllers`);
  await fs.ensureDir(`${dir}/src/models`);
  await fs.ensureDir(`${dir}/src/routes`);
  await fs.ensureDir(`${dir}/src/middlewares`);

  // Create files
  await createPackageJson(dir, name, useTypescript);
  await copyFileFromTemplate(dir, 'app.js', useTypescript);
  await copyFileFromTemplate(dir, 'server.js', useTypescript);
  await copyFileFromTemplate(dir, 'db.js', useTypescript);
  await copyFileFromTemplate(dir, 'userRoute.js', useTypescript);
  await copyFileFromTemplate(dir, 'userController.js', useTypescript);
  await copyFileFromTemplate(dir, 'userModel.js', useTypescript);
  await copyFileFromTemplate(dir, 'authMiddleware.js', useTypescript); // Ensure correct casing

  if (useTypescript) {
    await createTsConfig(dir);
  }

  console.log(`Project ${name} created successfully!\n`);
  console.log('Run "npm install" to install dependencies.');
}

async function createPackageJson(dir, name, useTypescript) {
  const packageJson = {
    name,
    version: '1.0.0',
    main: useTypescript ? 'dist/server.js' : 'server.js',
    type: 'module',
    scripts: {
      start: useTypescript ? 'node dist/server.js' : 'node server.js',
      dev: useTypescript ? 'tsc && nodemon dist/server.js' : 'nodemon server.js',
      ...(useTypescript ? { build: 'tsc' } : {}),
    },
    dependencies: {
      bcrypt: '^5.1.1',
      express: '^4.17.1',
      cors: '^2.8.5',
      dotenv: '^10.0.0',
      jsonwebtoken: '^9.0.2',
      mongoose: '^6.0.0',
    },
    devDependencies: {
      nodemon: '^3.1.7',
      ...(useTypescript
        ? { typescript: '^4.0.0', '@types/node': '^14.0.0', '@types/express': '^4.17.1' }
        : {}),
    },
  };
  await fs.writeFile(`${dir}/package.json`, JSON.stringify(packageJson, null, 2));
}

async function copyFileFromTemplate(dir, filename, useTypescript) {
  let templatePath, destinationPath;

  // Determine the extension based on whether TypeScript is used
  const ext = useTypescript ? 'ts' : 'js';

  // Use a switch-case for better readability
  switch (filename) {
    case 'server.js':
      templatePath = path.resolve(`./templates/${filename}`);
      destinationPath = `${dir}/server.${ext}`;
      break;
    case 'db.js':
      templatePath = path.resolve(`./templates/${filename}`);
      destinationPath = `${dir}/src/config/db.${ext}`;
      break;
    case 'userRoute.js':
      templatePath = path.resolve(`./templates/${filename}`);
      destinationPath = `${dir}/src/routes/userRoute.${ext}`;
      break;
    case 'userController.js':
      templatePath = path.resolve(`./templates/${filename}`);
      destinationPath = `${dir}/src/controllers/userController.${ext}`;
      break;
    case 'authMiddleware.js': // Ensure correct casing
      templatePath = path.resolve(`./templates/${filename}`);
      destinationPath = `${dir}/src/middlewares/authMiddleware.${ext}`;
      break;
    case 'userModel.js': // Ensure correct casing
      templatePath = path.resolve(`./templates/${filename}`);
      destinationPath = `${dir}/src/models/userModel.${ext}`;
      break;
    default:
      templatePath = path.resolve(`./templates/${filename}`);
      destinationPath = `${dir}/src/app.${ext}`;
      break;
  }

  // Check if the template file exists and copy it
  if (fs.existsSync(templatePath)) {
    await fs.copy(templatePath, destinationPath);
    console.log(`${filename} copied to ${destinationPath} with .${ext} extension`);
  } else {
    console.error(`Template ${filename} not found!`);
  }
}

async function createTsConfig(dir) {
  const tsConfig = {
    compilerOptions: {
      target: 'ES6',
      module: 'ES6',
      rootDir: './src',
      outDir: './dist',
      esModuleInterop: true,
      strict: true,
    },
    include: ['src/**/*.ts'],
  };
  await fs.writeFile(`${dir}/tsconfig.json`, JSON.stringify(tsConfig, null, 2));
}
