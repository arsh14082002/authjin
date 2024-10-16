import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';

export async function copyFileFromTemplate(dir, filename, useTypescript) {
  let templatePath, destinationPath;
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const ext = useTypescript ? 'ts' : 'js';

  switch (filename) {
    case 'eslint.config.js':
      templatePath = path.join(__dirname, `../templates/eslint.config.js`);
      destinationPath = path.join(dir, `eslint.config.js`);
      break;
    case '.prettierrc':
      templatePath = path.join(__dirname, `../templates/.prettierrc`);
      destinationPath = path.join(dir, `.prettierrc`);
      break;
    case ".gitignore":
      templatePath = path.join(__dirname, `../templates/.gitignore`);
      destinationPath = path.join(dir, `.gitignore`);
      break;
    case 'server.js':
      templatePath = path.join(__dirname, `../templates/server.js`);
      destinationPath = path.join(dir, `server.${ext}`);
      break;
    case 'src/config/db.js':
      templatePath = path.join(__dirname, `../templates/src/config/db.js`);
      destinationPath = path.join(dir, `src/config/db.${ext}`);
      break;
    case 'src/routes/userRoute.js':
      templatePath = path.join(__dirname, `../templates/src/routes/userRoute.js`);
      destinationPath = path.join(dir, `src/routes/userRoute.${ext}`);
      break;
    case 'src/controllers/userController.js':
      templatePath = path.join(__dirname, `../templates/src/controllers/userController.js`);
      destinationPath = path.join(dir, `src/controllers/userController.${ext}`);
      break;
    case 'src/middlewares/authMiddleware.js':
      templatePath = path.join(__dirname, `../templates/src/middlewares/authMiddleware.js`);
      destinationPath = path.join(dir, `src/middlewares/authMiddleware.${ext}`);
      break;
    case 'src/models/userModel.js':
      templatePath = path.join(__dirname, `../templates/src/models/userModel.js`);
      destinationPath = path.join(dir, `src/models/userModel.${ext}`);
      break;
    case 'src/config/apiConfig.js': // Use the correct filename here
      templatePath = path.join(__dirname, `../templates/src/config/apiConfig.js`);
      destinationPath = path.join(dir, `src/config/apiConfig.${ext}`);
      break;
    default:
      templatePath = path.join(__dirname, `../templates/src/app.js`);
      destinationPath = path.join(dir, `src/app.${ext}`);
      break;
  }

  if (fs.existsSync(templatePath)) {
    await fs.copy(templatePath, destinationPath);
    // console.log(`${filename} copied to ${destinationPath} with .${ext} extension`);
  } else {
    console.error(`Template ${templatePath} not found!`);
  }
}
