import fs from 'fs-extra';
import path from 'path';

export async function copyFileFromTemplate(dir, filename, useTypescript) {
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
