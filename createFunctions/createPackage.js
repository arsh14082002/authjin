import fs from 'fs-extra';

export async function createPackageJson(dir, name, useTypescript) {
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
      zod: '^3.23.8',
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
