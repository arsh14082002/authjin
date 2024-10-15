import fs from 'fs-extra';

export async function createTsConfig(dir) {
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
