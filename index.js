#!/usr/bin/env node

import { program } from 'commander';
import fs from 'fs-extra';
import { createProject } from './createFunctions.js';

program
  .command('create <project-name>')
  .description(
    'Create a new Node.js project with Express, CORS, dotenv, Mongoose, and default user routes',
  )
  .action(async (projectName) => {
    await createProject(projectName);
  });

program.parse(process.argv);
