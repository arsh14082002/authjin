# NodeJs Authentication Bundler

## Description

This project is a backend application built with Express, MongoDB, and JWT authentication for user registration, login, and profile management.

## Table of Contents

- [Features](#features)
- [Technologies](#technologies)
- [Installation](#installation)
- [Usage](#usage)
- [Run](#run)
- [API Endpoints](#api-endpoints)
- [License](#license)

## Features

- User registration and login
- JWT-based authentication
- Password hashing with bcrypt
- User profile retrieval
- Logout functionality with token invalidation
- Middleware for protected routes

## Technologies

- Node.js
- Express
- MongoDB
- Mongoose
- JWT (JSON Web Tokens)
- Bcrypt
- Inquirer (for project setup)
- Nodemon (for development)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/yourproject.git

   ```

2. Navigate to the project directory:

   ```bash
   cd yourproject

   ```

3. Install the dependencies:

   ```bash
   npm install

   ```

4. JWT_SECRET=your_jwt_secret

   ```bash

   ```

## Usage

1. Make the index.js file executable:

   ```bash
   chmod +x index.js
   ```

2. Link the package globally so you can use it anywhere:

   ```bash
   npm link
   ```

3. Create a new project by running the following command:

   ```bash
      sys create <filename>
   ```

   Replace <filename> with the desired name for your project. This command will initialize a new project with the specified structure and files.

## Run

To start the application in development mode, run:
npm run dev
