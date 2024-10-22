# Oth-Jen - Node.js Authentication API

## Table of Contents

1. [Introduction](#introduction)
2. [Features](#features)
3. [Requirements](#requirements)
4. [Installation](#installation)
5. [Project Structure](#project-structure)
6. [Usage](#usage)
   - [Registration](#registration)
   - [Login](#login)
   - [Verify Email](#verify-email)
   - [Forgot Password](#forgot-password)
   - [Reset Password](#reset-password)
   - [SMS OTP](#sms-otp)
   - [Logout](#logout)
7. [API Endpoints](#api-endpoints)
8. [Environment Variables](#environment-variables)
9. [Contributing](#contributing)
10. [License](#license)

## Introduction

`Auth-Jen` is a Node.js-based authentication system built with Express, Mongoose, and JWT. It provides user registration, login, email verification, password reset, SMS OTP, and JWT-based authentication with token management via cookies.

## Features

- User Registration
- JWT-based Authentication
- Email Verification
- Password Reset
- SMS OTP Verification
- Secure Authentication via Cookies
- Environment Configuration Support (dotenv)
- Modular Structure for Easy Expansion

## Requirements

Before running this project, make sure you have the following:

- Node.js (v14+)
- MongoDB

## Installation

To get started, clone the repository and install the necessary dependencies:

```bash
git clone https://github.com/arsh14082002/oth-jen.git
cd oth-jen
npm install
```

### Create a new project with the CLI
```bash
chmod +x index.js
```

### link bundler
```bash
npm link
```

## Project Structure
```bash
.
├── bin/
│   └── create.js        # CLI for project creation
├── src/
│   ├── app.js           # Express app configuration
│   ├── config/
│   │   └── db.js        # MongoDB connection setup
│   ├── controllers/
│   │   └── userController.js # User-related controllers
│   ├── middlewares/
│   │   └── authMiddleware.js # Authentication middleware
│   ├── models/
│   │   └── userModel.js  # User schema and model
│   ├── routes/
│       └── userRoute.js  # User-related routes
└── package.json         # Project metadata and dependencies
```