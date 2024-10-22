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

### Now Create Project for authentication
```bash
npx sys create <project-name>
```

## Project Structure
```bash
.
├── createFunctions/
│   └── copyFileFromTemplate.js        
│   └── createPackage.js        
│   └── createTsConfig.js        
├── templates/
│   ├── src           
│   │   └── config       
│   │   │    └─── db.js       
│   │   │    └─── apiConfig.js       
│   │   └── controllers       
│   │   │    └─── userController.js       
│   │   └── middlewares       
│   │   │    └─── authMiddleware.js       
│   │   └── models       
│   │   │    └─── userModel.js       
│   │   └── routes       
│   │   │    └─── userRoutes.js       
│   │   └── app.js       
│   ├── .gitignore           
│   ├── .prettierrc           
│   ├── eslint.config.js           
│   ├── server.js           
└── .gitignore         
└── createFunctions.js         
└── index.js         
└── package-lock.json         
└── package.json         
└── webpack.config.js         
```

# Usage
#### 1. Registration
- Register a new user by sending a POST request:
- Endpoint: ```/api/users/register```
- Payload:
```json
{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "securepassword",
  "mobile": "+1234567890"
}
```

#### 2. Login
- Login with email, username, or mobile:
- Endpoint: ```/api/users/login```
- Payload:
```json
{
  "emailOrUsernameOrMobile": "john@example.com",
  "password": "securepassword"
}
```

#### 3. Verify Email
- To verify email with OTP sent on registration:
- Endpoint: ```/api/users/verify-email```
- Payload:
```json
{
  "email": "john@example.com",
  "verificationToken": "123456"
}
```

#### 4. Forgot Password
- Request a password reset email:
- Endpoint: ```/api/users/forgot-password```
- Payload:
```json
{
  "email": "john@example.com"
}
```
#### 5. Reset Password
- Reset password using the token from the email:
- Endpoint: ```/api/users/reset-password```
- Payload:
```json
{
  "token": "resetTokenFromEmail",
  "newPassword": "newSecurePassword",
  "confirmPassword": "newSecurePassword"
}
```

#### 6. SMS OTP
- Send an OTP via SMS:
- Endpoint: /api/users/send-otp
- Payload:
```json
{
  "phoneNumber": "+1234567890"
}
```

7. Logout
- Logout the user by clearing the authentication cookie:
- Endpoint: /api/users/logout
- No payload required.

