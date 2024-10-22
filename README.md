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
cd auth-jen
npm install
```

## Create a new project with the CLI
```bash
npm run create <project-name>
```

## Set up environment variables
- Create a ```plaintext .env ``` file in the root directory and configure the following variables: