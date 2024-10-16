# My Node Authentication Bundler

## Overview

This API provides user authentication and management functionalities. Below is a detailed explanation of the routes available in the application, along with instructions on configuring necessary API keys and environment variables for a successful setup.

## Routes

### User Authentication

1. **Register User**
   - **Endpoint:** `POST /api/register`
   - **Description:** Registers a new user in the application.
   - **Request Body:**
     ```json
     {
       "username": "string",
       "email": "string",
       "password": "string"
     }
     ```

2. **Login User**
   - **Endpoint:** `POST /api/login`
   - **Description:** Authenticates a user and returns a JWT token.
   - **Request Body:**
     ```json
     {
       "email": "string",
       "password": "string"
     }
     ```

3. **Logout User**
   - **Endpoint:** `POST /api/logout`
   - **Description:** Logs out the user by invalidating the JWT token.
   - **Middleware:** Requires authentication.

4. **Forgot Password**
   - **Endpoint:** `POST /api/forgot-password`
   - **Description:** Initiates the password reset process by sending an email to the user.
   - **Request Body:**
     ```json
     {
       "email": "string"
     }
     ```
   - **Middleware:** Requires authentication.

5. **Reset Password**
   - **Endpoint:** `POST /api/reset-password`
   - **Description:** Resets the user's password using a token sent via email.
   - **Request Body:**
     ```json
     {
       "token": "string",
       "newPassword": "string"
     }
     ```
   - **Middleware:** Requires authentication.

### SMS Verification

6. **Send SMS OTP**
   - **Endpoint:** `POST /api/send-otp`
   - **Description:** Sends an OTP (One-Time Password) to the user's registered phone number for verification.

7. **Verify OTP**
   - **Endpoint:** `POST /api/verify-otp`
   - **Description:** Verifies the OTP sent to the user's phone number.

### User Profile

8. **Get Single User**
   - **Endpoint:** `GET /api/:id`
   - **Description:** Retrieves the profile of a user by their ID.
   - **Middleware:** Requires authentication.

## Configuration

Before running the application, make sure to set up your environment variables. You can create a `.env` file in the root of your project with the following keys:

```plaintext
# JWT Secret for signing tokens
JWT_SECRET=your_jwt_secret

# Email configuration
EMAIL_USER=your_email@example.com
EMAIL_PASS=your_email_password

# Twilio configuration
TWILIO_ACCOUNT_SID=your_twilio_account_sid
TWILIO_AUTH_TOKEN=your_twilio_auth_token

# MongoDB connection string
MONGO_URI=mongodb://localhost:27017/mydatabase
```

# Important Notes
   - **JWT Secret:** This is crucial for token generation and validation. Ensure this is a strong, random string.
   - **Email Configuration:** Use your actual email credentials for sending password reset emails.
   - **Twilio Configuration:** Required if you are using Twilio for SMS services. Make sure to sign up for a Twilio account and obtain your `Account SID` and `Auth Token`.
   - **MongoDB URI:** If you're using a local MongoDB instance, the default connection string will suffice. For cloud databases, replace it with your connection string.

# Running the Application
    After configuring your environment variables, run the following commands to install dependencies and start the server:
    ```bash
    npm install
    npm start
    ```
Ensure that you have MongoDB running (either locally or remotely) to connect to the database successfully.

# License
This project is licensed under the MIT License - see the LICENSE file for details.

```plaintext

### Usage
- Save this content to a file named `README.md` in the root directory of your project.
- Make sure to update the **License** section if your project uses a different license. 

Let me know if you need any further adjustments!
```