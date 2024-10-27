import fs from 'fs-extra';
import path from 'path';
import { createMongoController } from './mongoController.js';
import { createMysqlController } from './mysqlController.js';

const typescriptConfig = {
  mongoConfig: {
    path: 'src/controllers/userController.ts',
    content: `/* TypeScript MongoDB controller content here */`,
  },
  mysqlConfig: {
    path: 'src/controllers/userController.ts',
    content: `/* TypeScript MySQL controller content here */`,
  },
};

export async function createController(dir, dbType, useTypescript) {
  const commonImports = `
    import bcrypt from 'bcrypt';
import User from '../models/userModel.js';
import { z } from 'zod';
import nodemailer from 'nodemailer';
import twilio from 'twilio';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import apiConfig from '../config/apiConfig.js';
import path from 'path';
import fs from 'fs-extra';

const your_jwt_secret = apiConfig.jwtSecret;
const emailUserName = apiConfig.emailUserName;
const emailPassword = apiConfig.emailPassword;
const accountSid = apiConfig.accountSid;
const authToken = apiConfig.authToken;
const client = new twilio(accountSid, authToken);
const otpStore = {};

const generateOtp = () =>
  Math.floor(100000 + Math.random() * 900000).toString();
  `;

  const fileContentMap = {
    mongoConfig: {
      path: path.join(
        dir,
        `src/controllers/userController${useTypescript ? '.ts' : '.js'}`
      ),
      content: `
      import bcrypt from 'bcrypt';
import { z } from 'zod';
import nodemailer from 'nodemailer';
import apiConfig from '../config/apiConfig.js';
import User from '../models/User.js';
import crypto from 'crypto';
import jwt from 'jsonwebtoken'; // Make sure you import jwt
import twilio from 'twilio';

const jwtSecret = apiConfig.jwtSecret;
const emailUserName = apiConfig.emailUserName;
const emailPassword = apiConfig.emailPassword;
const accountSid = apiConfig.accountSid;
const authToken = apiConfig.authToken;
const client = new twilio(accountSid, authToken);
const otpStore = {};

const generateOtp = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

export const registerUser = async (req, res) => {
  const userValidationSchema = z.object({
    username: z.string().min(1, 'Username is required'),
    email: z.string().email('Invalid email address'),
    password: z.string().min(6, 'Password must be at least 6 characters long'),
    mobile: z.string().optional(),
  });

  try {
    const validatedData = userValidationSchema.parse(req.body);
    const { username, email, password, mobile } = validatedData;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const emailVerificationToken = generateOtp(); // Ensure generateOtp function is defined and imported

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      mobile,
      emailVerificationToken,
    });

    await newUser.save();

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: emailUserName,
        pass: emailPassword,
      },
    });

    const mailOptions = {
      from: emailUserName,
      to: email,
      subject: 'Verify your Email',
      html:
        '<p>Welcome ' +
        username +
        ',</p><p>Your verification code is:' +
        generateOtp() +
        '</b></p><p>Please use this code to verify your email and activate your account.</p>', // Corrected backticks
    };

    await transporter.sendMail(mailOptions);

    res
      .status(201)
      .json({ message: 'User registered. Verification email sent.' });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.errors });
    }
    res.status(500).json({ message: error.message });
  }
};

export const loginUser = async (req, res) => {
  const loginValidationSchema = z.object({
    emailOrUsernameOrMobile: z
      .string()
      .min(1, 'Username, email, or mobile is required'),
    password: z.string().min(6, 'Password must be at least 6 characters long'),
  });

  try {
    const validatedData = loginValidationSchema.parse(req.body);
    const { emailOrUsernameOrMobile, password } = validatedData;

    const user = await User.findOne({
      $or: [
        { username: emailOrUsernameOrMobile },
        { email: emailOrUsernameOrMobile },
        { mobile: emailOrUsernameOrMobile },
      ],
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    const token = jwt.sign({ userId: user._id }, 'your_jwt_secret', {
      expiresIn: '1h',
    });

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000, // 1 hour
    });

    res.json({ token });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.errors });
    }
    res.status(500).json({ message: error.message });
  }
};

export const verifyEmail = async (req, res) => {
  const { email, verificationToken } = req.body;

  try {
    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if the verification token matches the one stored in the database
    if (user.emailVerificationToken === verificationToken) {
      // Mark user as verified
      user.isVerified = true;
      user.emailVerificationToken = undefined; // Clear the token after successful verification
      await user.save();

      // Generate JWT token after successful verification
      const token = jwt.sign(
        { userId: user._id },
        jwtSecret, // Ensure your secret is defined in environment variables
        { expiresIn: '1h' }
      );

      // Send the token in an HTTP-only cookie
      res.cookie('token', token, {
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 3600000, // 1 hour
      });

      // Respond with success message and token
      res.status(200).json({ message: 'Email verified successfully', token });
    } else {
      res.status(400).json({ message: 'Invalid verification token' });
    }
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const logoutUser = async (req, res) => {
  // Clear the token cookie
  res.clearCookie('token', {
    path: '/',
    httpOnly: true,
  });

  res.json({ message: 'User logged out successfully.' });
};

export const forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Generate a reset token
    // const resetToken = crypto.randomBytes(32).toString('hex');
    const resetToken = generateOtp();

    user.resetPasswordToken = resetToken;
    user.resetPasswordExpire = Date.now() + 3600000; // Token expires in 1 hour
    await user.save();

    // Send email
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: emailUserName,
        pass: emailPassword,
      },
    });

    const mailOptions = {
      from: emailUserName,
      to: user.email,
      subject: 'Password Reset',
      html:
        'You requested a password reset. Click the following link to reset your password:' +
        generateOtp(),
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Password reset email sent' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const resetPassword = async (req, res) => {
  const { token, newPassword, confirmPassword } = req.body;

  try {
    // Check if passwords match
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: 'Passwords do not match' });
    }

    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user)
      return res.status(400).json({ message: 'Invalid or expired token' });

    // Hash new password and save
    user.password = await bcrypt.hash(newPassword, 12);
    user.resetPasswordToken = undefined; // Clear token
    user.resetPasswordExpire = undefined; // Clear expiry
    await user.save();

    res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const sendSMSOTP = async (req, res) => {
  const { email } = req.body;

  try {
    // Find the user by email
    const user = await User.findOne({ email });
    if (!user || !user.mobile) {
      return res
        .status(404)
        .json({ message: 'User or mobile number not found' });
    }

    // Generate a new OTP
    const otp = generateOtp();

    // Store the OTP and its expiration time in the database
    user.mobileOtp = otp;
    user.mobileOtpExpire = Date.now() + 300000; // 5 minutes
    await user.save();

    // Send the OTP via SMS to the user's registered mobile number
    await client.messages.create({
      body: "Your OTP code is ${otp}",
      from: '+13037474559', // Replace with your Twilio phone number
      to: user.mobile,
    });

    res
      .status(200)
      .json({ message: 'OTP sent successfully to registered mobile number' });
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .json({ message: 'Error sending OTP', error: error.message });
  }
};

export const verifyOTP = async (req, res) => {
  const { email, otp } = req.body;

  try {
    // Find the user by email and check OTP
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if OTP matches and is not expired
    if (user.mobileOtp === otp && user.mobileOtpExpire > Date.now()) {
      // Clear the OTP and expiration time upon successful verification
      user.mobileOtp = undefined;
      user.mobileOtpExpire = undefined;
      await user.save();

      res.status(200).json({ message: 'OTP verified successfully' });
    } else {
      res.status(400).json({ message: 'Invalid or expired OTP' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
};


export const getSingleUser = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }
    res.json(user);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

      `,
    },

    mysqlConfig: {
      path: path.join(
        dir,
        `src/controllers/userController${useTypescript ? '.ts' : '.js'}`
      ),
      content: `
        import bcrypt from 'bcrypt';
import { z } from 'zod';
import nodemailer from 'nodemailer';
import apiConfig from '../config/apiConfig.js';
import { User } from '../models'; // Assuming Sequelize models are defined here
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import twilio from 'twilio';

const jwtSecret = apiConfig.jwtSecret;
const emailUserName = apiConfig.emailUserName;
const emailPassword = apiConfig.emailPassword;
const accountSid = apiConfig.accountSid;
const authToken = apiConfig.authToken;
const client = new twilio(accountSid, authToken);

const generateOtp = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

export const registerUser = async (req, res) => {
  const userValidationSchema = z.object({
    username: z.string().min(1, 'Username is required'),
    email: z.string().email('Invalid email address'),
    password: z.string().min(6, 'Password must be at least 6 characters long'),
    mobile: z.string().optional(),
  });

  try {
    const validatedData = userValidationSchema.parse(req.body);
    const { username, email, password, mobile } = validatedData;

    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const emailVerificationToken = generateOtp();

    const newUser = await User.create({
      username,
      email,
      password: hashedPassword,
      mobile,
      emailVerificationToken,
    });

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: emailUserName,
        pass: emailPassword,
      },
    });

    const mailOptions = {
      from: emailUserName,
      to: email,
      subject: 'Verify your Email',
      html: "<p>Welcome ,</p>" + username + "<p>Your verification code is:" + emailVerificationToken,
    };

    await transporter.sendMail(mailOptions);

    res.status(201).json({ message: 'User registered. Verification email sent.' });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.errors });
    }
    res.status(500).json({ message: error.message });
  }
};

export const loginUser = async (req, res) => {
  const loginValidationSchema = z.object({
    emailOrUsernameOrMobile: z.string().min(1, 'Username, email, or mobile is required'),
    password: z.string().min(6, 'Password must be at least 6 characters long'),
  });

  try {
    const validatedData = loginValidationSchema.parse(req.body);
    const { emailOrUsernameOrMobile, password } = validatedData;

    const user = await User.findOne({
      where: {
        [Op.or]: [
          { username: emailOrUsernameOrMobile },
          { email: emailOrUsernameOrMobile },
          { mobile: emailOrUsernameOrMobile },
        ],
      },
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    const token = jwt.sign({ userId: user.id }, jwtSecret, {
      expiresIn: '1h',
    });

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000,
    });

    res.json({ token });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.errors });
    }
    res.status(500).json({ message: error.message });
  }
};

export const verifyEmail = async (req, res) => {
  const { email, verificationToken } = req.body;

  try {
    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (user.emailVerificationToken === verificationToken) {
      await user.update({ isVerified: true, emailVerificationToken: null });

      const token = jwt.sign({ userId: user.id }, jwtSecret, { expiresIn: '1h' });

      res.cookie('token', token, {
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 3600000,
      });

      res.status(200).json({ message: 'Email verified successfully', token });
    } else {
      res.status(400).json({ message: 'Invalid verification token' });
    }
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const logoutUser = (req, res) => {
  res.clearCookie('token', { path: '/', httpOnly: true });
  res.json({ message: 'User logged out successfully.' });
};

export const forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const resetToken = generateOtp();

    await user.update({ resetPasswordToken: resetToken, resetPasswordExpire: Date.now() + 3600000 });

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: emailUserName, pass: emailPassword },
    });

    const mailOptions = {
      from: emailUserName,
      to: user.email,
      subject: 'Password Reset',
      html: "<p>Your reset code is: <b>" + resetToken ,
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Password reset email sent' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const resetPassword = async (req, res) => {
  const { token, newPassword, confirmPassword } = req.body;

  try {
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: 'Passwords do not match' });
    }

    const user = await User.findOne({
      where: {
        resetPasswordToken: token,
        resetPasswordExpire: { [Op.gt]: Date.now() },
      },
    });

    if (!user) return res.status(400).json({ message: 'Invalid or expired token' });

    const hashedPassword = await bcrypt.hash(newPassword, 12);

    await user.update({ password: hashedPassword, resetPasswordToken: null, resetPasswordExpire: null });

    res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const sendSMSOTP = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ where: { email } });
    if (!user || !user.mobile) {
      return res.status(404).json({ message: 'User or mobile number not found' });
    }

    const otp = generateOtp();

    await user.update({ mobileOtp: otp, mobileOtpExpire: Date.now() + 300000 });

    await client.messages.create({
      body: "Your OTP code is ${otp}",
      from: '+13037474559',
      to: user.mobile,
    });

    res.status(200).json({ message: 'OTP sent successfully to registered mobile number' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error sending OTP', error: error.message });
  }
};

export const verifyOTP = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ where: { email } });

    if (!user) return res.status(404).json({ message: 'User not found' });

    if (user.mobileOtp === otp && user.mobileOtpExpire > Date.now()) {
      await user.update({ mobileOtp: null, mobileOtpExpire: null });
      res.status(200).json({ message: 'OTP verified successfully' });
    } else {
      res.status(400).json({ message: 'Invalid or expired OTP' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const getSingleUser = async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

      `,
    },
  };

  try {
    const config =
      dbType === 'MongoDB'
        ? fileContentMap.mongoConfig
        : fileContentMap.mysqlConfig;
    await fs.outputFile(config.path, config.content);
    console.log('Controller file created based on configuration');
  } catch (error) {
    console.error('Error creating controller file:', error);
  }
}

// export const registerUser = async (req, res) => {
//   const userValidationSchema = z.object({
//     username: z.string().min(1, 'Username is required'),
//     email: z.string().email('Invalid email address'),
//     password: z.string().min(6, 'Password must be at least 6 characters long'),
//     mobile: z.string().optional(),
//   });

//   try {
//     const validatedData = userValidationSchema.parse(req.body);
//     const { username, email, password, mobile } = validatedData;

//     // Check if the email is already registered
//     const existingUser = await User.findOne({ email });
//     if (existingUser) {
//       return res.status(400).json({ message: 'Email already registered' });
//     }

//     const hashedPassword = await bcrypt.hash(password, 10);
//     const emailVerificationToken = generateOtp();

//     const newUser = new User({
//       username,
//       email,
//       password: hashedPassword,
//       mobile,
//       emailVerificationToken, // Store the OTP
//     });

//     await newUser.save();

//     // Send OTP via email
//     const transporter = nodemailer.createTransport({
//       service: 'gmail',
//       auth: {
//         user: emailUserName,
//         pass: emailPassword,
//       },
//     });

//     const mailOptions = {
//       from: emailUserName,
//       to: email,
//       subject: 'Verify your Email',
//       html: `<p>Welcome ${username},</p>
//              <p>Your verification code is: <b>${emailVerificationToken}</b></p>
//              <p>Please use this code to verify your email and activate your account.</p>`,
//     };

//     await transporter.sendMail(mailOptions);

//     res
//       .status(201)
//       .json({ message: 'User registered. Verification email sent.' });
//   } catch (error) {
//     if (error instanceof z.ZodError) {
//       return res.status(400).json({ message: error.errors });
//     }
//     res.status(500).json({ message: error.message });
//   }
// };

// export const loginUser = async (req, res) => {
//   // Zod schema defined inside the controller
//   const loginValidationSchema = z.object({
//     emailOrUsernameOrMobile: z
//       .string()
//       .min(1, 'Username, email, or mobile is required'), // Can be username, email, or mobile
//     password: z.string().min(6, 'Password must be at least 6 characters long'),
//   });

//   try {
//     // Validate request body using the Zod schema
//     const validatedData = loginValidationSchema.parse(req.body);

//     const { emailOrUsernameOrMobile, password } = validatedData;

//     // console.log('Received login credentials:', emailOrUsernameOrMobile);

//     // Find user by username, email, or mobile
//     const user = await User.findOne({
//       $or: [
//         { username: emailOrUsernameOrMobile },
//         { email: emailOrUsernameOrMobile },
//         { mobile: emailOrUsernameOrMobile },
//       ],
//     });

//     // If user is not found, return error
//     if (!user) {
//       console.log('User not found with the provided credentials.');
//       return res.status(400).json({ message: 'Invalid credentials.' });
//     }

//     // Compare the password with the stored hashed password
//     const isPasswordValid = await bcrypt.compare(password, user.password);
//     if (!isPasswordValid) {
//       console.log('Invalid password.');
//       return res.status(400).json({ message: 'Invalid credentials.' });
//     }

//     // Generate JWT token
//     const token = jwt.sign({ userId: user._id }, your_jwt_secret, {
//       expiresIn: '1h',
//     });

//     res.cookie('token', token, {
//       httpOnly: true,
//       secure: process.env.NODE_ENV === 'production',
//       sameSite: 'strict',
//       maxAge: 3600000,
//     });

//     res.json({ token });
//   } catch (error) {
//     if (error instanceof z.ZodError) {
//       return res.status(400).json({ message: error.errors });
//     }
//     // console.error('Login error:', error);
//     res.status(400).json({ message: error.message });
//   }
// };

export const verifyEmail = async (req, res) => {
  const { email, verificationToken } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if the verification token matches the one in the database
    if (user.emailVerificationToken === verificationToken) {
      // Set user as verified
      user.isVerified = true;
      user.emailVerificationToken = undefined; // Clear the token after successful verification
      await user.save();

      // Generate JWT token after successful verification
      const token = jwt.sign(
        { userId: user._id },
        your_jwt_secret, // Ensure this is correctly defined
        { expiresIn: '1h' }
      );

      // Send the token in an HTTP-only cookie
      res.cookie('token', token, {
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 3600000, // 1 hour
      });

      // Respond with success and token (if you want to send it directly)
      res.status(200).json({ message: 'Email verified successfully', token });
    } else {
      res.status(400).json({ message: 'Invalid verification token' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

export const logoutUser = async (req, res) => {
  // Clear the token cookie
  res.clearCookie('token', {
    path: '/',
    httpOnly: true,
  });

  res.json({ message: 'User logged out successfully.' });
};

export const forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Generate a reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpire = Date.now() + 3600000; // Token expires in 1 hour
    await user.save();

    // Send email
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: emailUserName,
        pass: emailPassword,
      },
    });

    const mailOptions = {
      from: emailUserName,
      to: user.email,
      subject: 'Password Reset',
      html: `You requested a password reset. Click the following link to reset your password: <a href="http:localhost:3000/reset-password/${resetToken}" target="_blank">Reset Password</a>`,
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Password reset email sent' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const resetPassword = async (req, res) => {
  const { token, newPassword, confirmPassword } = req.body;

  try {
    // Check if passwords match
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: 'Passwords do not match' });
    }

    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user)
      return res.status(400).json({ message: 'Invalid or expired token' });

    // Hash new password and save
    user.password = await bcrypt.hash(newPassword, 12);
    user.resetPasswordToken = undefined; // Clear token
    user.resetPasswordExpire = undefined; // Clear expiry
    await user.save();

    res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const sendSMSOTP = async (req, res) => {
  const { phoneNumber } = req.body;
  const otp = generateOtp();

  try {
    await client.messages.create({
      body: `Your OTP code is ${otp}`,
      from: '+13037474559', // Replace with your Twilio phone number
      to: phoneNumber,
    });

    // Here, save the OTP and phoneNumber in your database with an expiry time
    // This example assumes you have a simple in-memory store (replace with your database logic)
    otpStore[phoneNumber] = otp;

    res.status(200).json({ message: 'OTP sent successfully' });
  } catch (error) {
    res.status(500).send({
      message: "'Error sending OTP'",
      error: error.message,
    });
  }
};

export const verifyOTP = async (req, res) => {
  const { phoneNumber, otp } = req.body;

  if (otpStore[phoneNumber] === otp) {
    delete otpStore[phoneNumber]; // Remove OTP after successful verification
    res.status(200).send('OTP verified successfully');
  } else {
    res.status(400).send('Invalid OTP');
  }
};

export const getSingleUser = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }
    res.json(user);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};
