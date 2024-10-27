export const createMongoController = () => {
  `
  import bcrypt from 'bcrypt';
import { z } from 'zod';
import nodemailer from 'nodemailer';
// import generateOtp from '../utils/generateOtp.js';
import apiConfig from '../config/apiConfig.js';
import User from '../models/User.js';
import jwt from 'jsonwebtoken'; // Make sure you import jwt

const your_jwt_secret = apiConfig.jwtSecret;
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
      html: "<p>Welcome " + username + ",</p><p>Your verification code is:" + generateOtp()+"</b></p><p>Please use this code to verify your email and activate your account.</p>", // Corrected backticks
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
      html: "You requested a password reset. Click the following link to reset your password:"+ generateOtp()
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
      body: "Your OTP code is " + generateOtp(),
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

  `;
};
