import bcrypt from 'bcrypt';
import User from '../models/userModel.js';
import { z } from 'zod';
import nodemailer from 'nodemailer';
import twilio from 'twilio';
import apiConfig from '../config/apiConfig.js';

const your_jwt_secret = apiConfig.jwtSecret;
const emailUserName = apiConfig.emailUserName;
const emailPassword = apiConfig.emailPassword;
const accountSid = apiConfig.accountSid;
const authToken = apiConfig.authToken;
const client = new twilio(accountSid, authToken);

const generateOtp = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

export const registerUser = async (req, res) => {
  // Zod schema defined inside the controller
  const userValidationSchema = z.object({
    username: z.string().min(1, 'Username is required'),
    email: z.string().email('Invalid email address'),
    password: z.string().min(6, 'Password must be at least 6 characters long'),
    mobile: z.string().optional(),
  });

  try {
    // Validate request body using the Zod schema
    const validatedData = userValidationSchema.parse(req.body);

    const { username, email, password, mobile } = validatedData;
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      mobile,
    });
    await newUser.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: newUser._id },
      process.env.SECRET_TOKEN || your_jwt_secret,
      {
        expiresIn: '1h',
      }
    );

    res.status(201).json({ message: 'User registered successfully.' });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.errors });
    }
    res.status(400).json({ message: error.message });
  }
};

export const loginUser = async (req, res) => {
  // Zod schema defined inside the controller
  const loginValidationSchema = z.object({
    identifier: z.string().min(1, 'Username, email, or mobile is required'), // Can be username, email, or mobile
    password: z.string().min(6, 'Password must be at least 6 characters long'),
  });

  try {
    // Validate request body using the Zod schema
    const validatedData = loginValidationSchema.parse(req.body);

    const { identifier, password } = validatedData;

    // Find user by username, email, or mobile
    const user = await User.findOne({
      $or: [
        { username: identifier },
        { email: identifier },
        { mobile: identifier },
      ],
    });

    // If user is not found, return error
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    // Compare the password with the stored hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id },
      process.env.SECRET_TOKEN || your_jwt_secret,
      {
        expiresIn: '1h',
      }
    );

    res.json({ token });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.errors });
    }
    res.status(400).json({ message: error.message });
  }
};

export const logoutUser = async (req, res) => {
  res.json({ message: 'User logged out successfully.' });
};

export const forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Generate a reset token
    const resetToken = crypto.randomBytes(32).toString('hex'); // Increased byte size for better security
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
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Password Reset',
      html: `You requested a password reset. Click the following link to reset your password: <a href="${process.env.FRONTEND_URL}/reset-password/${resetToken}" target="_blank">Reset Password</a>`,
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
      from: '+19388676282', // Replace with your Twilio phone number
      to: phoneNumber,
    });

    // Here, save the OTP and phoneNumber in your database with an expiry time
    // This example assumes you have a simple in-memory store (replace with your database logic)
    otpStore[phoneNumber] = otp;

    res.status(200).send('OTP sent successfully');
  } catch (error) {
    res.status(500).send('Error sending OTP');
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
