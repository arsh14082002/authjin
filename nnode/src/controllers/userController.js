import bcrypt from 'bcrypt';
import { z } from 'zod';
import nodemailer from 'nodemailer';
import apiConfig from '../config/apiConfig.js';
import User from '../models/User.js';
import jwt from 'jsonwebtoken';

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

    const [existingUser] = await db.execute(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );

    if (existingUser.length > 0) {
      return res.status(400).json({ message: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const emailVerificationToken = generateOtp();

    await db.execute(
      'INSERT INTO users (username, email, password, mobile, emailVerificationToken) VALUES (?, ?, ?, ?, ?)',
      [username, email, hashedPassword, mobile, emailVerificationToken]
    );

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
        ',</p><p>Your verification code is: <b>' +
        emailVerificationToken +
        '</b></p><p>Please use this code to verify your email and activate your account.</p>',
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

    const [userRows] = await db.execute(
      'SELECT * FROM users WHERE username = ? OR email = ? OR mobile = ?',
      [
        emailOrUsernameOrMobile,
        emailOrUsernameOrMobile,
        emailOrUsernameOrMobile,
      ]
    );

    const user = userRows[0];
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    const token = jwt.sign({ userId: user.id }, your_jwt_secret, {
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
