import bcrypt from 'bcrypt';
import User from '../models/userModel.js';
import { z } from 'zod';

const your_jwt_secret = process.env.JWT_SECRET || 'your_jwt_secret';

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

    const newUser = new User({ username, email, password: hashedPassword, mobile });
    await newUser.save();

    // Generate JWT token
    const token = jwt.sign({ userId: newUser._id }, your_jwt_token, {
      expiresIn: '1h',
    });

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
      $or: [{ username: identifier }, { email: identifier }, { mobile: identifier }],
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
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'your_jwt_secret', {
      expiresIn: '1h',
    });

    res.json({ token });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.errors });
    }
    res.status(400).json({ message: error.message });
  }
};

export const logoutUser = (req, res) => {
  res.json({ message: 'User logged out successfully.' });
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
