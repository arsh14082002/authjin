import jwt from 'jsonwebtoken';
import User from '../models/userModel.js';
import apiConfig from '../config/apiConfig.js';

const your_jwt_secret = apiConfig.jwtSecret;

export const authMiddleware = async (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  console.log(token)

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, your_jwt_secret);
    req.userId = decoded.userId;

    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (!user.isVerified) {
      return res.status(403).json({ message: 'Please verify your email first' });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('JWT Verification Error:', error.message); // Log error message
    res.status(403).json({ message: 'Invalid token',error:error.message });
  }
};

export default authMiddleware;

