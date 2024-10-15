import jwt from 'jsonwebtoken';

const your_jwt_secret = process.env.JWT_SECRET || 'your_jwt_secret';

const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, your_jwt_secret);
    req.user = decoded; // Assuming you attach user data to req.user
    next();
  } catch (error) {
    res.status(400).json({ message: 'Invalid token.' });
  }
};

export default authMiddleware;
