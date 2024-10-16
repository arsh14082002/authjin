import express from 'express';
import {
  registerUser,
  loginUser,
  logoutUser,
  getSingleUser,
  forgotPassword,
  resetPassword,
  sendSMSOTP,
  verifyOTP,
} from '../controllers/userController.js';
import authMiddleware from '../middlewares/authMiddleware.js';

const router = express.Router();

router.post('/register', registerUser);
router.post('/login', loginUser);
router.post('/logout', authMiddleware, logoutUser);
router.post('/forgot-password', authMiddleware, forgotPassword);
router.post('/reset-password', authMiddleware, resetPassword);
router.post('/send-otp', sendSMSOTP);
router.post('/verify-otp', verifyOTP);
router.get('/:id', authMiddleware, getSingleUser);

export default router;
