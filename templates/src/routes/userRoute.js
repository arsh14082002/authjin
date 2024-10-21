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
  verifyEmail
} from '../controllers/userController.js';
import authMiddleware from '../middlewares/authMiddleware.js';

const router = express.Router();

router.post('/register', registerUser); //done
router.post('/login', loginUser); //done
router.post('/verify-email', verifyEmail); // done
router.post('/logout', authMiddleware, logoutUser); //done
router.post('/forgot-password', authMiddleware, forgotPassword); //done
router.post('/reset-password', authMiddleware, resetPassword); //done
router.post('/send-otp', sendSMSOTP); // done
router.post('/verify-otp', verifyOTP); // done
router.get('/:id', authMiddleware, getSingleUser);

export default router;

