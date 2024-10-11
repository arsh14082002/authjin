import express from 'express';
import {
  registerUser,
  loginUser,
  logoutUser,
  getSingleUser,
} from '../controllers/userController.js';
import authMiddleware from '../middlewares/authMiddleware.js';

const router = express.Router();

router.post('/register', registerUser);
router.post('/login', loginUser);
router.post('/logout', authMiddleware, logoutUser);
router.get('/:id', authMiddleware, getSingleUser);

export default router;
