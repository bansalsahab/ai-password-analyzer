const express = require('express');
const router = express.Router();
const {
  authUser,
  registerUser,
  getUserProfile,
  updateUserProfile,
  addPasswordToHistory,
  getPasswordHistory,
} = require('../controllers/userController');
const { protect } = require('../middleware/authMiddleware');

// Public routes
router.post('/login', authUser);
router.post('/', registerUser);

// Protected routes
router.route('/profile')
  .get(protect, getUserProfile)
  .put(protect, updateUserProfile);

router.route('/password-history')
  .get(protect, getPasswordHistory)
  .post(protect, addPasswordToHistory);

module.exports = router; 