const express = require('express');
const router = express.Router();
const {
  analyzePassword,
  getPasswordHistory,
} = require('../controllers/passwordController');
const { protect } = require('../middleware/authMiddleware');

// Public route for password analysis
router.post('/analyze', analyzePassword);

// Protected route for password history
router.get('/history', protect, getPasswordHistory);

module.exports = router; 