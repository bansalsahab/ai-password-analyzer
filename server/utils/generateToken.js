const jwt = require('jsonwebtoken');

/**
 * Generate JWT for authenticated users
 * @param {string} id - User ID to encode in the token
 * @returns {string} - JWT token
 */
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: '30d',
  });
};

module.exports = generateToken; 