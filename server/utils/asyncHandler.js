/**
 * Express async handler utility to handle exceptions in async/await functions
 * This eliminates the need for try/catch blocks in route controllers
 * 
 * @param {Function} fn - Async function to wrap
 * @returns {Function} - Middleware function with error handling
 */
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

module.exports = asyncHandler; 