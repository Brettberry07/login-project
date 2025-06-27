// middleware/auth.js
const jwt = require('jsonwebtoken');
const { SECRET } = require('./config');
const db = require('./db_utils');
const ApiError = require('./api_error');
const { logger } = require('./logger');

function authenticateToken(req, res, next) {
  const token = req.cookies?.token;
  if (!token) {
    return next(new ApiError(401, 'Authentication token required'));
  }

  // Step 1: Check blacklist
  db.get(
    'SELECT 1 FROM blacklisted_tokens WHERE token = ?',
    [token],
    (err, row) => {
      if (err) {
        logger.error('Error checking blacklist', { message: err.message });
        return next(new ApiError(500, 'Internal server error'));
      }
      if (row) {
        logger.warn('Attempt to use blacklisted token');
        return next(new ApiError(403, 'Logged out'));
      }

      // Step 2: Verify JWT
      jwt.verify(token, SECRET, (err, user) => {
        if (err) {
          logger.error('JWT verification failed', { message: err.message });
          return next(new ApiError(403, 'Invalid or expired token'));
        }

        req.user = user;
        logger.info('Token verified', { userId: user.userId });
        next();
      });
    }
  );
}

module.exports = { authenticateToken };
