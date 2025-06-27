// routes/users.js
const express = require('express');
const { authenticateToken } = require('../utils/auth_middleware');
const { logger } = require('../utils/logger');
const router = express.Router();

// Protected: get user data
router.get('/data', authenticateToken, (req, res, next) => {
  try {
    logger.info('User data accessed', { userId: req.user.userId });
    res.json({ userId: req.user.userId, email: req.user.email });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
