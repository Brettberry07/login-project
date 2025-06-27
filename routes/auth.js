// routes/auth.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt    = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const db       = require('../utils/db_utils');
const { SECRET } = require('../utils/config');
const ApiError = require('../utils/api_error');
const { logger } = require('../utils/logger');

const router = express.Router();

// Create account
router.post(
  '/create',
  [
    body('email').isEmail().withMessage('Invalid email format'),
    body('password')
      .isLength({ min: 6 })
      .withMessage('Password must be at least 6 characters long'),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation failed on user create', { errors: errors.array() });
      return next(new ApiError(400, 'Invalid email or password'));
    }

    try {
      const { email, password } = req.body;
      const hashed = await bcrypt.hash(password, 10);
      db.run(
        'INSERT INTO users (email, password) VALUES (?, ?)',
        [email, hashed],
        function (err) {
          if (err) {
            logger.error('DB error inserting user', { message: err.message });
            return next(new ApiError(500, 'Could not create user'));
          }
          logger.info('User created', { userId: this.lastID });
          res.status(201).json({ userId: this.lastID });
        }
      );
    } catch (err) {
      next(err);
    }
  }
);

// Login
router.post(
  '/login',
  [
    body('email').isEmail().withMessage('Invalid email format'),
    body('password')
      .isLength({ min: 6 })
      .withMessage('Password must be at least 6 characters long'),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation failed on login', { errors: errors.array() });
      return next(new ApiError(400, 'Invalid email or password'));
    }

    try {
      const { email, password } = req.body;
      db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) {
          logger.error('DB error fetching user', { message: err.message });
          return next(new ApiError(500, 'Login failed'));
        }
        if (!user) {
          return next(new ApiError(401, 'Invalid email or password'));
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
          return next(new ApiError(401, 'Invalid email or password'));
        }

        const token = jwt.sign(
          { userId: user.id, email: user.email },
          SECRET,
          { expiresIn: '1h' }
        );
        res.cookie('token', token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 3600000,
        });

        logger.info('User logged in', { email, userId: user.id });
        res.json({ message: 'Logged in' });
      });
    } catch (err) {
      next(err);
    }
  }
);

// Logout
router.post('/logout', (req, res, next) => {
  try {
    res.clearCookie('token');
    logger.info('User logged out');
    res.json({ message: 'Logged out' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
