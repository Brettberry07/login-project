const express = require('express')
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const winston = require('winston');
// Setup logging with winston
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' })
    ]
});

const morgan = require('morgan');
// Setup morgan for HTTP request logging

require('dotenv').config(); // Load environment variables from .env file

const app = express()

app.use(express.static('public')); // Serving the frontend page
app.use(cookieParser()); // Middleware to parse cookies
app.use(express.json()); // Middleware to parse JSON bodies
app.use(morgan('combined')); // Use morgan for logging HTTP requests

// limimt the bumber of requests to 100 per 15 minutes
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests, please try again later.' ,
})

app.use(limiter); // Apply the rate limiting middleware to all requests



// loading consts from .env
const PORT = process.env.PORT || 3000; // Default to 3000 if PORT is not set
const DB_PATH = process.env.DB_PATH || './data.db'; // Default to './data.db' if DB_PATH is not set
const SECRET = process.env.SECRET

const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error('Could not connect to database', err);
    } else {
        console.log('Connected to SQLite database');
    }
});

// Create the table for users if it doesn't exist
// id | email | encrypted password
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)`);

// Create the table for blacklisted tokens if it doesn't exist
// token | expires_at
db.run(`
  CREATE TABLE IF NOT EXISTS blacklisted_tokens (
    token TEXT PRIMARY KEY,
    expires_at INTEGER
  )
`);

app.get('/', (req, res) => {
  res.send('Hello World!')
})

app.listen(PORT, () => {
  logger.info(`Example app listening on port ${PORT}`);
  console.log(`Example app listening on port ${PORT}`)
})

// Create a new user with JOSN!
// more standard, more secure, and better practice
// adding validation now
app.post('/users/create', 
  [
    body('email').isEmail().withMessage('Invalid email format'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
  ],
  async (req, res) => {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        logger.error('Email or password validation error for create user');
        console.error('Email or password validation error for create user');

        return res.status(400).json({ errors: errors.array() });
    }
    

    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10); // Hash the password before storing it
    const sql = 'INSERT INTO users (email, password) VALUES (?, ?)';
    db.run(sql, [email, hashedPassword], function(err) {
        if (err) {
            logger.error('Error inserting user:', err.message);
            console.error('Error inserting user:', err.message);
            res.status(500).send('Error creating user');
        } else {
            logger.info(`User created with ID: ${this.lastID}`);
            console.log(`User created with ID: ${this.lastID}`);
            res.status(201).send(`User created with ID: ${this.lastID}`);
        }
    })
})

// login as a user (/login {email, password})
app.post('/login',
  [
    body('email').isEmail().withMessage('Invalid email format'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
  ],
  async (req, res) => {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        logger.error('Email or password validation error for log in');
        console.error('Email or password validation error for log in');
        return res.status(400).json({ errors: errors.array() });
    }
    
    const { email, password } = req.body;
    const sql = 'SELECT * FROM users WHERE email = ?';
    db.get(sql, [email], async (err, user) => {
        if (err || !user) {
            logger.error('Error fetching user or user not found:', err ? err.message : 'User not found');
            console.error('Error fetching user or user not found:', err ? err.message : 'User not found');
            return res.status(401).send('Invalid email or password');
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            logger.error('Invalid password for user:', email);
            console.error('Invalid password for user:', email);
            return res.status(401).send('Invalid email or password');
        }

        // Generate JWT
        const token = jwt.sign(
            { userId: user.id, email: user.email },
            SECRET,
            { expiresIn: '1h' }
        );

        // Set the token in a cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', // true on HTTPS only
            sameSite: 'strict', // or 'lax' depending on needs
            maxAge: 3600000, // 1 hour in ms
        });

        logger.info(`User ${email} logged in successfully`);
        console.log(`User ${email} logged in successfully`);
        res.json({ message: 'Logged in, stored token in cookie' });
    });
});

// logout the current user (/logout (cookie)) | Cookie based, just clear cookie
app.post('/logout', (req, res) => {
  res.clearCookie('token');
  logger.info('User logged out, cookie cleared');
  console.log('User logged out, cookie cleared');
  res.send('Logged out');

});

// get the users data (pulldata {jwt} )
app.get('/users/data', authenticateToken, (req, res) => {
    res.send(`User ID: ${req.user.userId}, Email: ${req.user.email}`);
    logger.info(`User data accessed for user ID: ${req.user.userId}`);
    console.log(`User data accessed for user ID: ${req.user.userId}`);
})

// middleware authentication function
function authenticateToken(req, res, next) {
  const token = req.cookies.token
  if (!token) return res.status(401).send('Token required');

  // Step 1: Check if token is blacklisted
  db.get('SELECT 1 FROM blacklisted_tokens WHERE token = ?', [token], (err, row) => {
    if (err) {
      logger.error('Error checking blacklist:', err.message);
      console.error('Error checking blacklist:', err.message);
      return res.status(500).send('Server error');
    }

    if (row) {
      logger.warn('Token has been logged out:', token);
      console.warn('Token has been logged out:', token);
      return res.status(403).send('Token has been logged out');
    }

    // Step 2: Verify token normally
    jwt.verify(token, SECRET, (err, user) => {
      if (err) {
        logger.error('Invalid or expired token:', err.message);
        console.error('Invalid or expired token:', err.message);
        return res.status(403).send('Invalid or expired token');
      }

      req.user = user;
      logger.info(`Token verified for user ID: ${user.userId}`);
      console.log(`Token verified for user ID: ${user.userId}`);
      next();
    });
  });
}


// creating a new user
// This obvsly not secure at all and bad practice lol
// app.post('/users/create/:email/:password', (req, res) => {
//     const { email, password } = req.params
//     const sql = 'INSERT INTO users (email, password) VALUES (?, ?)';
//     db.run(sql, [email, password], function(err) {
//         if (err) {
//             console.error('Error inserting user:', err.message);
//             res.status(500).send('Error creating user');
//         } else {
//             console.log(`User created with ID: ${this.lastID}`);
//             res.status(201).send(`User created with ID: ${this.lastID}`);
//         }
//     })
// })

// // logour of the current user (/logout {jwt}) | Blacklisting the token
// app.post('/logout', authenticateToken, (req, res) => {
//   const authHeader = req.headers['authorization'];
//   const token = authHeader && authHeader.split(' ')[1];

//   if (!token) return res.status(400).send('No token provided');

//   // Decode token to get expiration
//   const decoded = jwt.decode(token);
//   const expiresAt = decoded.exp;

//   const sql = 'INSERT INTO blacklisted_tokens (token, expires_at) VALUES (?, ?)';
//   db.run(sql, [token, expiresAt], function (err) {
//     if (err) {
//       console.error('Failed to blacklist token:', err.message);
//       return res.status(500).send('Could not log out');
//     }

//     res.send('Successfully logged out');
//   });
// });

// // Route parameters
// app.get('/users/:userId/books/:bookId', (req, res) => {
// //   res.send(req.params) // Returns an object with userId and bookId
//     res.send(`User ID: ${req.params.userId}, Book ID: ${req.params.bookId}`)
// })


