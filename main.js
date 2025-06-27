const express          = require('express');
const cookieParser     = require('cookie-parser');
const rateLimit        = require('express-rate-limit');

const { PORT } = require('./utils/config');
const { logger, httpLogger } = require('./utils/logger');
const authRoutes    = require('./routes/auth');
const userRoutes    = require('./routes/users');

const app = express();

// --- global middleware ---
app.use(express.static('public'));
app.use(cookieParser());
app.use(express.json());
app.use(httpLogger);
app.use(rateLimit({ windowMs:15*60e3, max:100, message:"To many requests, try again later"})); // 15 minutes, 100 requests

// Mount Routes
app.use('/users', authRoutes);  // signup/login/logout under /users/*
app.use('/', userRoutes);       // /data


// Centralized error handler middleware
app.use((err, req, res, next) => {
  logger.error(`[${req.method}] ${req.url} → ${err.message}`);
  console.error(err.stack); // optional for dev

  const status = err.status || 500;
  const message = err.message || 'Internal Server Error';

  res.status(status).json({ error: message });
});

app.listen(PORT, () => {
  logger.info(`App listening on port ${PORT}`);
})



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


