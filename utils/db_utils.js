// db.js
const sqlite3 = require('sqlite3').verbose();
const { DB_PATH } = require('./config');

const db = new sqlite3.Database(DB_PATH, err => {
  if (err) console.error('DB connection error:', err);
  else     console.log('Connected to SQLite');
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

module.exports = db;
