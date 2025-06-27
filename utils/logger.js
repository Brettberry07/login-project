// logger.js
const winston = require('winston');
const morgan  = require('morgan');
const fs      = require('fs');
const path    = require('path');

// 1) Ensure logs directory exists
const logDir = path.join(__dirname, '..', 'logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir);
}

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ 
      filename: path.join(logDir, 'error.log'), 
      level: 'error' 
    }),
    new winston.transports.File({ 
      filename: path.join(logDir, 'combinend.log'), 
    }),
  ]
});

// export Morgan middleware too
const httpLogger = morgan('combined');

module.exports = { logger, httpLogger };
