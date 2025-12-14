const Database = require('better-sqlite3');
const path = require('path');

// Define the database file path
const dbPath = path.join(__dirname, 'forum.db');

// Create a new database connection
const db = new Database(dbPath, { verbose: console.log });

// Enable foreign keys
db.pragma('foreign_keys = ON');

// Error handling wrapper
function initDb() {
  try {
    // Begin a transaction for schema creation
    const stmt = db.prepare('BEGIN');
    stmt.run();

    // users Table
    db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL, -- Hashed password
        email TEXT UNIQUE NOT NULL,
        display_name TEXT NOT NULL,
        profile_customization TEXT, -- JSON string for customization
        failed_login_attempts INTEGER DEFAULT 0,
        lockout_until DATETIME
      )
    `);

    // sessions Table
    // This is a generic schema based on the request
    db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY,
        user_id INTEGER,
        data TEXT,
        expires DATETIME,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // comments Table
    db.exec(`
      CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        text TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // login_attempts Table
    db.exec(`
      CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        ip_address TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        success INTEGER -- 1 for success, 0 for failure
      )
    `);

    // commit the transaction
    db.prepare('COMMIT').run();
    console.log('Database schema initialized successfully.');

  } catch (err) {
    // rollback in case of error
    db.prepare('ROLLBACK').run();
    console.error('Error initializing database schema:', err);
    throw err;
  }
}

// initialize the database
initDb();

module.exports = db;
