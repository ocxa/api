// scripts/init-db.js
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');

// Path to the data directory, relative to the project root
const dataDir = path.join(__dirname, '..', 'data');

// Ensure the data directory exists
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
  console.log('✓ Created data directory');
}

const dbPath = path.join(dataDir, 'database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database', err.message);
  } else {
    console.log('✓ Connected to the SQLite database.');
  }
});


db.serialize(async () => {
  try {
    // Enable foreign keys
    db.run('PRAGMA foreign_keys = ON');

    // Create users table
    db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      is_admin INTEGER DEFAULT 0,
      is_blocked INTEGER DEFAULT 0,
      can_post INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login DATETIME,
      ip_address TEXT
    )`);

    // Create invite codes table
    db.run(`
    CREATE TABLE IF NOT EXISTS invite_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE NOT NULL,
      created_by INTEGER,
      used_by INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      used_at DATETIME,
      is_used INTEGER DEFAULT 0,
      FOREIGN KEY (created_by) REFERENCES users(id),
                                             FOREIGN KEY (used_by) REFERENCES users(id)
    )`);

    // Create API keys table
    db.run(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER UNIQUE NOT NULL,
      key_hash TEXT NOT NULL,
      key_preview TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_used DATETIME,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // Create shortened URLs table
    db.run(`
    CREATE TABLE IF NOT EXISTS urls (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      short_code TEXT UNIQUE NOT NULL,
      original_url TEXT NOT NULL,
      user_id INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME,
      clicks INTEGER DEFAULT 0,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // Create blocked IPs table
    db.run(`
    CREATE TABLE IF NOT EXISTS blocked_ips (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip_address TEXT UNIQUE NOT NULL,
      blocked_by INTEGER,
      blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      reason TEXT,
      FOREIGN KEY (blocked_by) REFERENCES users(id)
    )`);

    // Create sessions table (managed by connect-sqlite3)
    // No need to create it here as the library handles it.

    console.log('✓ All tables created or already exist.');

    // Create default admin user
    const adminPassword = await bcrypt.hash('admin', 10);

    const adminInsert = `
    INSERT OR IGNORE INTO users (username, password_hash, is_admin)
    VALUES ('admin', ?, 1)`;

    db.run(adminInsert, [adminPassword], function(err) {
      if (err) {
        return console.error('Error creating admin user:', err.message);
      }
      if (this.changes > 0) {
        console.log('✓ Default admin account created (username: admin, password: admin)');
        console.log('✓ Please change the default admin password after first login');
      } else {
        console.log('✓ Admin user already exists.');
      }
    });

  } catch (error) {
    console.error('Error initializing database:', error);
  } finally {
    // Close database connection
    db.close((err) => {
      if (err) {
        console.error('Error closing database:', err.message);
      } else {
        console.log('✓ Database initialization complete. Connection closed.');
      }
    });
  }
});
