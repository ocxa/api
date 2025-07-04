const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// --- DATABASE SETUP ---
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)){
  fs.mkdirSync(dataDir, { recursive: true });
}
const dbPath = path.join(dataDir, 'database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error("Error opening database:", err);
});
db.run('PRAGMA foreign_keys = ON');

// --- MIDDLEWARE ---
// Security
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      ...helmet.contentSecurityPolicy.getDefaultDirectives(),
               "script-src": ["'self'"], // Only allow scripts from own domain
               "img-src": ["'self'", "data:", "https:", "https://*.gravatar.com"], // Allow gravatar
    },
  },
}));
app.use(cors());

// Body Parsers
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Session Management
app.use(session({
  store: new SQLiteStore({ 
      db: 'sessions.sqlite', // The name of the session db file
      dir: dataDir             // The directory to store it in (your ./data folder)
  }),
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax', // Better for security
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Rate Limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: 'Too many requests, please try again later' }
});
app.use('/api/', apiLimiter);

// --- UTILITY & AUTH MIDDLEWARE ---
function generateCode(length = 6) { return crypto.randomBytes(length).toString('hex').substring(0, length); }
function generateApiKey() { return 'evade_' + crypto.randomBytes(32).toString('hex'); }
function isValidUrl(string) { try { new URL(string); return true; } catch (_) { return false; } }

function requireAuth(req, res, next) {
  db.get('SELECT * FROM users WHERE id = ?', [req.session.userId], (err, user) => {
    if (err || !user || user.is_blocked) {
      req.session.destroy();
      return res.status(401).json({ error: 'Authentication required or account blocked.' });
    }
    req.user = user;
    next();
  });
}

function requireAdmin(req, res, next) {
  if (!req.user || !req.user.is_admin) {
    return res.status(403).json({ error: 'Admin privileges required' });
  }
  next();
}

function requireApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: 'API key required' });

  const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');
  db.get('SELECT u.* FROM api_keys ak JOIN users u ON ak.user_id = u.id WHERE ak.key_hash = ?', [keyHash], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid API key' });
    if (user.is_blocked || !user.can_post) return res.status(403).json({ error: 'This account is blocked or cannot post.' });

    req.apiUser = user;
    db.run('UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE key_hash = ?', [keyHash]);
    next();
  });
}


// Health Check for Docker
app.get('/health', (req, res) => res.status(200).send('OK'));

// Get current session status
app.get('/api/auth/session', (req, res) => {
  if (req.session.userId) {
    db.get('SELECT id, username, is_admin FROM users WHERE id = ?', [req.session.userId], (err, user) => {
      if (err || !user) return res.json({ loggedIn: false });
      res.json({ loggedIn: true, user });
    });
  } else {
    res.json({ loggedIn: false });
  }
});


// AUTH ROUTES
app.post('/api/auth/register', (req, res) => {
  const { username, password, inviteCode } = req.body;
  
  if (!username || !password || !inviteCode) {
    return res.status(400).json({ error: 'Username, password, and invite code are required' });
  }
  
  // Check invite code
  db.get('SELECT * FROM invite_codes WHERE code = ? AND is_used = 0', [inviteCode], async (err, invite) => {
    if (err || !invite) {
      return res.status(400).json({ error: 'Invalid or expired invite code' });
    }
    
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const clientIp = req.ip;
      
      db.run('INSERT INTO users (username, password_hash, ip_address) VALUES (?, ?, ?)', 
        [username, hashedPassword, clientIp], function(err) {
        if (err) {
          if (err.code === 'SQLITE_CONSTRAINT') {
            return res.status(400).json({ error: 'Username already exists' });
          }
          return res.status(500).json({ error: 'Registration failed' });
        }
        
        const userId = this.lastID;
        
        // Mark invite code as used
        db.run('UPDATE invite_codes SET is_used = 1, used_by = ?, used_at = CURRENT_TIMESTAMP WHERE code = ?', 
          [userId, inviteCode], (err) => {
          if (err) {
            console.error('Error updating invite code:', err);
          }
        });
        
        res.json({ message: 'Registration successful' });
      });
    } catch (error) {
      res.status(500).json({ error: 'Registration failed' });
    }
  });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err || !user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    if (user.is_blocked) {
      return res.status(403).json({ error: 'Account is blocked' });
    }
    
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Update last login and IP
    const clientIp = req.ip || req.connection.remoteAddress;
    db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP, ip_address = ? WHERE id = ?', 
      [clientIp, user.id]);
    
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.isAdmin = user.is_admin;
    
    res.json({ 
      message: 'Login successful',
      user: {
        id: user.id,
        username: user.username,
        isAdmin: user.is_admin
      }
    });
  });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ message: 'Logout successful' });
  });
});

// API KEY ROUTES
app.post('/api/keys/generate', requireAuth, (req, res) => {
  const apiKey = generateApiKey();
  const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');
  const keyPreview = apiKey.substring(0, 8) + '...';
  
  // Delete existing API key for user
  db.run('DELETE FROM api_keys WHERE user_id = ?', [req.session.userId], (err) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to generate API key' });
    }
    
    // Insert new API key
    db.run('INSERT INTO api_keys (user_id, key_hash, key_preview) VALUES (?, ?, ?)',
      [req.session.userId, keyHash, keyPreview], function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to generate API key' });
      }
      
      res.json({ 
        message: 'API key generated successfully',
        apiKey: apiKey,
        preview: keyPreview
      });
    });
  });
});

app.get('/api/keys/info', requireAuth, (req, res) => {
  db.get('SELECT key_preview, created_at, last_used FROM api_keys WHERE user_id = ?', 
    [req.session.userId], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch API key info' });
    }
    
    res.json(row || { message: 'No API key found' });
  });
});

app.delete('/api/keys/:userId', requireAdmin, (req, res) => {
  const { userId } = req.params;
  
  db.run('DELETE FROM api_keys WHERE user_id = ?', [userId], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to delete API key' });
    }
    
    res.json({ message: 'API key deleted successfully', deletedCount: this.changes });
  });
});

// URL SHORTENER ROUTES
app.post('/api/shorten', requireApiKey, (req, res) => {
  const { url, expiresIn } = req.body;
  
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }
  
  // Check if user can post
  db.get('SELECT can_post FROM users WHERE id = ?', [req.apiUserId], (err, user) => {
    if (err || !user || !user.can_post) {
      return res.status(403).json({ error: 'URL shortening is disabled for your account' });
    }
    
    // Add protocol if missing
    let fullUrl = url;
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      fullUrl = 'https://' + url;
    }
    
    if (!isValidUrl(fullUrl)) {
      return res.status(400).json({ error: 'Invalid URL format' });
    }
    
    let expiresAt = null;
    if (expiresIn) {
      const minutes = parseInt(expiresIn);
      if (minutes >= 1 && minutes <= 10080) { // 1 minute to 7 days
        expiresAt = new Date(Date.now() + minutes * 60 * 1000).toISOString();
      }
    }
    
    // Check if URL already exists for this user
    db.get('SELECT * FROM urls WHERE original_url = ? AND user_id = ?', [fullUrl, req.apiUserId], (err, existing) => {
      if (existing) {
        return res.json({
          id: existing.id,
          originalUrl: existing.original_url,
          shortUrl: `${req.protocol}://${req.get('host')}/r/${existing.short_code}`,
          shortCode: existing.short_code,
          expiresAt: existing.expires_at
        });
      }
      
      let shortCode;
      function tryInsert() {
        shortCode = generateCode();
        
        db.run('INSERT INTO urls (short_code, original_url, user_id, expires_at) VALUES (?, ?, ?, ?)',
          [shortCode, fullUrl, req.apiUserId, expiresAt], function(err) {
          if (err) {
            if (err.code === 'SQLITE_CONSTRAINT') {
              return tryInsert(); // Try again with new code
            }
            return res.status(500).json({ error: 'Failed to create short URL' });
          }
          
          res.json({
            id: this.lastID,
            originalUrl: fullUrl,
            shortUrl: `${req.protocol}://${req.get('host')}/r/${shortCode}`,
            shortCode: shortCode,
            expiresAt: expiresAt
          });
        });
      }
      
      tryInsert();
    });
  });
});

app.get('/api/urls', requireAuth, (req, res) => {
  db.all('SELECT id, short_code, original_url, created_at, expires_at, clicks FROM urls WHERE user_id = ? ORDER BY created_at DESC',
    [req.session.userId], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch URLs' });
    }
    
    res.json(rows);
  });
});

app.get('/r/:shortCode', (req, res) => {
  const { shortCode } = req.params;
  
  db.get('SELECT * FROM urls WHERE short_code = ?', [shortCode], (err, url) => {
    if (err || !url) {
      return res.status(404).json({ error: 'Short URL not found' });
    }
    
    // Check if expired
    if (url.expires_at && new Date() > new Date(url.expires_at)) {
      return res.status(410).json({ error: 'Short URL has expired' });
    }
    
    // Increment click count
    db.run('UPDATE urls SET clicks = clicks + 1 WHERE id = ?', [url.id]);
    
    res.redirect(url.original_url);
  });
});

app.delete('/api/urls/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  
  db.run('DELETE FROM urls WHERE id = ? AND user_id = ?', [id, req.session.userId], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to delete URL' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'URL not found' });
    }
    
    res.json({ message: 'URL deleted successfully' });
  });
});

app.put('/api/urls/:id/expiry', requireAuth, (req, res) => {
  const { id } = req.params;
  const { expiresIn } = req.body;
  
  let expiresAt = null;
  if (expiresIn) {
    const minutes = parseInt(expiresIn);
    if (minutes >= 1 && minutes <= 10080) { // 1 minute to 7 days
      expiresAt = new Date(Date.now() + minutes * 60 * 1000).toISOString();
    } else {
      return res.status(400).json({ error: 'Expiry must be between 1 minute and 7 days' });
    }
  }
  
  db.run('UPDATE urls SET expires_at = ? WHERE id = ? AND user_id = ?', 
    [expiresAt, id, req.session.userId], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to update expiry' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'URL not found' });
    }
    
    res.json({ message: 'Expiry updated successfully', expiresAt });
  });
});

// USER MANAGEMENT ROUTES
app.post('/api/user/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current password and new password are required' });
  }
  
  db.get('SELECT password_hash FROM users WHERE id = ?', [req.session.userId], async (err, user) => {
    if (err || !user) {
      return res.status(500).json({ error: 'Failed to change password' });
    }
    
    const isValidPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!isValidPassword) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    db.run('UPDATE users SET password_hash = ? WHERE id = ?', [hashedPassword, req.session.userId], (err) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to change password' });
      }
      
      res.json({ message: 'Password changed successfully' });
    });
  });
});

// ADMIN ROUTES
app.post('/api/admin/invite-codes', requireAdmin, (req, res) => {
  const inviteCode = generateCode(12);
  
  db.run('INSERT INTO invite_codes (code, created_by) VALUES (?, ?)', 
    [inviteCode, req.session.userId], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to create invite code' });
    }
    
    res.json({ 
      message: 'Invite code created successfully',
      code: inviteCode,
      id: this.lastID
    });
  });
});

app.get('/api/admin/invite-codes', requireAdmin, (req, res) => {
  db.all(`SELECT ic.*, u.username as created_by_username, u2.username as used_by_username 
          FROM invite_codes ic 
          LEFT JOIN users u ON ic.created_by = u.id 
          LEFT JOIN users u2 ON ic.used_by = u2.id 
          ORDER BY ic.created_at DESC`, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch invite codes' });
    }
    
    res.json(rows);
  });
});

app.get('/api/admin/users', requireAdmin, (req, res) => {
  db.all('SELECT id, username, is_admin, is_blocked, can_post, created_at, last_login, ip_address FROM users ORDER BY created_at DESC', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch users' });
    }
    
    res.json(rows);
  });
});

app.put('/api/admin/users/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { username, password, is_blocked, can_post } = req.body;
  
  let updates = [];
  let params = [];
  
  if (username) {
    updates.push('username = ?');
    params.push(username);
  }
  
  if (password) {
    updates.push('password_hash = ?');
    params.push(bcrypt.hashSync(password, 10));
  }
  
  if (typeof is_blocked === 'boolean') {
    updates.push('is_blocked = ?');
    params.push(is_blocked ? 1 : 0);
  }
  
  if (typeof can_post === 'boolean') {
    updates.push('can_post = ?');
    params.push(can_post ? 1 : 0);
  }
  
  if (updates.length === 0) {
    return res.status(400).json({ error: 'No valid updates provided' });
  }
  
  params.push(id);
  
  db.run(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params, function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to update user' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ message: 'User updated successfully' });
  });
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  
  if (parseInt(id) === req.session.userId) {
    return res.status(400).json({ error: 'Cannot delete your own account' });
  }
  
  db.run('DELETE FROM users WHERE id = ?', [id], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to delete user' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ message: 'User deleted successfully' });
  });
});

// Admin route to get all URLs
app.get('/api/admin/urls', requireAdmin, (req, res) => {
  db.all(`SELECT u.*, us.username 
          FROM urls u 
          LEFT JOIN users us ON u.user_id = us.id 
          ORDER BY u.created_at DESC`, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch URLs' });
    }
    
    res.json(rows);
  });
});

// Admin route to delete any URL
app.delete('/api/admin/urls/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  
  db.run('DELETE FROM urls WHERE id = ?', [id], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to delete URL' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'URL not found' });
    }
    
    res.json({ message: 'URL deleted successfully' });
  });
});

// Admin route to delete all URLs
app.delete('/api/admin/urls', requireAdmin, (req, res) => {
  db.run('DELETE FROM urls', function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to delete all URLs' });
    }
    
    res.json({ message: 'All URLs deleted successfully', deletedCount: this.changes });
  });
});

// IP blocking routes
app.post('/api/admin/block-ip', requireAdmin, (req, res) => {
  const { ip_address, reason } = req.body;
  
  if (!ip_address) {
    return res.status(400).json({ error: 'IP address is required' });
  }
  
  db.run('INSERT INTO blocked_ips (ip_address, blocked_by, reason) VALUES (?, ?, ?)',
    [ip_address, req.session.userId, reason || 'No reason provided'], function(err) {
    if (err) {
      if (err.code === 'SQLITE_CONSTRAINT') {
        return res.status(400).json({ error: 'IP address is already blocked' });
      }
      return res.status(500).json({ error: 'Failed to block IP' });
    }
    
    res.json({ message: 'IP blocked successfully', id: this.lastID });
  });
});

app.get('/api/admin/blocked-ips', requireAdmin, (req, res) => {
  db.all(`SELECT bi.*, u.username as blocked_by_username 
          FROM blocked_ips bi 
          LEFT JOIN users u ON bi.blocked_by = u.id 
          ORDER BY bi.blocked_at DESC`, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch blocked IPs' });
    }
    
    res.json(rows);
  });
});

app.delete('/api/admin/blocked-ips/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  
  db.run('DELETE FROM blocked_ips WHERE id = ?', [id], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to unblock IP' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Blocked IP not found' });
    }
    
    res.json({ message: 'IP unblocked successfully' });
  });
});


app.use(session({
  store: new SQLiteStore({ 
      db: 'sessions.sqlite', // connect-sqlite3 needs a name
      dir: dataDir             // and a directory
  }),
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack); // This logs the full error to your server console
  // Send the detailed error back in the API response for debugging
  res.status(500).json({ 
    error: 'Something went wrong!',
    message: err.message, // The actual error message
    stack: err.stack      // The stack trace
  });
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
  // Exclude API calls from being redirected to index.html
  if (req.path.startsWith('/api/') || req.path.startsWith('/r/')) {
    return next();
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


// --- ERROR HANDLING & SERVER START ---
//app.use((err, req, res, next) => {
  //console.error(err.stack);
  //res.status(500).json({ error: 'Something went wrong!', message: err.message });
//});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`evade.lol server running on http://0.0.0.0:${PORT}`);
  console.log(`Access locally at http://localhost:${PORT}`);
});

