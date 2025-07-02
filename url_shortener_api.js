const express = require('express');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

// In-memory storage (use Redis or database in production)
const urlDatabase = new Map();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Generate short code
function generateShortCode(length = 6) {
  return crypto.randomBytes(length).toString('base64url').substring(0, length);
}

// Validate URL
function isValidUrl(string) {
  try {
    new URL(string);
    return true;
  } catch (_) {
    return false;
  }
}

// Create short URL
app.post('/api/shorten', (req, res) => {
  const { url } = req.body;
  
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }
  
  // Add protocol if missing
  let fullUrl = url;
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    fullUrl = 'https://' + url;
  }
  
  if (!isValidUrl(fullUrl)) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }
  
  // Check if URL already exists
  for (const [code, storedUrl] of urlDatabase.entries()) {
    if (storedUrl === fullUrl) {
      return res.json({
        originalUrl: fullUrl,
        shortUrl: `${req.protocol}://${req.get('host')}/r/${code}`,
        shortCode: code
      });
    }
  }
  
  // Generate new short code
  let shortCode;
  do {
    shortCode = generateShortCode();
  } while (urlDatabase.has(shortCode));
  
  urlDatabase.set(shortCode, fullUrl);
  
  res.json({
    originalUrl: fullUrl,
    shortUrl: `${req.protocol}://${req.get('host')}/r/${shortCode}`,
    shortCode: shortCode
  });
});

// Redirect to original URL
app.get('/r/:shortCode', (req, res) => {
  const { shortCode } = req.params;
  const originalUrl = urlDatabase.get(shortCode);
  
  if (!originalUrl) {
    return res.status(404).json({ error: 'Short URL not found' });
  }
  
  res.redirect(originalUrl);
});

// Get URL info
app.get('/api/info/:shortCode', (req, res) => {
  const { shortCode } = req.params;
  const originalUrl = urlDatabase.get(shortCode);
  
  if (!originalUrl) {
    return res.status(404).json({ error: 'Short URL not found' });
  }
  
  res.json({
    shortCode: shortCode,
    originalUrl: originalUrl,
    shortUrl: `${req.protocol}://${req.get('host')}/r/${shortCode}`
  });
});

// List all URLs (for development)
app.get('/api/urls', (req, res) => {
  const urls = Array.from(urlDatabase.entries()).map(([code, url]) => ({
    shortCode: code,
    originalUrl: url,
    shortUrl: `${req.protocol}://${req.get('host')}/r/${code}`
  }));
  
  res.json(urls);
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Basic HTML form for testing
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>URL Shortener</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
            .form-group { margin-bottom: 15px; }
            input[type="url"] { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; }
            button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
            button:hover { background: #0056b3; }
            .result { margin-top: 20px; padding: 15px; background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; }
        </style>
    </head>
    <body>
        <h1>URL Shortener</h1>
        <form id="urlForm">
            <div class="form-group">
                <label for="url">Enter URL to shorten:</label>
                <input type="url" id="url" name="url" placeholder="https://example.com" required>
            </div>
            <button type="submit">Shorten URL</button>
        </form>
        <div id="result" class="result" style="display: none;"></div>
        
        <script>
            document.getElementById('urlForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const url = document.getElementById('url').value;
                
                try {
                    const response = await fetch('/api/shorten', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url })
                    });
                    
                    const data = await response.json();
                    const resultDiv = document.getElementById('result');
                    
                    if (response.ok) {
                        resultDiv.innerHTML = \`
                            <h3>Success!</h3>
                            <p><strong>Original URL:</strong> \${data.originalUrl}</p>
                            <p><strong>Short URL:</strong> <a href="\${data.shortUrl}" target="_blank">\${data.shortUrl}</a></p>
                            <p><strong>Short Code:</strong> \${data.shortCode}</p>
                        \`;
                    } else {
                        resultDiv.innerHTML = \`<p style="color: red;">Error: \${data.error}</p>\`;
                    }
                    
                    resultDiv.style.display = 'block';
                } catch (error) {
                    document.getElementById('result').innerHTML = \`<p style="color: red;">Error: \${error.message}</p>\`;
                    document.getElementById('result').style.display = 'block';
                }
            });
        </script>
    </body>
    </html>
  `);
});

app.listen(PORT, () => {
  console.log(`URL Shortener API running on port ${PORT}`);
  console.log(`Access the web interface at http://localhost:${PORT}`);
});
