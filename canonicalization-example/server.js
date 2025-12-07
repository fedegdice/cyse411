// server.js - FIXED VERSION
const express = require('express');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');

const app = express();

// Fix: Add security headers middleware
app.use((req, res, next) => {
  // Content Security Policy - prevents XSS attacks
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
  
  // X-Frame-Options - prevents clickjacking
  res.setHeader("X-Frame-Options", "DENY");
  
  // X-Content-Type-Options - prevents MIME sniffing
  res.setHeader("X-Content-Type-Options", "nosniff");
  
  // Permissions Policy - restricts browser features
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  
  // Cross-Origin policies - Spectre protection
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  
  // Remove server version info
  res.removeHeader("X-Powered-By");
  
  next();
});

// Fix: Add rate limiting to prevent brute force attacks
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const BASE_DIR = path.resolve(__dirname, 'files');
if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });

// Fix: Secure path resolution with proper canonicalization
function resolveSafe(baseDir, userInput) {
  // Decode URI component safely
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {
    return null; // Invalid input
  }
  
  // Resolve and canonicalize the path
  const resolved = path.resolve(baseDir, userInput);
  const canonicalBase = fs.realpathSync(baseDir);
  const canonicalPath = path.resolve(resolved);
  
  // Ensure the resolved path is within the base directory
  if (!canonicalPath.startsWith(canonicalBase + path.sep)) {
    return null; // Path traversal attempt
  }
  
  return canonicalPath;
}

// Secure route with proper validation
app.post(
  '/read',
  body('filename')
    .exists().withMessage('filename required')
    .bail()
    .isString()
    .trim()
    .notEmpty().withMessage('filename must not be empty')
    .custom(value => {
      if (value.includes('\0')) throw new Error('null byte not allowed');
      if (value.includes('..')) throw new Error('path traversal not allowed');
      return true;
    }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    
    const filename = req.body.filename;
    const normalized = resolveSafe(BASE_DIR, filename);
    
    if (!normalized) {
      return res.status(403).json({ error: 'Invalid or unsafe path' });
    }
    
    if (!fs.existsSync(normalized)) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    const content = fs.readFileSync(normalized, 'utf8');
    res.json({ path: normalized, content });
  }
);

// Fix: Remove or secure the vulnerable route
// This route should be removed in production
// Keeping it commented for educational purposes
/*
app.post('/read-no-validate', (req, res) => {
  const filename = req.body.filename || '';
  const joined = path.join(BASE_DIR, filename); // VULNERABLE: No validation
  if (!fs.existsSync(joined)) return res.status(404).json({ error: 'File not found', path: joined });
  const content = fs.readFileSync(joined, 'utf8');
  res.json({ path: joined, content });
});
*/

// Helper route for samples
app.post('/setup-sample', (req, res) => {
  const samples = {
    'hello.txt': 'Hello from safe file!\n',
    'notes/readme.md': '# Readme\nSample readme file'
  };
  Object.keys(samples).forEach(k => {
    const p = path.resolve(BASE_DIR, k);
    const d = path.dirname(p);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(p, samples[k], 'utf8');
  });
  res.json({ ok: true, base: BASE_DIR });
});

// Only listen when run directly (not when imported by tests)
if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

module.exports = app;
