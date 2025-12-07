
const express = require('express');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');

const app = express();


app.use((req, res, next) => {
  
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
  
  
  res.setHeader("X-Frame-Options", "DENY");
  
  
  res.setHeader("X-Content-Type-Options", "nosniff");
  
  
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  
  
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  
  
  res.removeHeader("X-Powered-By");
  
  next();
});


const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 100 
});
app.use(limiter);

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const BASE_DIR = path.resolve(__dirname, 'files');
if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });


function resolveSafe(baseDir, userInput) {
  // Decode URI component safely
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {
    return null; // Invalid input
  }
  
  
  const resolved = path.resolve(baseDir, userInput);
  const canonicalBase = fs.realpathSync(baseDir);
  const canonicalPath = path.resolve(resolved);
  
  
  if (!canonicalPath.startsWith(canonicalBase + path.sep)) {
    return null; // Path traversal attempt
  }
  
  return canonicalPath;
}


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


if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

module.exports = app;
