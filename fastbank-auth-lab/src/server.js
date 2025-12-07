const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const csurf = require("csurf");
const rateLimit = require("express-rate-limit");
const https = require("https");
const fs = require("fs");

const app = express();
const PORT = 8080;
const HTTPS_PORT = 3443;

// FIX: Add security headers middleware
app.use((req, res, next) => {
  // Content Security Policy - prevents XSS attacks
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; form-action 'self'");
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
  
  // Strict Transport Security - forces HTTPS
  if (req.secure) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  
  // Remove server version info
  res.removeHeader("X-Powered-By");
  
  // FIX: Add Cache-Control for sensitive pages
  if (req.path.startsWith('/api/')) {
    res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate, private");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
  }
  
  next();
});

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static("public"));

// FIX: Add CSRF protection
const csrfProtection = csurf({ cookie: true });

// FIX: Add rate limiting for login attempts
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 login attempts per windowMs
  message: { success: false, message: "Too many login attempts, please try again later" }
});

/**
 * FIXED USER DB
 * Using bcrypt with proper salt rounds instead of fast hash
 */
const SALT_ROUNDS = 12;

// Initialize with bcrypt-hashed password
const users = [
  {
    id: 1,
    username: "student",
    // FIXED: Using bcrypt instead of fast hash
    passwordHash: bcrypt.hashSync("password123", SALT_ROUNDS)
  }
];

// In-memory session store
const sessions = {}; // token -> { userId, createdAt }

// FIX: Generate cryptographically secure random session tokens
function generateSecureToken() {
  return crypto.randomBytes(32).toString("hex");
}

// Helper: find user by username
function findUser(username) {
  return users.find((u) => u.username === username);
}

// FIX: CSRF token endpoint
app.get("/api/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Home API just to show who is logged in
app.get("/api/me", (req, res) => {
  const token = req.cookies.session;
  if (!token || !sessions[token]) {
    return res.status(401).json({ authenticated: false });
  }
  const session = sessions[token];
  const user = users.find((u) => u.id === session.userId);
  res.json({ authenticated: true, username: user.username });
});

/**
 * FIXED LOGIN ENDPOINT
 * - Uses bcrypt instead of fastHash
 * - Generic error messages prevent username enumeration
 * - Cryptographically secure session tokens
 * - Secure cookie flags
 * - Rate limiting
 */
app.post("/api/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);
  
  // FIX: Generic error message to prevent username enumeration
  if (!user) {
    return res
      .status(401)
      .json({ success: false, message: "Invalid username or password" });
  }

  // FIX: Use bcrypt to compare password (async)
  const isMatch = await bcrypt.compare(password, user.passwordHash);
  
  if (!isMatch) {
    return res
      .status(401)
      .json({ success: false, message: "Invalid username or password" });
  }

  // FIX: Generate cryptographically secure token
  const token = generateSecureToken();
  
  // FIX: Store session with timestamp for potential expiration
  sessions[token] = { 
    userId: user.id,
    createdAt: Date.now()
  };

  // FIX: Set secure cookie flags
  res.cookie("session", token, {
    httpOnly: true,  // Prevents JavaScript access (XSS protection)
    secure: req.secure || process.env.NODE_ENV === "production", // HTTPS only
    sameSite: "strict", // CSRF protection
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  });

  res.json({ success: true, token });
});

// FIX: Add CSRF protection to logout
app.post("/api/logout", csrfProtection, (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) {
    delete sessions[token];
  }
  res.clearCookie("session");
  res.json({ success: true });
});

// Start HTTP server (for development)
app.listen(PORT, () => {
  console.log(`FastBank Auth Lab (HTTP) running at http://localhost:${PORT}`);
});

// Start HTTPS server (recommended for production)
// Generate self-signed certificate for local testing:
// openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
try {
  const httpsOptions = {
    key: fs.readFileSync('./key.pem'),
    cert: fs.readFileSync('./cert.pem')
  };
  
  https.createServer(httpsOptions, app).listen(HTTPS_PORT, () => {
    console.log(`FastBank Auth Lab (HTTPS) running at https://localhost:${HTTPS_PORT}`);
  });
} catch (err) {
  console.log('HTTPS not configured. Run the following to create certificates:');
  console.log('openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes');
}
