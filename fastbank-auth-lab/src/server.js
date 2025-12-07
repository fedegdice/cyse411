const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const csurf = require("csurf");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = 3001;

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
    secure: process.env.NODE_ENV === "production", // HTTPS only in production
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

app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
