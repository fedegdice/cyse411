const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const csurf = require("csurf");

const app = express();

// FIX: Add rate limiting to prevent brute force attacks
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 login requests per windowMs
  message: { error: "Too many login attempts, please try again later" }
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100 // limit each IP to 100 requests per windowMs
});

// --- BASIC CORS (clean, not vulnerable) ---
app.use(
  cors({
    origin: ["http://localhost:3001", "http://127.0.0.1:3001"],
    credentials: true
  })
);

app.use(bodyParser.json());
app.use(cookieParser());

// FIX: Add CSRF protection middleware
const csrfProtection = csurf({ cookie: true });

// --- IN-MEMORY SQLITE DB (clean) ---
const db = new sqlite3.Database(":memory:");

db.serialize(() => {
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT,
      email TEXT
    );
  `);

  db.run(`
    CREATE TABLE transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      amount REAL,
      description TEXT
    );
  `);

  db.run(`
    CREATE TABLE feedback (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user TEXT,
      comment TEXT
    );
  `);

  // FIX: Use bcrypt instead of SHA256 for password hashing
  const bcrypt = require("bcrypt");
  const saltRounds = 12; // Increased from fast hash to proper bcrypt
  const passwordHash = bcrypt.hashSync("password123", saltRounds);

  db.run(`INSERT INTO users (username, password_hash, email)
          VALUES (?, ?, ?)`, ["alice", passwordHash, "alice@example.com"]);

  db.run(`INSERT INTO transactions (user_id, amount, description) VALUES (1, 25.50, 'Coffee shop')`);
  db.run(`INSERT INTO transactions (user_id, amount, description) VALUES (1, 100, 'Groceries')`);
});

// --- SESSION STORE (simple, predictable token exactly like assignment) ---
const sessions = {};

// FIX: Generate cryptographically secure random session IDs
function generateSecureSessionId() {
  return crypto.randomBytes(32).toString("hex");
}

function auth(req, res, next) {
  const sid = req.cookies.sid;
  if (!sid || !sessions[sid]) return res.status(401).json({ error: "Not authenticated" });
  req.user = { id: sessions[sid].userId };
  next();
}

// FIX: Get CSRF token endpoint
app.get("/csrf-token", (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// ------------------------------------------------------------
// FIXED AUTH: Bcrypt + parameterized queries + secure sessions + generic error messages
// ------------------------------------------------------------
app.post("/login", loginLimiter, (req, res) => {
  const { username, password } = req.body;

  // FIX: Use parameterized query to prevent SQL injection
  const sql = `SELECT id, username, password_hash FROM users WHERE username = ?`;

  db.get(sql, [username], async (err, user) => {
    // FIX: Generic error message to prevent username enumeration
    if (!user) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    // FIX: Use bcrypt to verify password (async)
    const bcrypt = require("bcrypt");
    const match = await bcrypt.compare(password, user.password_hash);
    
    if (!match) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    // FIX: Generate cryptographically secure session ID
    const sid = generateSecureSessionId();
    sessions[sid] = { userId: user.id };

    // FIX: Set secure cookie flags
    res.cookie("sid", sid, {
      httpOnly: true,  // Prevents XSS access to cookie
      secure: process.env.NODE_ENV === "production", // HTTPS only in production
      sameSite: "strict" // CSRF protection
    });

    res.json({ success: true });
  });
});

// ------------------------------------------------------------
// /me — clean route, now with parameterized query
// ------------------------------------------------------------
app.get("/me", apiLimiter, auth, (req, res) => {
  // FIX: Use parameterized query
  db.get(`SELECT username, email FROM users WHERE id = ?`, [req.user.id], (err, row) => {
    res.json(row);
  });
});

// ------------------------------------------------------------
// FIXED: SQL injection in transaction search
// ------------------------------------------------------------
app.get("/transactions", apiLimiter, auth, (req, res) => {
  const q = req.query.q || "";
  
  // FIX: Use parameterized query to prevent SQL injection
  const sql = `
    SELECT id, amount, description
    FROM transactions
    WHERE user_id = ?
      AND description LIKE ?
    ORDER BY id DESC
  `;
  
  db.all(sql, [req.user.id, `%${q}%`], (err, rows) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json(rows);
  });
});

// ------------------------------------------------------------
// FIXED: Stored XSS + SQL injection in feedback
// ------------------------------------------------------------
app.post("/feedback", apiLimiter, auth, csrfProtection, (req, res) => {
  const comment = req.body.comment;
  const userId = req.user.id;

  // FIX: Use parameterized queries
  db.get(`SELECT username FROM users WHERE id = ?`, [userId], (err, row) => {
    if (err || !row) return res.status(500).json({ error: "Database error" });
    
    const username = row.username;

    // FIX: Use parameterized query to prevent SQL injection
    const insert = `INSERT INTO feedback (user, comment) VALUES (?, ?)`;
    
    db.run(insert, [username, comment], (err) => {
      if (err) return res.status(500).json({ error: "Database error" });
      res.json({ success: true });
    });
  });
});

app.get("/feedback", apiLimiter, auth, (req, res) => {
  db.all("SELECT user, comment FROM feedback ORDER BY id DESC", (err, rows) => {
    if (err) return res.status(500).json({ error: "Database error" });
    
    // FIX: Sanitize output to prevent XSS (escape HTML)
    const sanitized = rows.map(row => ({
      user: escapeHtml(row.user),
      comment: escapeHtml(row.comment)
    }));
    
    res.json(sanitized);
  });
});

// FIX: Helper function to escape HTML and prevent XSS
function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}

// ------------------------------------------------------------
// FIXED: CSRF protection + SQL injection in email update
// ------------------------------------------------------------
app.post("/change-email", apiLimiter, auth, csrfProtection, (req, res) => {
  const newEmail = req.body.email;

  if (!newEmail || !newEmail.includes("@")) {
    return res.status(400).json({ error: "Invalid email" });
  }

  // FIX: Use parameterized query to prevent SQL injection
  const sql = `UPDATE users SET email = ? WHERE id = ?`;
  
  db.run(sql, [newEmail, req.user.id], (err) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json({ success: true, email: newEmail });
  });
});

// ------------------------------------------------------------
app.listen(4000, () =>
  console.log("FastBank Version A backend running on http://localhost:4000")
);
