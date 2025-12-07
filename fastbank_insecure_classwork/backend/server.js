const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const csurf = require("csurf");
const path = require("path");

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


const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 5, 
  message: { error: "Too many login attempts, please try again later" }
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100 
});


app.use(
  cors({
    origin: ["http://localhost:3001", "http://127.0.0.1:3001"],
    credentials: true
  })
);

app.use(bodyParser.json());
app.use(cookieParser());


app.use(express.static(path.join(__dirname, '../frontend')));


const csrfProtection = csurf({ cookie: true });


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

  
  const bcrypt = require("bcrypt");
  const saltRounds = 12; 
  const passwordHash = bcrypt.hashSync("password123", saltRounds);

  db.run(`INSERT INTO users (username, password_hash, email)
          VALUES (?, ?, ?)`, ["alice", passwordHash, "alice@example.com"]);

  db.run(`INSERT INTO transactions (user_id, amount, description) VALUES (1, 25.50, 'Coffee shop')`);
  db.run(`INSERT INTO transactions (user_id, amount, description) VALUES (1, 100, 'Groceries')`);
});


const sessions = {};


function generateSecureSessionId() {
  return crypto.randomBytes(32).toString("hex");
}

function auth(req, res, next) {
  const sid = req.cookies.sid;
  if (!sid || !sessions[sid]) return res.status(401).json({ error: "Not authenticated" });
  req.user = { id: sessions[sid].userId };
  next();
}


app.get("/csrf-token", (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});



app.post("/login", loginLimiter, (req, res) => {
  const { username, password } = req.body;

  
  const sql = `SELECT id, username, password_hash FROM users WHERE username = ?`;

  db.get(sql, [username], async (err, user) => {
    
    if (!user) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    
    const bcrypt = require("bcrypt");
    const match = await bcrypt.compare(password, user.password_hash);
    
    if (!match) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    
    const sid = generateSecureSessionId();
    sessions[sid] = { userId: user.id };

    
    res.cookie("sid", sid, {
      httpOnly: true,  
      secure: process.env.NODE_ENV === "production", 
      sameSite: "strict" 
    });

    res.json({ success: true });
  });
});



app.get("/me", apiLimiter, auth, (req, res) => {
  
  db.get(`SELECT username, email FROM users WHERE id = ?`, [req.user.id], (err, row) => {
    res.json(row);
  });
});



app.get("/transactions", apiLimiter, auth, (req, res) => {
  const q = req.query.q || "";
  
  
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


app.post("/feedback", apiLimiter, auth, csrfProtection, (req, res) => {
  const comment = req.body.comment;
  const userId = req.user.id;

  // FIX: Use parameterized queries
  db.get(`SELECT username FROM users WHERE id = ?`, [userId], (err, row) => {
    if (err || !row) return res.status(500).json({ error: "Database error" });
    
    const username = row.username;

    
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
    
    
    const sanitized = rows.map(row => ({
      user: escapeHtml(row.user),
      comment: escapeHtml(row.comment)
    }));
    
    res.json(sanitized);
  });
});


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


app.post("/change-email", apiLimiter, auth, csrfProtection, (req, res) => {
  const newEmail = req.body.email;

  if (!newEmail || !newEmail.includes("@")) {
    return res.status(400).json({ error: "Invalid email" });
  }

  
  const sql = `UPDATE users SET email = ? WHERE id = ?`;
  
  db.run(sql, [newEmail, req.user.id], (err) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json({ success: true, email: newEmail });
  });
});


app.listen(4000, () =>
  console.log("FastBank Version A backend running on http://localhost:4000")
);
