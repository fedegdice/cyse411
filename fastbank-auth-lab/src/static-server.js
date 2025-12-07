const express = require("express");
const path = require("path");

const app = express();
const PORT = 8080;

// Add ALL security headers middleware
app.use((req, res, next) => {
  // Content Security Policy - prevents XSS attacks (stricter without unsafe-inline)
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
  
  // Cache-Control for all content
  res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  
  // Remove server version info
  res.removeHeader("X-Powered-By");
  
  next();
});

// Serve static files from current directory
app.use(express.static("."));

// Handle 404s
app.use((req, res) => {
  res.status(404).send("Not Found");
});

app.listen(PORT, () => {
  console.log(`Secure static file server running at http://localhost:${PORT}`);
  console.log("All security headers are enabled!");
});
