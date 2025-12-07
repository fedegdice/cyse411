const express = require("express");
const path = require("path");

const app = express();
const PORT = 8080;


app.use((req, res, next) => {
  
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; form-action 'self'");
  
  
  res.setHeader("X-Frame-Options", "DENY");
  
  
  res.setHeader("X-Content-Type-Options", "nosniff");
  
  
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  
  
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  
  
  res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  
  
  res.removeHeader("X-Powered-By");
  
  next();
});


app.use(express.static("public"));


app.use((req, res) => {
  res.status(404).send("Not Found");
});

app.listen(PORT, () => {
  console.log(`Secure static file server running at http://localhost:${PORT}`);
  console.log("All security headers are enabled!");
});
