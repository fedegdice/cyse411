const API = "http://localhost:4000";


let csrfToken = null;


async function fetchCsrfToken() {
  try {
    const res = await fetch(`${API}/csrf-token`, { credentials: "include" });
    const data = await res.json();
    csrfToken = data.csrfToken;
  } catch (error) {
    console.error("Failed to fetch CSRF token:", error);
  }
}

async function login(e) {
  e.preventDefault();
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  
  const res = await fetch(`${API}/login`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });
  
  const status = document.getElementById("login-status");
  if (!res.ok) {
    const data = await res.json();
    status.textContent = data.error;
    return;
  }
  
  status.textContent = "Logged in!";
  
  
  await fetchCsrfToken();
  loadUser();
}

async function loadUser() {
  const res = await fetch(`${API}/me`, { credentials: "include" });
  if (!res.ok) return;
  
  const me = await res.json();
  document.getElementById("login-section").style.display = "none";
  document.getElementById("user-section").style.display = "";
  document.getElementById("transactions-section").style.display = "";
  document.getElementById("feedback-section").style.display = "";
  document.getElementById("email-section").style.display = "";
  document.getElementById("user-info").textContent = `${me.username} (${me.email})`;
}

async function searchTransactions(e) {
  e.preventDefault();
  const q = document.getElementById("search-q").value;
  
  const res = await fetch(`${API}/transactions?q=${q}`, {
    credentials: "include"
  });
  
  const tx = await res.json();
  const table = document.getElementById("transactions-table");
  table.innerHTML = "<tr><th>ID</th><th>Amount</th><th>Description</th></tr>";
  
  tx.forEach(t => {
    const row = document.createElement("tr");
    row.innerHTML = `<td>${t.id}</td><td>${t.amount}</td><td>${t.description}</td>`;
    table.appendChild(row);
  });
}

async function submitFeedback(e) {
  e.preventDefault();
  const comment = document.getElementById("feedback-comment").value;
  
  
  const res = await fetch(`${API}/feedback`, {
    method: "POST",
    credentials: "include",
    headers: { 
      "Content-Type": "application/json",
      "CSRF-Token": csrfToken  
    },
    body: JSON.stringify({ comment })
  });
  
  if (!res.ok) {
    alert("Failed to submit feedback");
    return;
  }
  
  loadFeedback();
}

async function loadFeedback() {
  const res = await fetch(`${API}/feedback`, { credentials: "include" });
  const list = await res.json();
  const container = document.getElementById("feedback-list");
  container.innerHTML = "";
  
  list.forEach(f => {
    
    const p = document.createElement("p");
    
    const strong = document.createElement("strong");
    strong.textContent = f.user + ": ";
    p.appendChild(strong);
    p.appendChild(document.createTextNode(f.comment));
    container.appendChild(p);
  });
}

async function updateEmail(e) {
  e.preventDefault();
  const email = document.getElementById("new-email").value;
  
  
  const res = await fetch(`${API}/change-email`, {
    method: "POST",
    credentials: "include",
    headers: { 
      "Content-Type": "application/json",
      "CSRF-Token": csrfToken  
    },
    body: JSON.stringify({ email })
  });
  
  if (!res.ok) {
    alert("Failed to update email");
    return;
  }
  
  loadUser(); 
}


document.getElementById("login-form").onsubmit = login;
document.getElementById("search-form").onsubmit = searchTransactions;
document.getElementById("feedback-form").onsubmit = submitFeedback;
document.getElementById("email-form").onsubmit = updateEmail;


fetchCsrfToken();
