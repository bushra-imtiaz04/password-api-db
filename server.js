// Password Checker API with database - DecodeLabs Project 2 + Project 3 (Database Integration)
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { DatabaseSync } = require("node:sqlite"); // built into Node.js, no install needed

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: "10kb" }));

// ---------- Database setup (Pillar 1: The Blueprint - schema design) ----------
const db = new DatabaseSync("data.sqlite");

db.exec(`
  CREATE TABLE IF NOT EXISTS feedback (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,   -- Primary key: unique id for every row
    name        TEXT NOT NULL,                        -- NOT NULL: a name is always required
    message     TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS generated_passwords (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    length      INTEGER NOT NULL CHECK (length BETWEEN 8 AND 64), -- CHECK: enforce valid range
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);
// Note: we log that a password WAS generated and how long it was, never the password itself.

// Prepared statements (Pillar 4: The Shield - parameterized queries stop SQL injection)
const stmts = {
  insertFeedback: db.prepare("INSERT INTO feedback (name, message) VALUES (?, ?)"),
  listFeedback: db.prepare("SELECT * FROM feedback ORDER BY id DESC LIMIT ? OFFSET ?"),
  countFeedback: db.prepare("SELECT COUNT(*) AS total FROM feedback"),
  getFeedback: db.prepare("SELECT * FROM feedback WHERE id = ?"),
  updateFeedback: db.prepare("UPDATE feedback SET name = ?, message = ? WHERE id = ?"),
  deleteFeedback: db.prepare("DELETE FROM feedback WHERE id = ?"),
  logGenerated: db.prepare("INSERT INTO generated_passwords (length) VALUES (?)")
};

// ---------- Rate limiter (429): 60 requests per minute per IP ----------
const hits = new Map();
app.use((req, res, next) => {
  const now = Date.now();
  const entry = hits.get(req.ip) || { count: 0, start: now };
  if (now - entry.start > 60_000) { entry.count = 0; entry.start = now; }
  entry.count++;
  hits.set(req.ip, entry);
  if (entry.count > 60) {
    return res.status(429).json({ error: "Too Many Requests", message: "Try again in a minute." });
  }
  next();
});

// ---------- Password strength logic (same rules as the frontend) ----------
const COMMON = ["password", "passw0rd", "123456", "12345678", "qwerty", "abc123",
  "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon", "football",
  "login", "princess", "sunshine", "pakistan", "111111", "000000"];
const LABELS = ["", "Very weak", "Weak", "Fair", "Good", "Strong"];

function hasSequence(s) {
  const t = s.toLowerCase();
  for (let i = 0; i < t.length - 2; i++) {
    const a = t.charCodeAt(i), b = t.charCodeAt(i + 1), c = t.charCodeAt(i + 2);
    if ((b - a === 1 && c - b === 1) || (a === b && b === c)) return true;
  }
  return false;
}

function entropyBits(s) {
  let pool = 0;
  if (/[a-z]/.test(s)) pool += 26;
  if (/[A-Z]/.test(s)) pool += 26;
  if (/\d/.test(s)) pool += 10;
  if (/[^A-Za-z0-9]/.test(s)) pool += 32;
  return pool ? Math.round(s.length * Math.log2(pool)) : 0;
}

function evaluate(s) {
  const lower = s.toLowerCase();
  const checks = {
    length: s.length >= 12,
    mixedCase: /[a-z]/.test(s) && /[A-Z]/.test(s),
    number: /\d/.test(s),
    symbol: /[^A-Za-z0-9]/.test(s),
    notCommon: !COMMON.some((w) => lower.includes(w)) && !hasSequence(s)
  };
  let score = 0;
  if (s.length >= 8) score++;
  if (s.length >= 12) score++;
  if (s.length >= 16) score++;
  if (checks.mixedCase) score++;
  if (checks.number) score++;
  if (checks.symbol) score++;
  if (!checks.notCommon) score = Math.min(score, 2);
  if (s.length < 8) score = Math.min(score, 1);
  const level = Math.max(1, Math.min(5, score));
  return { level, label: LABELS[level], entropyBits: entropyBits(s), checks };
}

// ---------- Routes: health + password tools (Project 2, unchanged) ----------

app.get("/api/health", (req, res) => {
  res.status(200).json({ status: "ok", time: new Date().toISOString() });
});

app.post("/api/check", (req, res) => {
  const { password } = req.body || {};
  const details = [];
  if (typeof password !== "string") details.push("password must be a string");
  else if (password.length === 0) details.push("password must not be empty");
  else if (password.length > 128) details.push("password must be 128 characters or fewer");
  if (details.length) return res.status(400).json({ error: "Bad Request", details });
  res.status(200).json(evaluate(password));
});

app.get("/api/generate", (req, res) => {
  const length = req.query.length === undefined ? 16 : Number(req.query.length);
  if (!Number.isInteger(length) || length < 8 || length > 64) {
    return res.status(400).json({ error: "Bad Request", details: ["length must be a whole number from 8 to 64"] });
  }
  const chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+?";
  let password = "";
  for (let i = 0; i < length; i++) password += chars[crypto.randomInt(chars.length)];
  stmts.logGenerated.run(length); // only the length is stored, never the password
  res.status(200).json({ password, length });
});

// ---------- Routes: feedback CRUD, backed by SQLite (Project 3) ----------

function validateFeedback(body) {
  const details = [];
  const { name, message } = body || {};
  if (typeof name !== "string" || name.trim().length < 1 || name.trim().length > 50)
    details.push("name is required (1 to 50 characters)");
  if (typeof message !== "string" || message.trim().length < 5 || message.trim().length > 500)
    details.push("message is required (5 to 500 characters)");
  return details;
}

// CREATE -> POST /api/feedback -> 201 | 400
app.post("/api/feedback", (req, res) => {
  const details = validateFeedback(req.body);
  if (details.length) return res.status(400).json({ error: "Bad Request", details });

  const { name, message } = req.body;
  const info = stmts.insertFeedback.run(name.trim(), message.trim()); // parameterized: safe from SQL injection
  const row = stmts.getFeedback.get(info.lastInsertRowid);
  res.status(201).json(row);
});

// READ (list, paginated) -> GET /api/feedback?limit=20&offset=0 -> 200 | 400
app.get("/api/feedback", (req, res) => {
  const limit = req.query.limit === undefined ? 20 : Number(req.query.limit);
  const offset = req.query.offset === undefined ? 0 : Number(req.query.offset);
  if (!Number.isInteger(limit) || limit < 1 || limit > 100)
    return res.status(400).json({ error: "Bad Request", details: ["limit must be a whole number from 1 to 100"] });
  if (!Number.isInteger(offset) || offset < 0)
    return res.status(400).json({ error: "Bad Request", details: ["offset must be 0 or a positive whole number"] });

  const rows = stmts.listFeedback.all(limit, offset);
  const { total } = stmts.countFeedback.get();
  res.status(200).json({ total, limit, offset, items: rows });
});

// READ (one) -> GET /api/feedback/:id -> 200 | 404
app.get("/api/feedback/:id", (req, res) => {
  const row = stmts.getFeedback.get(req.params.id);
  if (!row) return res.status(404).json({ error: "Not Found", message: "No feedback with that id." });
  res.status(200).json(row);
});

// UPDATE (full replace) -> PUT /api/feedback/:id -> 200 | 400 | 404
app.put("/api/feedback/:id", (req, res) => {
  const existing = stmts.getFeedback.get(req.params.id);
  if (!existing) return res.status(404).json({ error: "Not Found", message: "No feedback with that id." });

  const details = validateFeedback(req.body);
  if (details.length) return res.status(400).json({ error: "Bad Request", details });

  const { name, message } = req.body;
  stmts.updateFeedback.run(name.trim(), message.trim(), req.params.id);
  res.status(200).json(stmts.getFeedback.get(req.params.id));
});

// DELETE -> DELETE /api/feedback/:id -> 204 | 404
app.delete("/api/feedback/:id", (req, res) => {
  const existing = stmts.getFeedback.get(req.params.id);
  if (!existing) return res.status(404).json({ error: "Not Found", message: "No feedback with that id." });
  stmts.deleteFeedback.run(req.params.id);
  res.status(204).send();
});

// ---------- 404 and error handling ----------
app.use((req, res) => {
  res.status(404).json({ error: "Not Found", message: `${req.method} ${req.originalUrl} does not exist.` });
});

app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Bad Request", details: ["body is not valid JSON"] });
  }
  if (err.type === "entity.too.large") {
    return res.status(413).json({ error: "Payload Too Large" });
  }
  console.error("Server error:", err.message); // never log request bodies (passwords, feedback text)
  res.status(500).json({ error: "Internal Server Error", message: "Something went wrong on our side." });
});

app.listen(PORT, () => console.log(`API running on http://localhost:${PORT} (database: data.sqlite)`));
