# Password Checker API + Database (DecodeLabs Project 2 + Project 3)

A REST API built with Node.js and Express. It checks password strength, generates random passwords, and now stores feedback permanently in a **SQLite database** instead of memory.

## Run it

```bash
npm install
npm start
```

The API runs on `http://localhost:3000`. A file called `data.sqlite` appears in this folder the first time you run it — that is your database. Delete it any time to start fresh; the tables are recreated automatically.

## Why SQLite

SQLite needs no separate server or installation (unlike PostgreSQL or MongoDB) — it is just a file. That makes it the right choice to *learn* schema design and CRUD before setting up a bigger database. The same SQL and the same ideas (primary keys, constraints, parameterized queries) carry over directly to PostgreSQL or MySQL later.

This project uses Node's **built-in** `node:sqlite` module (Node.js 22.5+), not the `better-sqlite3` npm package. `better-sqlite3` has to be compiled from C++ on install, which fails on Windows machines without Visual Studio's C++ build tools. `node:sqlite` ships inside Node itself, so `npm install` only needs to fetch `express` and `cors` — nothing to compile. You may see a one-line `ExperimentalWarning: SQLite is an experimental feature` when the server starts; that is expected and harmless.

This project uses Node's **built-in** `node:sqlite` module (added in Node 22+) instead of an npm package, so there is nothing extra to install and nothing to compile. You will see this warning the first time you run it — it is expected, not an error:

```
(node:xxxx) ExperimentalWarning: SQLite is an experimental feature and might change at any time
```

If `node:sqlite` is not available on your Node version, update Node to the latest LTS from nodejs.org.

## Schema

```sql
CREATE TABLE feedback (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL,
  message     TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE generated_passwords (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  length      INTEGER NOT NULL CHECK (length BETWEEN 8 AND 64),
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
```

- `id` is the **primary key** — a unique identifier for every row.
- `NOT NULL` means that column can never be left empty.
- `CHECK` enforces a rule at the database level (a generated password's length must be 8–64), so bad data can never get in even if the application code has a bug.
- We only ever log the *length* of a generated password, never the password itself, and we never store the passwords people check. Those stay in memory for the one request and are discarded.

## Endpoints

| Method | Path | Success | Errors | Maps to |
|--------|------|---------|--------|---------|
| GET | `/api/health` | 200 | | — |
| POST | `/api/check` | 200 | 400 | — |
| GET | `/api/generate?length=16` | 200 | 400 | — |
| **POST** | `/api/feedback` | **201** | 400 | SQL `INSERT` (Create) |
| **GET** | `/api/feedback?limit=20&offset=0` | **200** | 400 | SQL `SELECT` (Read, list) |
| **GET** | `/api/feedback/:id` | **200** | 404 | SQL `SELECT` (Read, one) |
| **PUT** | `/api/feedback/:id` | **200** | 400, 404 | SQL `UPDATE` |
| **DELETE** | `/api/feedback/:id` | **204** | 404 | SQL `DELETE` |

Unknown routes return 404, too many requests return 429, and unexpected failures return 500.

## Examples

Create feedback:
```bash
curl -X POST http://localhost:3000/api/feedback -H "Content-Type: application/json" -d "{\"name\":\"Bushra\",\"message\":\"Nice tool!\"}"
```

Update it:
```bash
curl -X PUT http://localhost:3000/api/feedback/1 -H "Content-Type: application/json" -d "{\"name\":\"Bushra\",\"message\":\"Updated message\"}"
```

Delete it:
```bash
curl -X DELETE http://localhost:3000/api/feedback/1
```

## Security: parameterized queries

Every query uses a `?` placeholder and passes user input as a separate argument, never by pasting it into the SQL string:

```js
// Safe: the database treats userInput strictly as data, never as code
db.prepare("INSERT INTO feedback (name, message) VALUES (?, ?)").run(name, message);
```

This is what stops **SQL injection** — a malicious name like `x'; DROP TABLE feedback; --` is stored as a harmless string instead of running as a command. Never build a query with string concatenation or template literals using user input.

## Design notes

- Resources are nouns, methods are verbs: `POST /api/feedback`, not `/createFeedback`.
- All input is validated on the server before it touches the database — the database is the final source of truth, so the app never trusts the client.
- `PUT` replaces the whole record, so both `name` and `message` are required, same as `POST`.
- `DELETE` returns `204 No Content` on success — there is nothing left to send back.
- WAL mode (`journal_mode = WAL`) is enabled so reads and writes don't block each other.
