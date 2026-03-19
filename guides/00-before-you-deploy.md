# Before You Deploy

> **Reading time**: 5 minutes
> **Difficulty**: Beginner
> **Related rules**: All

You built something with AI. Before you put it on the internet, read this guide. It could save you from a data breach, a surprise bill, or worse.

## The Analogy

Imagine you built a house. AI was the contractor — it did the work fast, it looks great, and the door opens when you turn the handle. But did anyone check if the locks work? Are the windows reinforced? Is the back door just... open?

That's what deploying AI-generated code without a security check is like. The app works. But "works" and "secure" are not the same thing.

## The 5 Things That Get People Breached

Based on real incidents — apps built with Cursor, Lovable, Replit, and other AI tools:

### 1. Hardcoded API Keys

**What it looks like:**
```python
# BAD — this key is visible to anyone who can see your code
openai_key = "sk-proj-abc123..."
```

**What happens:** Bots scan GitHub 24/7 for patterns like `sk-proj-`. Within hours of pushing code with a hardcoded key, someone will find it and use it. You'll get a surprise bill.

**The fix:**
```python
# GOOD — load from environment variable
import os
openai_key = os.environ.get("OPENAI_API_KEY")
```

Put the actual key in a `.env` file and make sure `.env` is in your `.gitignore`. Run `shipsafe check-secrets .` to verify.

### 2. Missing .gitignore

**What it looks like:** Your `.gitignore` file doesn't exist, or it's missing entries for `.env`, `node_modules`, or `__pycache__`.

**What happens:** Secrets, dependencies, and build artifacts get committed to git. Even if you delete them later, they're in the git history forever.

**The fix:** Run `shipsafe check-gitignore .` and follow the suggestions.

### 3. Debug Mode in Production

**What it looks like:**
```python
# BAD — Django settings
DEBUG = True
```

**What happens:** Debug mode shows detailed error pages with your file paths, environment variables, and database queries. Attackers use this information to find more vulnerabilities.

**The fix:** Set `DEBUG = False` in production. Use environment variables to switch between development and production settings.

### 4. CORS Wildcard

**What it looks like:**
```javascript
// BAD — allows any website to make requests to your API
app.use(cors({ origin: '*' }))
```

**What happens:** Any website can make requests to your API as if they were your frontend. This enables cross-site attacks where a malicious site steals your users' data.

**The fix:** Specify exactly which domains should have access:
```javascript
app.use(cors({ origin: 'https://yourapp.com' }))
```

### 5. TLS Verification Disabled

**What it looks like:**
```python
# BAD — disables HTTPS certificate checking
requests.get(url, verify=False)
```

**What happens:** A man-in-the-middle can intercept all traffic between your app and the API. They can read and modify everything — passwords, API keys, user data.

**The fix:** Remove `verify=False`. If you're getting certificate errors in development, fix the certificate issue instead of disabling verification.

## Your Action Items

1. Run `shipsafe scan .` against your project
2. Fix all CRITICAL findings immediately
3. Fix HIGH findings before deploying
4. Read the specific guide linked in each finding for more detail

## How ShipSafe Catches This

ShipSafe scans your entire codebase for these patterns and 37 more. Every finding includes a copy-paste fix and a link to the relevant guide. The tool runs locally — your code never leaves your machine.
