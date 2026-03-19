# Secrets Management

> **Reading time**: 8 minutes
> **Difficulty**: Beginner
> **Related rules**: SEC001–SEC018

## The Analogy

A hardcoded API key is like writing your bank PIN on a sticky note and taping it to your debit card. It works — you'll never forget it — but anyone who picks up your card can drain your account.

When you put an API key directly in your source code, anyone who can see your code can use your key. That includes: anyone with access to your GitHub repo (public repos are visible to the entire internet), anyone who forks your code, and bots that scan GitHub 24/7 specifically looking for exposed keys.

## What Can Go Wrong

**Real incident**: Moltbook exposed 1.5 million API keys through secrets committed to their repository. The Escape.tech 2025 study found this is the single most common vulnerability in AI-generated codebases.

**What happens when a key leaks:**
1. Automated bots find the key (usually within minutes to hours for public repos)
2. The key is used to make API calls at your expense
3. You get a surprise bill (OpenAI, AWS, Stripe bills can run into thousands)
4. Your account may be suspended
5. If the key accesses user data, you have a data breach with legal obligations

## How to Fix It

### Step 1: Move secrets to environment variables

**Python:**
```python
# BAD
api_key = "sk-proj-abc123..."

# GOOD
import os
api_key = os.environ.get("OPENAI_API_KEY")
if not api_key:
    raise ValueError("OPENAI_API_KEY environment variable is not set")
```

**JavaScript / Node.js:**
```javascript
// BAD
const apiKey = "sk-proj-abc123...";

// GOOD
const apiKey = process.env.OPENAI_API_KEY;
if (!apiKey) {
    throw new Error("OPENAI_API_KEY environment variable is not set");
}
```

**Next.js:**
```javascript
// For server-side only (API routes, server components):
const apiKey = process.env.OPENAI_API_KEY;

// For client-side (NEVER put secret keys here):
// Only use NEXT_PUBLIC_ prefix for non-secret values
const publicUrl = process.env.NEXT_PUBLIC_API_URL;
```

### Step 2: Create a .env file

Create a file called `.env` in your project root:

```
OPENAI_API_KEY=sk-proj-your-actual-key-here
DATABASE_URL=postgres://user:password@localhost:5432/mydb
STRIPE_SECRET_KEY=sk_live_your-stripe-key-here
```

### Step 3: Add .env to .gitignore

Add this to your `.gitignore` file:

```
.env
.env.*
.env.local
.env.production
```

### Step 4: Create a .env.example

Create `.env.example` showing what variables are needed, without the actual values:

```
OPENAI_API_KEY=your-openai-api-key-here
DATABASE_URL=postgres://user:password@localhost:5432/mydb
STRIPE_SECRET_KEY=your-stripe-secret-key-here
```

This file IS safe to commit — it shows the structure without exposing secrets.

### Step 5: Rotate compromised keys

If a key was ever in your git history, it is compromised. Even if you deleted the file, the key is still in git history. You must rotate (regenerate) the key.

**Rotation URLs by provider:**

| Provider | Where to rotate |
|----------|----------------|
| OpenAI | https://platform.openai.com/api-keys |
| Anthropic | https://console.anthropic.com/settings/keys |
| AWS | https://console.aws.amazon.com/iam/ |
| Google Cloud | https://console.cloud.google.com/apis/credentials |
| Stripe | https://dashboard.stripe.com/apikeys |
| GitHub | https://github.com/settings/tokens |
| Supabase | Project Settings > API in your Supabase dashboard |

## How to Clean Git History

If a key was committed to git, deleting the file is NOT enough. The key is in the git history. You need to clean the history.

**Option 1: BFG Repo Cleaner (recommended)**
```bash
# Install BFG
brew install bfg  # or download from https://rtyley.github.io/bfg-repo-cleaner/

# Remove a file from all history
bfg --delete-files .env

# Remove specific strings
echo "sk-proj-your-leaked-key" > passwords.txt
bfg --replace-text passwords.txt

# Clean up
git reflog expire --expire=now --all
git gc --prune=now --aggressive
git push --force
```

**Option 2: git filter-branch**
```bash
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch .env" \
  --prune-empty --tag-name-filter cat -- --all
```

**After cleaning history, you MUST still rotate the key.** Assume it has been scraped.

## How ShipSafe Catches This

ShipSafe includes 18 secrets detection rules (SEC001–SEC018) covering API keys for OpenAI, Anthropic, AWS, GCP, Stripe, GitHub, GitLab, Slack, Twilio, SendGrid, Mailgun, NPM, PyPI, Docker Hub, Vercel, Supabase, database URLs, and private keys.

Each rule uses specific regex patterns that match the key format for that provider. Detected keys are always redacted in output — ShipSafe never displays the full key value.

Run `shipsafe check-secrets .` for a quick secrets-only scan.
