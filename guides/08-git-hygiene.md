# Git Hygiene

> **Reading time**: 5 minutes
> **Difficulty**: Beginner
> **Related rules**: GIT002–GIT006

## The Analogy

Git is like a security camera that records everything. Every file you commit, every change you make — it's all stored in the history. If you accidentally put your house key in front of the camera, deleting the key later doesn't erase the footage. The recording still shows where you kept it.

That's why `.gitignore` exists. It tells git "don't record these files." Getting this right from the start is much easier than cleaning up the footage later.

## What Can Go Wrong

**Common disaster scenario:**
1. You create a project with AI tools
2. The AI generates a `.env` file with your API keys
3. You run `git add .` (which adds everything)
4. You push to GitHub
5. Within minutes, bots find your keys in the public repo
6. You get a $2,000 cloud bill overnight

## The .gitignore File

Create a file called `.gitignore` in your project root. Here's what every project needs:

### Universal (every project)
```gitignore
# Environment files (secrets)
.env
.env.*
.env.local
.env.production

# OS files
.DS_Store
Thumbs.db

# IDE files
.idea/
.vscode/
*.swp
*.swo
```

### Python projects
```gitignore
__pycache__/
*.pyc
*.pyo
*.egg-info/
dist/
build/
venv/
.venv/
.tox/
.mypy_cache/
.pytest_cache/
```

### JavaScript / Node.js projects
```gitignore
node_modules/
dist/
build/
.next/
.nuxt/
coverage/
*.log
```

### React Native / Expo
```gitignore
node_modules/
.expo/
ios/Pods/
android/.gradle/
*.jks
*.keystore
```

## What Should NEVER Be Committed

| File/Pattern | Why |
|-------------|-----|
| `.env`, `.env.*` | Contains API keys and database passwords |
| `node_modules/` | Thousands of files, install from `package.json` instead |
| `__pycache__/` | Python bytecode, regenerated automatically |
| `*.sqlite`, `*.db` | May contain user data |
| `*.pem`, `*.key` | Private keys and certificates |
| `.DS_Store` | macOS metadata, no value to the project |
| `build/`, `dist/` | Build artifacts, regenerated from source |
| `coverage/` | Test coverage reports |

## What to Do If You Already Committed Secrets

If secrets are already in your git history:

1. **Rotate the key immediately** — generate a new key from the provider's dashboard
2. **Add the file to .gitignore** so it won't be committed again
3. **Remove from tracking**: `git rm --cached .env`
4. **Clean the git history** using BFG Repo Cleaner (see [Secrets Management guide](01-secrets-management.md))
5. **Force push** the cleaned history: `git push --force`

Remember: deleting the file and committing is NOT enough. The old version with the secret is still in git history.

## How ShipSafe Catches This

ShipSafe checks for:
- **GIT002**: `.gitignore` missing `.env` entry
- **GIT003**: `.gitignore` missing `node_modules` entry
- **GIT004**: `.gitignore` missing `__pycache__` entry
- **GIT005**: `.gitignore` missing `.DS_Store` entry
- **GIT006**: `.env` file found in the project directory

Run `shipsafe check-gitignore .` for a quick check.
