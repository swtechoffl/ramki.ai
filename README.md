# RAMKI Website — Hardened Full Stack

## Quick Start

```bash
npm install

# Generate a strong JWT secret (required for production)
export JWT_SECRET=$(node -e "require('crypto').randomBytes(64).toString('hex').length > 0 && process.stdout.write(require('crypto').randomBytes(64).toString('hex'))")
export NODE_ENV=development

node server.js
# Open http://localhost:3000
```

## First Run
On first launch, a **random one-time password** is printed to the console.
Copy it, log in, and **immediately change it** via Dashboard → Settings → Change Password.

No default password is hardcoded or stored anywhere.

## Production Deployment

```bash
# 1. Set required environment variables
export JWT_SECRET=$(openssl rand -hex 64)   # NEVER commit this
export COOKIE_SECRET=$(openssl rand -hex 32)
export NODE_ENV=production
export PORT=3000

# 2. Start with PM2
npm install -g pm2
pm2 start server.js --name ramki-site
pm2 save && pm2 startup

# 3. Put Nginx in front for HTTPS
# See nginx-example.conf for a sample config
```

## Security Features (v2 — Hardened)

| Feature | Implementation |
|---|---|
| Password hashing | bcrypt, rounds=12 |
| JWT storage | HttpOnly signed cookie (not localStorage) |
| Rate limiting | 10 login attempts / 15 min per IP |
| Security headers | helmet (CSP, X-Frame-Options, noSniff, HSTS) |
| File validation | MIME header + magic byte (file-type library) |
| Token revocation | JTI blacklist in revoked.db |
| Input sanitisation | ID format validation, field length limits, category whitelisting |
| Error hygiene | No stack traces exposed in production |
| HTTPS redirect | Enforced in production mode |
| Default credentials | Random per-install, one-time console display |
| Password complexity | Min 8 chars, must contain letter + number |
| Password change | Revokes existing token, forces re-login |

## Directory Structure

```
ramki-site/
├── server.js              ← Hardened Express server
├── public/
│   ├── index.html         ← Complete frontend (SPA)
│   └── uploads/           ← User-uploaded images
├── data/
│   ├── users.db           ← Admin accounts (bcrypt)
│   ├── blogs.db           ← Blog posts
│   ├── analytics.db       ← Page view counters
│   ├── settings.db        ← Site config + hero photo
│   └── revoked.db         ← JWT blacklist
└── README.md
```

## Backup
Back up the `data/` and `public/uploads/` directories regularly.
These contain all persistent data — the codebase alone is stateless.
