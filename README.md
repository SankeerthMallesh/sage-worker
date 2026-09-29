# Sage on Cloudflare Workers (free)

- public/index.html: the site
- src/: the server code (checkout, session, verify)
- wrangler.jsonc: Cloudflare settings

## Secrets (Cloudflare > your Worker > Settings > Variables and Secrets)
STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY, SIGNING_SECRET

Edit prices in src/util.js (amounts in cents).
