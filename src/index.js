// Sage — Cloudflare Worker: Stripe Embedded Checkout + signed unlock tokens.
// Routes: POST /api/checkout, GET /api/session?id=cs_..., POST /api/verify
// Everything else is served from /public by the ASSETS binding.
//
// Required secrets (already set in Cloudflare -> Variables and Secrets):
//   STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY, SIGNING_SECRET
// Required plain variables (set in wrangler.jsonc "vars"):
//   PRICE_COURSE, PRICE_MONTHLY, PRICE_YEARLY

const STRIPE_API = 'https://api.stripe.com/v1';

const PLANS = {
  course: { mode: 'payment', priceVar: 'PRICE_COURSE' },
  m: { mode: 'subscription', priceVar: 'PRICE_MONTHLY', trialDays: 14 },
  y: { mode: 'subscription', priceVar: 'PRICE_YEARLY', trialDays: 7 },
};

const enc = new TextEncoder();
const dec = new TextDecoder();

/* ---------- small helpers ---------- */

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

function b64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unb64url(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function hmacKey(env, usages) {
  return crypto.subtle.importKey('raw', enc.encode(env.SIGNING_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, usages);
}

async function signToken(payload, env) {
  const body = b64url(enc.encode(JSON.stringify(payload)));
  const key = await hmacKey(env, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(body)));
  return body + '.' + b64url(sig);
}

// Returns the payload if the signature is valid, otherwise null.
async function readToken(token, env) {
  if (typeof token !== 'string' || token.length > 2000) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  try {
    const key = await hmacKey(env, ['verify']);
    const ok = await crypto.subtle.verify('HMAC', key, unb64url(parts[1]), enc.encode(parts[0]));
    if (!ok) return null;
    const payload = JSON.parse(dec.decode(unb64url(parts[0])));
    return payload && payload.v === 1 ? payload : null;
  } catch (e) {
    return null;
  }
}

async function stripeFetch(env, method, path, params) {
  const init = {
    method,
    headers: {
      Authorization: 'Bearer ' + env.STRIPE_SECRET_KEY,
    },
  };
  if (params && method !== 'GET') {
    init.headers['Content-Type'] = 'application/x-www-form-urlencoded';
    init.body = params.toString();
  }
  const res = await fetch(STRIPE_API + path, init);
  let data = null;
  try {
    data = await res.json();
  } catch (e) {}
  return { ok: res.ok, status: res.status, data };
}

function getSession(env, id) {
  const q = 'expand%5B%5D=subscription&expand%5B%5D=payment_intent.latest_charge';
  return stripeFetch(env, 'GET', '/checkout/sessions/' + encodeURIComponent(id) + '?' + q);
}

// Is this Checkout Session still entitled to its plan right now?
function entitled(s) {
  const plan = s.metadata && s.metadata.plan;
  if (!PLANS[plan] || s.status !== 'complete') return null;
  if (plan === 'course') {
    const charge = s.payment_intent && typeof s.payment_intent === 'object' ? s.payment_intent.latest_charge : null;
    const refunded = charge && typeof charge === 'object' && charge.refunded === true;
    return s.payment_status === 'paid' && !refunded ? { plan } : null;
  }
  // Sage+ (trial counts): subscription must exist and be trialing or active.
  const sub = s.subscription && typeof s.subscription === 'object' ? s.subscription : null;
  return sub && (sub.status === 'trialing' || sub.status === 'active') ? { plan, sub: sub.id } : null;
}

/* ---------- routes ---------- */

async function checkout(request, env) {
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ error: 'Bad request.' }, 400);
  }
  const planKey = body && body.plan;
  const plan = PLANS[planKey];
  if (!plan) return json({ error: 'Unknown plan.' }, 400);

  const priceId = env[plan.priceVar];
  if (!env.STRIPE_SECRET_KEY || !env.STRIPE_PUBLISHABLE_KEY || !env.SIGNING_SECRET || !priceId) {
    return json({ error: 'Payments are not configured yet.' }, 500);
  }

  const origin = new URL(request.url).origin;
  const p = new URLSearchParams();
  p.set('ui_mode', 'embedded_page');
  p.set('mode', plan.mode);
  p.set('line_items[0][price]', priceId);
  p.set('line_items[0][quantity]', '1');
  p.set('return_url', origin + '/?session_id={CHECKOUT_SESSION_ID}&paid=' + planKey);
  p.set('redirect_on_completion', 'if_required');
  p.set('metadata[plan]', planKey);
  if (plan.mode === 'subscription') {
    p.set('subscription_data[trial_period_days]', String(plan.trialDays));
    p.set('subscription_data[metadata][plan]', planKey);
  }

  const r = await stripeFetch(env, 'POST', '/checkout/sessions', p);
  if (!r.ok || !r.data || !r.data.client_secret) {
    const why = r.data && r.data.error && r.data.error.message ? r.data.error.message : 'status ' + r.status;
    console.error('Stripe checkout error:', r.status, JSON.stringify(r.data && r.data.error));
    return json({ error: 'Could not start checkout: ' + why }, 502);
  }
  return json({
    publishableKey: env.STRIPE_PUBLISHABLE_KEY,
    clientSecret: r.data.client_secret,
    sessionId: r.data.id,
  });
}

async function session(url, env) {
  const id = url.searchParams.get('id') || '';
  if (!/^cs_(test|live)_[A-Za-z0-9]+$/.test(id)) return json({ error: 'Invalid session.' }, 400);
  if (!env.STRIPE_SECRET_KEY || !env.SIGNING_SECRET) return json({ error: 'Payments are not configured yet.' }, 500);

  const r = await getSession(env, id);
  if (r.status === 404) return json({ error: 'Payment not found.' }, 404);
  if (!r.ok || !r.data) return json({ error: 'Could not confirm payment. Please try again.' }, 502);

  const ent = entitled(r.data);
  if (!ent) return json({ error: 'Payment not completed yet.' }, 402);

  const token = await signToken({ v: 1, plan: ent.plan, sid: r.data.id, iat: Date.now() }, env);
  return json({ token, plan: ent.plan });
}

async function verify(request, env) {
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ ok: false });
  }
  if (!env.STRIPE_SECRET_KEY || !env.SIGNING_SECRET) return json({ error: 'Not configured.' }, 500);

  const payload = await readToken(body && body.token, env);
  if (!payload || !PLANS[payload.plan] || typeof payload.sid !== 'string') return json({ ok: false });

  const r = await getSession(env, payload.sid);
  // Stripe does not know this session (for example a test-mode token after going live).
  if (r.status === 404) return json({ ok: false });
  // Temporary trouble: answer with an error so the page keeps the user's access.
  if (!r.ok || !r.data) return json({ error: 'Could not verify right now.' }, 503);

  const ent = entitled(r.data);
  if (!ent || ent.plan !== payload.plan) return json({ ok: false });
  return json({ ok: true, plan: ent.plan });
}

/* ---------- entry ---------- */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      try {
        if (url.pathname === '/api/checkout' && request.method === 'POST') return await checkout(request, env);
        if (url.pathname === '/api/session' && request.method === 'GET') return await session(url, env);
        if (url.pathname === '/api/verify' && request.method === 'POST') return await verify(request, env);
        return json({ error: 'Not found.' }, 404);
      } catch (e) {
        return json({ error: 'Something went wrong. Please try again.' }, 500);
      }
    }
    return env.ASSETS.fetch(request);
  },
};
