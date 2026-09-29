// Shared helpers for the Cloudflare Pages Functions.
export const PLANS = {
  course: { mode: 'payment', amount: 5900, name: 'Sage Course Access (lifetime)', desc: 'All 100 lessons, 320 practice questions, unit tests and Course Challenge' },
  m: { mode: 'subscription', amount: 500, interval: 'month', trialDays: 14, name: 'Sage+ Monthly', desc: 'Dashboard, streaks, mastery breakdown, certificate, unlimited arcade and tools' },
  y: { mode: 'subscription', amount: 5000, interval: 'year', trialDays: 14, name: 'Sage+ Annual', desc: 'Dashboard, streaks, mastery breakdown, certificate, unlimited arcade and tools' },
};

export const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });

// Stripe wants form-encoded bodies with bracket notation: a[b][0]=c
export function encode(obj, prefix = '', out = []) {
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    const key = prefix ? `${prefix}[${k}]` : k;
    if (typeof v === 'object') encode(v, key, out);
    else out.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(v))}`);
  }
  return out;
}

export async function stripe(env, method, path, params) {
  if (!env.STRIPE_SECRET_KEY) throw new Error('STRIPE_SECRET_KEY is not set');
  const headers = { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`, 'Stripe-Version': '2025-02-24.acacia' };
  let url = 'https://api.stripe.com/v1' + path;
  const init = { method, headers };
  if (params) {
    const body = encode(params).join('&');
    if (method === 'GET') url += '?' + body;
    else { init.body = body; headers['Content-Type'] = 'application/x-www-form-urlencoded'; }
  }
  const res = await fetch(url, init);
  const data = await res.json();
  if (!res.ok) throw new Error((data.error && data.error.message) || 'Stripe error');
  return data;
}

const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
async function hmacKey(env) {
  if (!env.SIGNING_SECRET) throw new Error('SIGNING_SECRET is not set');
  return crypto.subtle.importKey('raw', new TextEncoder().encode(env.SIGNING_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
export async function sign(env, payload) {
  const body = b64u(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(env), new TextEncoder().encode(body));
  return body + '.' + b64u(sig);
}
export async function verify(env, token) {
  if (typeof token !== 'string') return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  try {
    const ok = await crypto.subtle.verify('HMAC', await hmacKey(env), fromB64u(sig), new TextEncoder().encode(body));
    if (!ok) return null;
    return JSON.parse(new TextDecoder().decode(fromB64u(body)));
  } catch { return null; }
}
