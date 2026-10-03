// worker-merged.js — Sage worker: checkout, course price $50, 7-day yearly trial, cash-back webhook
// Required secrets: STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY, SIGNING_SECRET, STRIPE_WEBHOOK_SECRET

const PLANS = {
  course: { mode: "payment", amount: 5000, name: "Sage Course Access (lifetime)", desc: "All 100 lessons, 320 practice questions, unit tests and Course Challenge" },
  m: { mode: "subscription", amount: 500, interval: "month", trialDays: 14, name: "Sage+ Monthly", desc: "Dashboard, streaks, mastery breakdown, certificate, unlimited arcade and tools" },
  y: { mode: "subscription", amount: 5000, interval: "year", trialDays: 7, name: "Sage+ Annual", desc: "Dashboard, streaks, mastery breakdown, certificate, unlimited arcade and tools" },
};
const CASHBACK_PERCENT = { m: 10, y: 15 };

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });

function encode(obj, prefix = "", out = []) {
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    const key = prefix ? `${prefix}[${k}]` : k;
    if (typeof v === "object") encode(v, key, out);
    else out.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(v))}`);
  }
  return out;
}

async function stripe(env, method, path, params, extraHeaders = {}) {
  if (!env.STRIPE_SECRET_KEY) throw new Error("STRIPE_SECRET_KEY is not set");
  const headers = { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`, "Stripe-Version": "2025-02-24.acacia", ...extraHeaders };
  let url = "https://api.stripe.com/v1" + path;
  const init = { method, headers };
  if (params) {
    const body = encode(params).join("&");
    if (method === "GET") url += "?" + body;
    else {
      init.body = body;
      headers["Content-Type"] = "application/x-www-form-urlencoded";
    }
  }
  const res = await fetch(url, init);
  const data = await res.json();
  if (!res.ok) throw new Error((data.error && data.error.message) || "Stripe error");
  return data;
}

const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

async function hmacKey(env) {
  if (!env.SIGNING_SECRET) throw new Error("SIGNING_SECRET is not set");
  return crypto.subtle.importKey("raw", new TextEncoder().encode(env.SIGNING_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
async function sign(env, payload) {
  const body = b64u(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(env), new TextEncoder().encode(body));
  return body + "." + b64u(sig);
}
async function verify(env, token) {
  if (typeof token !== "string") return null;
  const [body, sig] = token.split(".");
  if (!body || !sig) return null;
  try {
    const ok = await crypto.subtle.verify("HMAC", await hmacKey(env), fromB64u(sig), new TextEncoder().encode(body));
    if (!ok) return null;
    return JSON.parse(new TextDecoder().decode(fromB64u(body)));
  } catch {
    return null;
  }
}

// ---- /api/checkout ----
async function checkout(request, env) {
  try {
    const body = await request.json().catch(() => ({}));
    const plan = body.plan;
    const p = PLANS[plan];
    if (!p) return json({ error: "Unknown plan" }, 400);
    if (!env.STRIPE_PUBLISHABLE_KEY) throw new Error("STRIPE_PUBLISHABLE_KEY is not set");
    const origin = new URL(request.url).origin;
    const price_data = { currency: "usd", unit_amount: p.amount, product_data: { name: p.name, description: p.desc } };
    if (p.interval) price_data.recurring = { interval: p.interval };
    const params = {
      ui_mode: "embedded",
      mode: p.mode,
      line_items: [{ quantity: 1, price_data }],
      allow_promotion_codes: true,
      metadata: { plan },
      redirect_on_completion: "if_required",
      return_url: `${origin}/?session_id={CHECKOUT_SESSION_ID}`,
    };
    if (p.mode === "subscription") {
      params.payment_method_collection = "always"; // card up front so the trial can convert
      params.subscription_data = { metadata: { plan }, trial_period_days: p.trialDays };
    }
    const session = await stripe(env, "POST", "/checkout/sessions", params);
    return json({ clientSecret: session.client_secret, sessionId: session.id, publishableKey: env.STRIPE_PUBLISHABLE_KEY });
  } catch (e) {
    console.error(e);
    return json({ error: "Checkout is unavailable right now. Please try again." }, 500);
  }
}

// ---- /api/session ----
async function session(request, env) {
  try {
    const id = String(new URL(request.url).searchParams.get("id") || "");
    if (!/^cs_/.test(id)) return json({ error: "Bad session id" }, 400);
    const s = await stripe(env, "GET", "/checkout/sessions/" + encodeURIComponent(id));
    const plan = s.metadata && s.metadata.plan;
    if (!PLANS[plan]) return json({ error: "Unknown plan" }, 400);
    const paidOk = s.payment_status === "paid" || (s.mode === "subscription" && s.payment_status === "no_payment_required");
    if (s.status !== "complete" || !paidOk) return json({ error: "Payment not completed yet" }, 402);
    const sub = typeof s.subscription === "string" ? s.subscription : (s.subscription && s.subscription.id) || null;
    return json({ plan, token: await sign(env, { plan, sub, iat: Date.now() }) });
  } catch (e) {
    console.error(e);
    return json({ error: "Could not confirm payment." }, 500);
  }
}

// ---- /api/verify ----
async function verifyToken(request, env) {
  try {
    const body = await request.json().catch(() => ({}));
    const t = await verify(env, body.token);
    if (!t) return json({ ok: false });
    if (t.plan === "course") return json({ ok: true, plan: "course" });
    if ((t.plan === "m" || t.plan === "y") && t.sub) {
      const sub = await stripe(env, "GET", "/subscriptions/" + encodeURIComponent(t.sub));
      return json({ ok: sub.status === "active" || sub.status === "trialing", plan: t.plan });
    }
    return json({ ok: false });
  } catch (e) {
    console.error(e);
    return json({ error: "Verification failed" }, 500);
  }
}

// ---- /api/webhook (cash-back) ----
const enc = new TextEncoder();
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
async function verifyStripeSignature(rawBody, header, secret, toleranceSec = 300) {
  if (!header || !secret) return false;
  let t = null;
  const sigs = [];
  for (const part of header.split(",")) {
    const [k, v] = part.split("=");
    if (k === "t") t = v;
    else if (k === "v1") sigs.push(v);
  }
  if (!t || sigs.length === 0) return false;
  if (Math.abs(Date.now() / 1000 - Number(t)) > toleranceSec) return false;
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(`${t}.${rawBody}`)));
  const expected = [...mac].map((b) => b.toString(16).padStart(2, "0")).join("");
  return sigs.some((s) => timingSafeEqual(s, expected));
}

async function webhook(request, env) {
  const raw = await request.text();
  if (!(await verifyStripeSignature(raw, request.headers.get("stripe-signature"), env.STRIPE_WEBHOOK_SECRET))) {
    return json({ error: "Invalid signature" }, 400);
  }
  const event = JSON.parse(raw);
  try {
    if (event.type === "customer.subscription.deleted") await onSubscriptionEnded(event.data.object, env);
    return json({ received: true });
  } catch (e) {
    console.error("webhook failed", event.id, e);
    return json({ error: "Handler error" }, 500); // Stripe retries
  }
}

async function onSubscriptionEnded(sub, env) {
  const skip = (why) => console.log(`[cashback] ${sub.id}: skipped (${why})`);

  // Voluntary cancellations only
  const reason = sub.cancellation_details && sub.cancellation_details.reason;
  if (reason !== "cancellation_requested") return skip(`reason=${reason}`);

  // Cancelled during the trial => never billed
  const endedAt = sub.ended_at || Math.floor(Date.now() / 1000);
  if (sub.trial_end && endedAt <= sub.trial_end) return skip("cancelled during trial");

  const plan = sub.metadata && sub.metadata.plan;
  const percent = CASHBACK_PERCENT[plan];
  if (!percent) return skip(`no cash-back for plan=${plan}`);

  // Must have actually paid something
  const invoices = await stripe(env, "GET", "/invoices", { subscription: sub.id, status: "paid", limit: 100 });
  const paid = invoices.data.filter((i) => i.amount_paid > 0);
  if (paid.length === 0) return skip("no paid invoices");

  const totalPaid = paid.reduce((sum, i) => sum + i.amount_paid, 0);
  const cashback = Math.round((totalPaid * percent) / 100);

  const latest = paid.sort((a, b) => b.created - a.created)[0];
  if (!latest.charge) throw new Error(`Invoice ${latest.id} has no charge`);
  const charge = await stripe(env, "GET", "/charges/" + encodeURIComponent(latest.charge));

  // Stateless de-dupe against Stripe itself
  const existing = await stripe(env, "GET", "/refunds", { charge: charge.id, limit: 100 });
  if (existing.data.some((r) => r.metadata && r.metadata.cashback_for === sub.id)) return skip("already refunded");

  const amount = Math.min(cashback, charge.amount - charge.amount_refunded);
  if (amount <= 0) return skip("nothing refundable");

  const refund = await stripe(
    env, "POST", "/refunds",
    { charge: charge.id, amount, reason: "requested_by_customer", metadata: { cashback_for: sub.id, percent: String(percent), plan } },
    { "Idempotency-Key": `cashback-${sub.id}` }
  );
  console.log(`[cashback] ${sub.id}: refunded ${amount} cents (${percent}%) -> ${refund.id}`);
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    const m = request.method;
    if (pathname === "/api/checkout" && m === "POST") return checkout(request, env);
    if (pathname === "/api/session" && m === "GET") return session(request, env);
    if (pathname === "/api/verify" && m === "POST") return verifyToken(request, env);
    if (pathname === "/api/webhook" && m === "POST") return webhook(request, env);
    if (pathname.startsWith("/api/")) return json({ error: "Not found" }, 404);

    const res = await env.ASSETS.fetch(request);
    const type = res.headers.get("content-type") || "";
    if (!type.includes("text/html")) return res;
    // Fix displayed price/trial text without touching the page files
    let html = await res.text();
    html = html
      .replaceAll("$59", () => "$50")
      .replace("Sage+ starts with a 2-week free trial,", () => "Sage+ starts with a free trial (2 weeks monthly, 1 week annual),");
    const headers = new Headers(res.headers);
    headers.delete("content-length");
    headers.delete("content-encoding");
    headers.delete("etag");
    return new Response(html, { status: res.status, headers });
  },
};
