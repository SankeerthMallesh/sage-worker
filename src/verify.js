import { json, stripe, verify } from './util.js';

// Re-checks an unlock token. Subscriptions are checked live, so cancelling Sage+ takes it away.
export async function handle(request, env) {
  try {
    const body = await request.json().catch(() => ({}));
    const t = await verify(env, body.token);
    if (!t) return json({ ok: false });
    if (t.plan === 'course') return json({ ok: true, plan: 'course' });
    if ((t.plan === 'm' || t.plan === 'y') && t.sub) {
      const sub = await stripe(env, 'GET', '/subscriptions/' + encodeURIComponent(t.sub));
      return json({ ok: sub.status === 'active' || sub.status === 'trialing', plan: t.plan });
    }
    return json({ ok: false });
  } catch (e) {
    console.error(e);
    return json({ error: 'Verification failed' }, 500);
  }
}
