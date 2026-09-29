import { PLANS, json, stripe, sign } from './util.js';

// Confirms with Stripe that the session is really complete, then returns a signed unlock token.
export async function handle(request, env) {
  try {
    const id = String(new URL(request.url).searchParams.get('id') || '');
    if (!/^cs_/.test(id)) return json({ error: 'Bad session id' }, 400);
    const s = await stripe(env, 'GET', '/checkout/sessions/' + encodeURIComponent(id));
    const plan = s.metadata && s.metadata.plan;
    if (!PLANS[plan]) return json({ error: 'Unknown plan' }, 400);
    // A free trial completes checkout with payment_status "no_payment_required".
    const paidOk = s.payment_status === 'paid' || (s.mode === 'subscription' && s.payment_status === 'no_payment_required');
    if (s.status !== 'complete' || !paidOk) return json({ error: 'Payment not completed yet' }, 402);
    const sub = typeof s.subscription === 'string' ? s.subscription : (s.subscription && s.subscription.id) || null;
    return json({ plan, token: await sign(env, { plan, sub, iat: Date.now() }) });
  } catch (e) {
    console.error(e);
    return json({ error: 'Could not confirm payment.' }, 500);
  }
}
