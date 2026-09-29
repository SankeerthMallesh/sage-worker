import { PLANS, json, stripe } from './util.js';

export async function handle(request, env) {
  try {
    const body = await request.json().catch(() => ({}));
    const plan = body.plan;
    const p = PLANS[plan];
    if (!p) return json({ error: 'Unknown plan' }, 400);
    if (!env.STRIPE_PUBLISHABLE_KEY) throw new Error('STRIPE_PUBLISHABLE_KEY is not set');
    const origin = new URL(request.url).origin;
    const price_data = { currency: 'usd', unit_amount: p.amount, product_data: { name: p.name, description: p.desc } };
    if (p.interval) price_data.recurring = { interval: p.interval };
    const params = {
      ui_mode: 'embedded',
      mode: p.mode,
      line_items: [{ quantity: 1, price_data }],
      allow_promotion_codes: true,
      metadata: { plan },
      redirect_on_completion: 'if_required',
      return_url: `${origin}/?session_id={CHECKOUT_SESSION_ID}`,
    };
    if (p.mode === 'subscription') params.subscription_data = { metadata: { plan }, trial_period_days: p.trialDays };
    const session = await stripe(env, 'POST', '/checkout/sessions', params);
    return json({ clientSecret: session.client_secret, sessionId: session.id, publishableKey: env.STRIPE_PUBLISHABLE_KEY });
  } catch (e) {
    console.error(e);
    return json({ error: 'Checkout is unavailable right now. Please try again.' }, 500);
  }
}
