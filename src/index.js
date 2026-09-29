import { json } from './util.js';
import { handle as checkout } from './checkout.js';
import { handle as session } from './session.js';
import { handle as verify } from './verify.js';

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    const m = request.method;
    if (pathname === '/api/checkout' && m === 'POST') return checkout(request, env);
    if (pathname === '/api/session' && m === 'GET') return session(request, env);
    if (pathname === '/api/verify' && m === 'POST') return verify(request, env);
    if (pathname.startsWith('/api/')) return json({ error: 'Not found' }, 404);
    return env.ASSETS.fetch(request); // everything else is the static site
  },
};
