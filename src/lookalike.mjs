// The invalid-credential probe for actor identity proofs (HTTP connector and
// conversation connector): a per-run random look-alike of the actor's own
// credential. It is listed in both identity sets (src/http-connector.mjs
// evaluatorHash and CONVERSATION_EVALUATOR_FILES), so a change here moves both.
import { createHmac } from 'node:crypto';

// Same length and character class at every position (lower, upper, digit; any other
// character is kept, so a JWT keeps its dots), drawn from HMAC(secret, actor, block).
// A credential with no letters or digits gets a fresh random token instead.
const CLASSES = ['abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', '0123456789'];
export function lookalikeCredential(real, secret, actorId) {
  if (![...real].some(ch => CLASSES.some(c => c.includes(ch)))) return createHmac('sha256', secret).update(`${actorId}\0token`).digest('base64url');
  for (let attempt = 0; ; attempt++) {
    const stream = [];
    while (stream.length < real.length) stream.push(...createHmac('sha256', secret).update(`${actorId}\0${attempt}\0${stream.length}`).digest());
    let i = 0;
    const out = [...real].map(ch => { const set = CLASSES.find(c => c.includes(ch)); return set ? set[stream[i++] % set.length] : ch; }).join('');
    if (out !== real) return out; // a draw equal to the real credential (a very short one) is redrawn
  }
}
