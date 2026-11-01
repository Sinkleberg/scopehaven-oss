// The authorization record for the local copy, drafted from five questions:
//   1. client            who the app belongs to (signer.organization)
//   2. hosts             the loopback origins the run may contact (origins)
//   3. permitted actions what the run may do (rules of engagement)
//   4. data class        what data the copy holds (rules of engagement)
//   5. contact           who agreed and is reachable during the test (signer.name and signer.role)
// The record format (scopehaven-authorization/1, checked by integrations/roe) has no fields for 3 and 4, so they go into a
// short rules-of-engagement file whose sha256 the record binds (rulesOfEngagement.sha256), as docs/RULES-OF-ENGAGEMENT.md
// intends. The signed-authorization boundary stays: init writes a draft, and seals it only when the operator confirms
// they are authorized to test this copy. The checksum is unkeyed; it is not a signature.
import { createHash } from 'node:crypto';
import { AUTHORIZATION_SCHEMA, checksumAuthorization, validateAuthorization } from '../../src/authorization.mjs';

export const QUESTIONS = Object.freeze([
  { key: 'client', prompt: 'Whose application is this (organization or owner)?' },
  { key: 'hosts', prompt: 'Which loopback origins may the run contact? (comma separated)' },
  { key: 'actions', prompt: 'What may the run do? (default: read-only GET requests from the drafted profile, no writes)' },
  { key: 'dataClass', prompt: 'What data does this copy hold? (default: synthetic test data only)' },
  { key: 'contact', prompt: 'Who agreed to this test and can be reached during it? (name, role)' },
]);
export const DEFAULT_ACTIONS = 'read-only GET requests from the drafted profile; no writes';
export const DEFAULT_DATA_CLASS = 'synthetic test data only';
const at = ms => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
const oneLine = (value, max) => String(value ?? '').replace(/[\u0000-\u001f\u007f]+/g, ' ').trim().slice(0, max);

export function parseContact(text) {
  const [name, ...rest] = String(text ?? '').split(',');
  return { name: oneLine(name, 120), role: oneLine(rest.join(',') || 'Owner of the local copy', 120) };
}

export function rulesOfEngagementText({ id, origin, answers, identities, validFrom, validUntil }) {
  return [
    `# Rules of engagement: ${id} (local copy)`,
    '',
    'Drafted by `scopehaven init` from five answers; the record binds this file\'s sha256. To change it, run init again with other answers: init rewrites this file and the draft, and removes any record sealed before.',
    '',
    `- Client: ${oneLine(answers.client, 160)}`,
    `- Hosts the run may contact: ${answers.hosts.join(', ')}`,
    `- Permitted actions: ${oneLine(answers.actions, 400)}`,
    `- Data class: ${oneLine(answers.dataClass, 200)}`,
    `- Contact: ${answers.contact.name} (${answers.contact.role})`,
    `- Test accounts (principal ids): ${identities.join(', ')}`,
    `- Window: ${validFrom} to ${validUntil}`,
    `- Target: ${origin}, a local copy on loopback. No production system, customer data or third party is in scope.`,
    '',
  ].join('\n');
}

export function draftAuthorization({ id, origin, answers, identities, now = new Date(), hours = 8 }) {
  const validFrom = at(now.getTime() - 60000), validUntil = at(now.getTime() + hours * 3600000);
  const roeText = rulesOfEngagementText({ id, origin, answers, identities, validFrom, validUntil });
  const record = {
    schema: AUTHORIZATION_SCHEMA, id: `${id.slice(0, 63)}-local-${validFrom.slice(0, 10)}`, target: { id, applicationId: id }, origins: answers.hosts, identities,
    validFrom, validUntil, signer: { name: answers.contact.name, role: answers.contact.role, organization: oneLine(answers.client, 160) }, signedAt: at(now.getTime() - 1000),
    rulesOfEngagement: { title: oneLine(`${id} local copy: rules of engagement drafted by scopehaven init`, 200), sha256: createHash('sha256').update(roeText).digest('hex') },
  };
  return { draft: record, roeText };
}

// Seals the draft (adds the checksum) and validates it; throws the roe checker's AuthorizationError on a bad draft.
export function sealAuthorization(draft) {
  const sealed = checksumAuthorization(draft);
  validateAuthorization(sealed);
  return sealed;
}
