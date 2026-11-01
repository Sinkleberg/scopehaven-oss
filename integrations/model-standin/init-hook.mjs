// init hook: `scopehaven init` (integrations/init/hooks.mjs) loads this module and calls draftForInit({ profile, openapi,
// root }), expecting { checks, notDrafted, warnings }. The model stand-in drafts no checks: it is the model the application talks
// to on a first run, so that run needs no provider key and no spend. The hook returns the plan to start from, the command and the
// environment lines that point an OpenAI-compatible app at it, with checks empty. Starting it, and pointing the application at
// it, is the operator's step (the application's own configuration); the hook starts nothing and sends nothing.
import { EXAMPLE_PLAN, validatePlan } from './server.mjs';
import { envLines } from './cli.mjs';

export const DEFAULT_PORT = 4471;

export async function draftForInit({ profile: _profile, openapi: _openapi, root: _root, port = DEFAULT_PORT } = {}) {
  const plan = validatePlan(structuredClone(EXAMPLE_PLAN));
  const origin = `http://127.0.0.1:${port}`;
  return {
    checks: [],
    notDrafted: [{ reason: 'the model stand-in drafts no checks: it stands in for the model so a first run needs no provider key' }],
    warnings: [],
    standIn: {
      plan,
      commands: ['node integrations/model-standin/cli.mjs example-plan --out standin-plan.json', `node integrations/model-standin/cli.mjs serve --plan standin-plan.json --port ${port}`],
      env: envLines(origin),
      note: 'Point the application\'s OpenAI-compatible provider at the base URL (integrations/model-standin/README.md lists the usual settings); edit the plan so its tool calls match the tools the app offers.',
    },
  };
}
