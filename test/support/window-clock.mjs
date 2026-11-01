// A test-only clock for the authorization-window cases, so a window can end at a moment the test chooses instead of a
// wall-clock deadline a loaded machine can miss. Production code never imports this file.
//
// The window guard (src/authorization.mjs windowGuard) reads `Date.now` once, when an entry point builds it at the
// start of a run, and calls that function before every request. A test makes the window long (a minute), installs the
// clock below just before the run starts, and at the moment the target receives the request the case is about, jumps
// the clock past the record's validUntil. At that moment the real Date.now goes back on the global, so only the guard,
// which captured the test clock at the start, sees the jump: the run's other clocks (the suspend detector, timers,
// timestamps) keep the real time.
//
// In process (the gate, the dashboard, sequences, conversations): installClock() and jumpPast(validUntil).
// In a child process (the assess CLI): spawn node with `--import <this file>` and SCOPEHAVEN_TEST_WINDOW_CLOCK naming a
// file. The child's clock follows the file: until it holds a time, the real clock; once it holds one, that time plus the
// real time elapsed since it was read. The test writes the file with writeJump(file, validUntil). In the child the global
// goes back to the real Date.now when the jump is first read, so the one caller that reads it, whichever that is, gets
// one jumped value: the guard, or another reader such as the suspend detector's wall clock, which records it as a wall
// step and does not stop the run on it. Every later reader but the guard sees the real time.
import { readFileSync, renameSync, writeFileSync } from 'node:fs';

export const realNow = Date.now.bind(Date);
// How far past validUntil a jump lands.
const PAST_MS = 1;

export function installClock() {
  const original = Date.now;
  let offset = 0;
  const clock = () => realNow() + offset;
  Date.now = clock;
  return Object.freeze({
    // Jump the captured clock past `untilMs`, and put the real Date.now back on the global.
    jumpPast(untilMs) { offset = untilMs + PAST_MS - realNow(); Date.now = original; },
    restore() { Date.now = original; },
  });
}

// Written whole under a temporary name, then renamed, so the child never reads a half-written file.
export function writeJump(file, untilMs) { writeFileSync(`${file}.tmp`, String(untilMs + PAST_MS), { mode: 0o600 }); renameSync(`${file}.tmp`, file); }

// The child-process half, active only when this file is preloaded (`--import`) with the variable set, so a test process
// that imports it for installClock is unaffected even if the variable is set in its environment.
const file = process.env.SCOPEHAVEN_TEST_WINDOW_CLOCK;
const preloaded = process.execArgv.some((arg, i, all) => (arg === '--import' ? all[i + 1] : arg.startsWith('--import=') ? arg.slice(9) : '').includes('window-clock.mjs'));
if (file && preloaded) {
  let offset = 0, jumped = false, checkedAt = -Infinity;
  const clock = () => {
    if (!jumped) {
      const t = performance.now();
      if (t - checkedAt >= 5) {
        checkedAt = t;
        let target = NaN;
        try { target = Number(readFileSync(file, 'utf8')); } catch {}
        if (Number.isSafeInteger(target) && target > 0) { offset = target - realNow(); jumped = true; Date.now = realNow; }
      }
    }
    return realNow() + offset;
  };
  Date.now = clock;
}
