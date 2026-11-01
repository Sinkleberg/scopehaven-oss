#!/usr/bin/env node
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { assertRuntime } from '../../src/runtime.mjs';
import { ImportFailure } from './bounded-json.mjs';
import { INPUT_CONTRACT, LIMITS, failureResult, importPromptfooJson } from './import.mjs';

// I/O wrapper only. No filesystem writes, stdin, URLs, provider dependencies,
// network calls or native storage. Do not mount this CLI as a web endpoint.
export async function importLocalFile(path, format) {
  if (format !== INPUT_CONTRACT) return failureResult('unsupported_format');
  if (typeof path !== 'string' || !path.length || path.length > 4096 || path.includes('\0') ||
      /^[A-Za-z][A-Za-z0-9+.-]*:/.test(path)) return failureResult('invalid_file');
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile()) throw new ImportFailure('invalid_file');
    if (before.size > BigInt(LIMITS.maxBytes)) throw new ImportFailure('input_limit');
    const buffer = Buffer.alloc(LIMITS.maxBytes + 1);
    let size = 0;
    while (size < buffer.length) {
      const { bytesRead } = await handle.read(buffer, size, buffer.length - size, size);
      if (bytesRead === 0) break;
      size += bytesRead;
    }
    if (size > LIMITS.maxBytes) throw new ImportFailure('input_limit');
    const after = await handle.stat({ bigint: true });
    if (before.size !== after.size || BigInt(size) !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) throw new ImportFailure('file_changed');
    let text;
    try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buffer.subarray(0, size)); }
    catch { throw new ImportFailure('invalid_utf8'); }
    return importPromptfooJson(text, format);
  } catch (error) {
    return failureResult(error instanceof ImportFailure ? error.code : 'invalid_file');
  } finally {
    await handle?.close().catch(() => {});
  }
}

export async function main(args) {
  try { assertRuntime(); } catch { return failureResult('runtime_unsupported'); }
  if (!Array.isArray(args) || args.length !== 4 || args[0] !== '--format' || args[2] !== '--input') return failureResult('usage');
  return importLocalFile(args[3], args[1]);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const result = await main(process.argv.slice(2));
  const output = result.ok ? process.stdout : process.stderr;
  output.write(`${JSON.stringify(result.ok ? result.record : result, null, 2)}\n`);
  if (!result.ok) process.exitCode = 2;
}
