#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import process from 'node:process';

import {
  canonicalJson,
  validateContextFirewallPacket,
} from '../src/context-firewall-v1.js';
import { runContextFirewallConformance } from '../src/conformance.js';

function usage() {
  return [
    'usage: decision-evidence validate-context-firewall [--packet PATH|-] [--source-input PATH]',
    '       decision-evidence conformance',
    '',
  ].join('\n');
}

async function readBytes(path) {
  if (path !== '-') return readFile(path);
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks);
}

function parseValidateArgs(args) {
  let packet = '-';
  let sourceInput = null;
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === '--packet' && args[index + 1]) packet = args[++index];
    else if (args[index] === '--source-input' && args[index + 1]) sourceInput = args[++index];
    else throw new TypeError(`unknown or incomplete argument: ${args[index]}`);
  }
  return { packet, sourceInput };
}

async function parseJsonFile(path, label) {
  const bytes = await readBytes(path);
  try {
    return { bytes, value: JSON.parse(bytes.toString('utf8')) };
  } catch {
    throw new TypeError(`${label} must be valid JSON`);
  }
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === 'conformance') {
    if (args.length > 0) throw new TypeError('conformance accepts no arguments');
    const report = await runContextFirewallConformance();
    process.stdout.write(`${canonicalJson(report)}\n`);
    process.exitCode = report.conformance === 'PASS' ? 0 : 1;
    return;
  }
  if (command !== 'validate-context-firewall') {
    process.stderr.write(usage());
    process.exitCode = 2;
    return;
  }
  const options = parseValidateArgs(args);
  const packet = await parseJsonFile(options.packet, 'packet');
  const sourceInput = options.sourceInput === null
    ? undefined
    : (await parseJsonFile(options.sourceInput, 'source input')).value;
  const result = validateContextFirewallPacket(packet.value, {
    packetBytes: packet.bytes,
    sourceInput,
  });
  process.stdout.write(`${canonicalJson(result)}\n`);
  process.exitCode = result.valid ? 0 : 1;
}

main().catch((error) => {
  process.stderr.write(`${canonicalJson({ code: 'INVALID_INVOCATION', message: error.message })}\n`);
  process.exitCode = 2;
});
