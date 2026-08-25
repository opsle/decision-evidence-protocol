#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises';
import process from 'node:process';

import {
  canonicalJson,
  validateContextFirewallPacket,
} from '../src/context-firewall-v1.js';
import { runContextFirewallConformance } from '../src/conformance.js';
import {
  createValidationValueReceipt,
  formatDecisionEvidenceIndicator,
  validateContextFirewallValueReceipt,
} from '../src/context-firewall-value.js';

function usage() {
  return [
    'usage: decision-evidence validate-context-firewall [--packet PATH|-] [--source-input PATH]',
    '                         [--mechanism-revision REV] [--value-receipt PATH]',
    '       decision-evidence validate-context-firewall-value --receipt PATH --packet PATH',
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
  let mechanismRevision = null;
  let valueReceipt = null;
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === '--packet' && args[index + 1]) packet = args[++index];
    else if (args[index] === '--source-input' && args[index + 1]) sourceInput = args[++index];
    else if (args[index] === '--mechanism-revision' && args[index + 1]) mechanismRevision = args[++index];
    else if (args[index] === '--value-receipt' && args[index + 1]) valueReceipt = args[++index];
    else throw new TypeError(`unknown or incomplete argument: ${args[index]}`);
  }
  return { mechanismRevision, packet, sourceInput, valueReceipt };
}

function parseValueArgs(args) {
  let packet = null;
  let receipt = null;
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === '--packet' && args[index + 1]) packet = args[++index];
    else if (args[index] === '--receipt' && args[index + 1]) receipt = args[++index];
    else throw new TypeError(`unknown or incomplete argument: ${args[index]}`);
  }
  if (packet === null || receipt === null) throw new TypeError('--packet and --receipt are required');
  return { packet, receipt };
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
  if (command === 'validate-context-firewall-value') {
    const options = parseValueArgs(args);
    const packet = await parseJsonFile(options.packet, 'packet');
    const receipt = await parseJsonFile(options.receipt, 'value receipt');
    const result = validateContextFirewallValueReceipt(receipt.value, packet.value);
    process.stdout.write(`${canonicalJson(result)}\n`);
    process.stderr.write(result.valid
      ? '[Decision Evidence] Context Firewall value receipt verified | 11 measurements checked\n'
      : `[Decision Evidence] Context Firewall value receipt rejected | ${result.violations.length} violation(s)\n`);
    process.exitCode = result.valid ? 0 : 1;
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
  if (options.valueReceipt !== null) {
    const receipt = createValidationValueReceipt(packet.value, result, {
      mechanismRevision: options.mechanismRevision,
    });
    await writeFile(options.valueReceipt, `${canonicalJson(receipt)}\n`, 'utf8');
  }
  process.stdout.write(`${canonicalJson(result)}\n`);
  process.stderr.write(`${formatDecisionEvidenceIndicator(result)}\n`);
  process.exitCode = result.valid ? 0 : 1;
}

main().catch((error) => {
  process.stderr.write(`${canonicalJson({ code: 'INVALID_INVOCATION', message: error.message })}\n`);
  process.exitCode = 2;
});
