#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

import {
  canonicalJson,
  validateContextFirewallPacket,
} from '../src/context-firewall-v1.js';

const EXPECTED_CONTEXT_FIREWALL_SHA = 'dd34bd9f681314761f1ca87f339648bf611811f3';

function gitHead(path) {
  const result = spawnSync('git', ['-C', path, 'rev-parse', 'HEAD'], { encoding: 'utf8' });
  if (result.status !== 0) throw new Error(result.stderr.trim() || `cannot read Git HEAD at ${path}`);
  return result.stdout.trim();
}

async function main() {
  const contextPath = resolve(process.argv[2] ?? '../context-firewall');
  const contextHead = gitHead(contextPath);
  if (contextHead !== EXPECTED_CONTEXT_FIREWALL_SHA) {
    throw new Error(`Context Firewall HEAD ${contextHead} does not match ${EXPECTED_CONTEXT_FIREWALL_SHA}`);
  }
  const reducer = await import(pathToFileURL(resolve(contextPath, 'src/reducer.js')));
  const fixtures = await import(pathToFileURL(resolve(contextPath, 'fixtures/corpus.js')));
  const cases = [
    ['normal-success', 'normal/small-all-pass', 'SUFFICIENT'],
    ['failure', 'failure/one', 'SUFFICIENT'],
    ['suppression-heavy', 'normal/large-all-pass', 'SUFFICIENT'],
    ['needs-raw-evidence', 'process/interrupted-truncated', 'NEEDS_RAW_EVIDENCE'],
  ].map(([id, fixtureName, expectedSufficiency]) => {
    const fixture = fixtures.corpus.find((item) => item.name === fixtureName);
    const packet = reducer.reduceTestRun(fixture.input, fixture.options);
    const packetBytes = reducer.serializePacket(packet);
    const result = validateContextFirewallPacket(packet, {
      packetBytes,
      sourceInput: fixture.input,
    });
    return {
      classification: result.classification,
      id,
      pass: result.valid && result.sufficiency === expectedSufficiency,
      producer_fixture: fixtureName,
      sufficiency: result.sufficiency,
    };
  });
  const tamperFixture = fixtures.corpus.find((item) => item.name === 'normal/small-all-pass');
  const tampered = reducer.reduceTestRun(tamperFixture.input);
  tampered.receipt.input_hash = `sha256:${'0'.repeat(64)}`;
  const tamperResult = validateContextFirewallPacket(tampered, {
    packetBytes: Buffer.from(`${canonicalJson(tampered)}\n`, 'utf8'),
    sourceInput: tamperFixture.input,
  });
  cases.push({
    classification: tamperResult.classification,
    id: 'tampered-copy',
    pass: !tamperResult.valid
      && tamperResult.violations.some((violation) => violation.code === 'INPUT_HASH_MISMATCH'),
    sufficiency: tamperResult.sufficiency,
  });
  const report = {
    case_count: cases.length,
    cases,
    conformance: cases.every((item) => item.pass) ? 'PASS' : 'FAIL',
    context_firewall_revision: contextHead,
    decision_evidence_revision: gitHead(resolve('.')),
    protocol_version: 'opsle.decision-evidence.context-firewall-interop/v1',
  };
  process.stdout.write(`${canonicalJson(report)}\n`);
  process.exitCode = report.conformance === 'PASS' ? 0 : 1;
}

main().catch((error) => {
  process.stderr.write(`${canonicalJson({ code: 'INTEROP_FAILED', message: error.message })}\n`);
  process.exitCode = 1;
});
