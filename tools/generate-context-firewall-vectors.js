#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const EXPECTED_CONTEXT_FIREWALL_SHA = '953c48f1cfd154d6b7ed10b51b87fe54e4df45f2';

function parseArgs(args) {
  const options = {
    contextFirewall: '../context-firewall',
    output: 'fixtures/context-firewall-packet-v1/vectors.json',
  };
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === '--context-firewall' && args[index + 1]) {
      options.contextFirewall = args[++index];
    } else if (args[index] === '--output' && args[index + 1]) options.output = args[++index];
    else throw new TypeError(`unknown or incomplete argument: ${args[index]}`);
  }
  return options;
}

function gitHead(path) {
  const result = spawnSync('git', ['-C', path, 'rev-parse', 'HEAD'], { encoding: 'utf8' });
  if (result.status !== 0) throw new Error(result.stderr.trim() || 'cannot read Context Firewall HEAD');
  return result.stdout.trim();
}

function expected(valid, classification, sufficiency, violationCodes = []) {
  return {
    classification,
    sufficiency,
    valid,
    ...(violationCodes.length > 0 ? { violation_codes: violationCodes } : {}),
  };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const contextPath = resolve(options.contextFirewall);
  const head = gitHead(contextPath);
  if (head !== EXPECTED_CONTEXT_FIREWALL_SHA) {
    throw new Error(`Context Firewall HEAD ${head} does not match ${EXPECTED_CONTEXT_FIREWALL_SHA}`);
  }
  const fixtures = await import(pathToFileURL(resolve(contextPath, 'fixtures/corpus.js')));
  const selected = [
    ['successful-reduced-run', 'normal/small-all-pass'],
    ['failed-test-packet', 'failure/one'],
    ['multiple-failures', 'failure/several'],
    ['large-successful-suppression', 'normal/large-all-pass'],
    ['valid-raw-evidence-reference', 'provenance/raw-reference-present'],
    ['valid-needs-raw-evidence', 'process/interrupted-truncated'],
    ['ambiguous-evidence-escalation', 'edge/malformed-output'],
    ['ceiling-triggered-escalation', 'payload/critical-too-large'],
    ['exact-payload-boundary', 'payload/exact-boundary'],
  ];
  const validVectors = selected.map(([id, fixtureName]) => {
    const fixture = fixtures.corpus.find((item) => item.name === fixtureName);
    if (!fixture) throw new Error(`missing producer fixture ${fixtureName}`);
    const execution = fixtures.executeFixture(fixture);
    if (!execution.pass || !execution.packet) {
      throw new Error(`producer fixture ${fixtureName} did not yield a valid packet`);
    }
    const packet = execution.packet;
    const valueReceipt = execution.valueReceipt;
    valueReceipt.mechanism.revision = head;
    const sufficiency = packet.decision_evidence.disposition;
    return {
      expected: expected(
        true,
        'VALID',
        sufficiency === 'SUFFICIENT' ? 'SUFFICIENT' : 'NEEDS_RAW_EVIDENCE',
      ),
      id,
      packet,
      producer_fixture: fixtureName,
      source_input: fixture.input,
      value_receipt: valueReceipt,
    };
  });

  const invalidVectors = [
    {
      id: 'missing-required-field', base: 'successful-reduced-run',
      packet_mutations: [{ op: 'remove', path: '/receipt/input_hash' }],
      expected: expected(false, 'STRUCTURALLY_INVALID', 'INVALID', ['MALFORMED_SHA256']),
    },
    {
      id: 'unsupported-schema-version', base: 'successful-reduced-run',
      packet_mutations: [{ op: 'replace', path: '/protocol_version', value: 'opsle.context-firewall.evidence-packet/v2' }],
      expected: expected(false, 'STRUCTURALLY_INVALID', 'INVALID', ['UNSUPPORTED_PACKET_VERSION']),
    },
    {
      id: 'malformed-hash', base: 'successful-reduced-run',
      packet_mutations: [{ op: 'replace', path: '/receipt/input_hash', value: 'sha256:not-a-digest' }],
      expected: expected(false, 'STRUCTURALLY_INVALID', 'INVALID', ['MALFORMED_SHA256']),
    },
    {
      id: 'wrong-source-hash', base: 'successful-reduced-run',
      packet_mutations: [{ op: 'replace', path: '/receipt/input_hash', value: `sha256:${'0'.repeat(64)}` }],
      refresh_reduced_bytes: true,
      expected: expected(false, 'CRYPTOGRAPHIC_MISMATCH', 'INVALID', ['INPUT_HASH_MISMATCH']),
    },
    {
      id: 'wrong-reduced-packet-hash', base: 'successful-reduced-run',
      packet_mutations: [{ op: 'replace', path: '/receipt/semantic_payload_hash', value: `sha256:${'1'.repeat(64)}` }],
      refresh_reduced_bytes: true,
      expected: expected(false, 'CRYPTOGRAPHIC_MISMATCH', 'INVALID', ['SEMANTIC_PAYLOAD_HASH_MISMATCH']),
    },
    {
      id: 'tampered-source-bytes', base: 'successful-reduced-run',
      source_mutations: [{ op: 'replace', path: '/streams/0/data', value: 'TAP version 13\nok 1 - tampered\n1..1\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n' }],
      expected: expected(false, 'CRYPTOGRAPHIC_MISMATCH', 'INVALID', ['INPUT_HASH_MISMATCH']),
    },
    {
      id: 'impossible-byte-counts', base: 'successful-reduced-run',
      packet_mutations: [{ op: 'replace', path: '/receipt/measurements/original_bytes', value: 105 }],
      refresh_reduced_bytes: true,
      expected: expected(false, 'INTERNALLY_INCONSISTENT', 'INVALID', ['ORIGINAL_BYTE_COUNT_MISMATCH']),
    },
    {
      id: 'impossible-evidence-counts', base: 'successful-reduced-run',
      packet_mutations: [{ op: 'replace', path: '/receipt/measurements/original_event_count', value: 1 }],
      refresh_reduced_bytes: true,
      expected: expected(false, 'INTERNALLY_INCONSISTENT', 'INVALID', ['EVIDENCE_ACCOUNTING_MISMATCH']),
    },
    {
      id: 'contradictory-suppression-accounting', base: 'successful-reduced-run',
      packet_mutations: [{ op: 'replace', path: '/receipt/suppressed/categories/successful_test', value: 3 }],
      refresh_reduced_bytes: true,
      expected: expected(false, 'INTERNALLY_INCONSISTENT', 'INVALID', ['SUPPRESSION_CATEGORY_TOTAL_MISMATCH']),
    },
    {
      id: 'invalid-escalation-state', base: 'valid-needs-raw-evidence',
      packet_mutations: [{ op: 'replace', path: '/receipt/raw_evidence/escalation_required', value: false }],
      refresh_reduced_bytes: true,
      expected: expected(false, 'INTERNALLY_INCONSISTENT', 'INVALID', ['ESCALATION_REQUIRED_MISMATCH']),
    },
    {
      id: 'negative-measurement', base: 'successful-reduced-run',
      packet_mutations: [{ op: 'replace', path: '/receipt/measurements/suppressed_evidence_count', value: -1 }],
      expected: expected(false, 'STRUCTURALLY_INVALID', 'INVALID', ['INVALID_MEASUREMENT']),
    },
    {
      id: 'overflow-like-measurement', base: 'successful-reduced-run',
      packet_mutations: [{ op: 'replace', path: '/receipt/measurements/original_bytes', value: 9007199254740992 }],
      expected: expected(false, 'STRUCTURALLY_INVALID', 'INVALID', ['INVALID_MEASUREMENT']),
    },
    {
      id: 'malformed-raw-evidence-locator', base: 'successful-reduced-run',
      packet_mutations: [{ op: 'replace', path: '/receipt/raw_evidence/reference', value: '' }],
      expected: expected(false, 'STRUCTURALLY_INVALID', 'INVALID', ['INVALID_IDENTITY']),
    },
    {
      id: 'false-sufficiency-claim', base: 'valid-needs-raw-evidence',
      packet_mutations: [{ op: 'replace', path: '/decision_evidence/disposition', value: 'SUFFICIENT' }],
      refresh_semantic_hash: true,
      refresh_reduced_bytes: true,
      expected: expected(false, 'INTERNALLY_INCONSISTENT', 'INVALID', ['DISPOSITION_MISMATCH']),
    },
    {
      id: 'wrong-reduced-byte-measurement', base: 'successful-reduced-run',
      packet_mutations: [{ op: 'replace', path: '/receipt/measurements/reduced_bytes', value: 1 }],
      expected: expected(false, 'INTERNALLY_INCONSISTENT', 'INVALID', ['REDUCED_BYTE_COUNT_MISMATCH']),
    },
  ];
  const output = {
    context_firewall_revision: head,
    invalid_vectors: invalidVectors,
    protocol_version: 'opsle.decision-evidence.context-firewall-conformance/v1',
    valid_vectors: validVectors,
  };
  await writeFile(resolve(options.output), `${JSON.stringify(output, null, 2)}\n`, 'utf8');
  process.stdout.write(`${JSON.stringify({ output: resolve(options.output), vector_count: validVectors.length + invalidVectors.length })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${JSON.stringify({ code: 'GENERATION_FAILED', message: error.message })}\n`);
  process.exitCode = 1;
});
