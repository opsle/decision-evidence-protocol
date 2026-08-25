import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  canonicalJson,
  validateContextFirewallPacket,
} from '../src/context-firewall-v1.js';
import {
  loadContextFirewallVectors,
  runContextFirewallConformance,
} from '../src/conformance.js';

const cliPath = fileURLToPath(new URL('../bin/decision-evidence.js', import.meta.url));
const vectors = await loadContextFirewallVectors();

function vector(id) {
  const result = vectors.valid_vectors.find((item) => item.id === id);
  assert.ok(result, `missing vector ${id}`);
  return structuredClone(result);
}

function packetBytes(packet) {
  return Buffer.from(`${canonicalJson(packet)}\n`, 'utf8');
}

function refreshReducedBytes(packet) {
  let length = packet.receipt.measurements.reduced_bytes;
  for (let iteration = 0; iteration < 12; iteration += 1) {
    packet.receipt.measurements.reduced_bytes = length;
    const next = packetBytes(packet).length;
    if (next === length) return;
    length = next;
  }
  throw new Error('test packet measurement did not converge');
}

function sha256Canonical(value) {
  const digest = createHash('sha256');
  digest.update(Buffer.from(canonicalJson(value), 'utf8'));
  return `sha256:${digest.digest('hex')}`;
}

test('validates a receipt alone without claiming source verification', () => {
  const { packet } = vector('successful-reduced-run');
  const result = validateContextFirewallPacket(packet);
  assert.equal(result.valid, true);
  assert.equal(result.classification, 'VALID_WITH_UNVERIFIED_SOURCE');
  assert.equal(result.sufficiency, 'SUFFICIENT');
  assert.equal(result.evidence_sufficient, true);
  assert.equal(result.verification.input_hash, 'NOT_SUPPLIED');
  assert.equal(result.cryptographic_verification, 'PARTIAL');
  assert.equal(result.raw_evidence.locator_verification, 'CALLER_CLAIM_ONLY');
});

test('rejects unsupported packet, receipt, source, reducer, and policy versions', async (context) => {
  const cases = [
    ['/protocol_version', 'unsupported', 'UNSUPPORTED_PACKET_VERSION'],
    ['/receipt/receipt_version', 2, 'UNSUPPORTED_RECEIPT_VERSION'],
    ['/receipt/source/protocol_version', 'unsupported', 'UNSUPPORTED_SOURCE_PROTOCOL'],
    ['/receipt/reducer/version', '9.0.0', 'UNSUPPORTED_REDUCER_VERSION'],
    ['/receipt/configuration/policy_revision', 'policy/v9', 'UNSUPPORTED_POLICY_REVISION'],
  ];
  for (const [path, value, code] of cases) {
    await context.test(code, () => {
      const item = vector('successful-reduced-run');
      const parts = path.slice(1).split('/');
      const final = parts.pop();
      let parent = item.packet;
      for (const part of parts) parent = parent[part];
      parent[final] = value;
      const result = validateContextFirewallPacket(item.packet);
      assert.equal(result.classification, 'STRUCTURALLY_INVALID');
      assert.ok(result.violations.some((violation) => violation.code === code));
    });
  }
});

test('independently verifies source bytes, source accounting, and canonical packet bytes', () => {
  const item = vector('failed-test-packet');
  const result = validateContextFirewallPacket(item.packet, {
    packetBytes: packetBytes(item.packet),
    sourceInput: item.source_input,
  });
  assert.equal(result.valid, true);
  assert.equal(result.classification, 'VALID');
  assert.equal(result.cryptographic_verification, 'VERIFIED');
  assert.deepEqual(result.verification, {
    configuration_identity: 'VERIFIED',
    input_hash: 'VERIFIED',
    line_evidence_hashes: 'VERIFIED',
    packet_serialization: 'VERIFIED',
    reduced_bytes: 'VERIFIED',
    semantic_payload_hash: 'VERIFIED',
    source_accounting: 'VERIFIED',
  });
});

test('NEEDS_RAW_EVIDENCE is valid but never sufficient', () => {
  const item = vector('valid-needs-raw-evidence');
  const result = validateContextFirewallPacket(item.packet, {
    packetBytes: packetBytes(item.packet),
    sourceInput: item.source_input,
  });
  assert.equal(result.valid, true);
  assert.equal(result.sufficiency, 'NEEDS_RAW_EVIDENCE');
  assert.equal(result.raw_evidence_required, true);
  assert.equal(result.evidence_sufficient, false);
});

test('ambiguous evidence is accepted only as an escalation state', () => {
  const item = vector('ambiguous-evidence-escalation');
  const result = validateContextFirewallPacket(item.packet, { sourceInput: item.source_input });
  assert.equal(result.valid, true);
  assert.equal(result.raw_evidence_required, true);
  assert.ok(item.packet.decision_evidence.reason_codes.includes('UNCLASSIFIED_EVIDENCE'));
});

test('ceiling-triggered critical omission is valid only as insufficient evidence', () => {
  const item = vector('ceiling-triggered-escalation');
  const result = validateContextFirewallPacket(item.packet, { sourceInput: item.source_input });
  assert.equal(result.valid, true);
  assert.equal(result.sufficiency, 'NEEDS_RAW_EVIDENCE');
  assert.equal(item.packet.receipt.retained.event_count, 0);
  assert.ok(item.packet.decision_evidence.reason_codes
    .includes('PAYLOAD_LIMIT_CRITICAL_EVIDENCE_EXCEEDED'));
});

test('large successful suppression is independently accounted for', () => {
  const item = vector('large-successful-suppression');
  const result = validateContextFirewallPacket(item.packet, { sourceInput: item.source_input });
  assert.equal(result.valid, true);
  assert.equal(result.verification.source_accounting, 'VERIFIED');
  assert.equal(item.packet.receipt.suppressed.categories.successful_test, 1500);
  assert.equal(
    item.packet.receipt.measurements.retained_evidence_count
      + item.packet.receipt.measurements.suppressed_evidence_count,
    item.packet.receipt.measurements.original_event_count,
  );
});

test('exact payload boundary remains valid byte for byte', () => {
  const item = vector('exact-payload-boundary');
  const result = validateContextFirewallPacket(item.packet, {
    packetBytes: packetBytes(item.packet),
    sourceInput: item.source_input,
  });
  assert.equal(result.valid, true);
  assert.equal(
    item.packet.receipt.measurements.reduced_bytes,
    item.packet.receipt.payload_limit.requested_bytes,
  );
});

test('source byte tampering is a cryptographic mismatch', () => {
  const item = vector('successful-reduced-run');
  item.source_input.streams[0].data += 'WARNING: tampered\n';
  const result = validateContextFirewallPacket(item.packet, { sourceInput: item.source_input });
  assert.equal(result.classification, 'CRYPTOGRAPHIC_MISMATCH');
  assert.ok(result.violations.some((violation) => violation.code === 'INPUT_HASH_MISMATCH'));
});

test('semantic payload tampering is independently detected', () => {
  const item = vector('successful-reduced-run');
  item.packet.decision_evidence.counts.passed = 3;
  refreshReducedBytes(item.packet);
  const result = validateContextFirewallPacket(item.packet);
  assert.equal(result.classification, 'CRYPTOGRAPHIC_MISMATCH');
  assert.ok(result.violations
    .some((violation) => violation.code === 'SEMANTIC_PAYLOAD_HASH_MISMATCH'));
});

test('configuration identity is recomputed independently', () => {
  const item = vector('successful-reduced-run');
  item.packet.receipt.configuration.identity = `sha256:${'f'.repeat(64)}`;
  refreshReducedBytes(item.packet);
  const result = validateContextFirewallPacket(item.packet);
  assert.equal(result.classification, 'CRYPTOGRAPHIC_MISMATCH');
  assert.ok(result.violations.some((violation) => violation.code === 'CONFIGURATION_HASH_MISMATCH'));
});

test('noncanonical supplied packet bytes are rejected', () => {
  const item = vector('successful-reduced-run');
  const bytes = Buffer.concat([packetBytes(item.packet), Buffer.from(' ')]);
  const result = validateContextFirewallPacket(item.packet, { packetBytes: bytes });
  assert.equal(result.classification, 'CRYPTOGRAPHIC_MISMATCH');
  assert.ok(result.violations.some((violation) => violation.code === 'NONCANONICAL_PACKET_BYTES'));
});

test('source metadata mismatch is distinct from byte-hash verification', () => {
  const item = vector('successful-reduced-run');
  item.source_input.source.id = 'different-source';
  const result = validateContextFirewallPacket(item.packet, { sourceInput: item.source_input });
  assert.equal(result.classification, 'INTERNALLY_INCONSISTENT');
  assert.equal(result.verification.input_hash, 'VERIFIED');
  assert.ok(result.violations.some((violation) => violation.code === 'SOURCE_METADATA_MISMATCH'));
});

test('sourceStreams verifies bytes without claiming caller metadata', () => {
  const item = vector('successful-reduced-run');
  const streams = item.source_input.streams.map((stream) => ({
    bytes: Buffer.from(stream.data, 'utf8'),
    name: stream.name,
  }));
  const result = validateContextFirewallPacket(item.packet, { sourceStreams: streams });
  assert.equal(result.valid, true);
  assert.equal(result.verification.input_hash, 'VERIFIED');
  assert.equal(result.verification.source_accounting, 'VERIFIED');
});

test('invalid supplied source material fails structurally', () => {
  const { packet } = vector('successful-reduced-run');
  const result = validateContextFirewallPacket(packet, {
    sourceStreams: [
      { name: 'stdout', bytes: 'one' },
      { name: 'stdout', bytes: 'two' },
    ],
  });
  assert.equal(result.classification, 'STRUCTURALLY_INVALID');
  assert.ok(result.violations.some((violation) => violation.code === 'INVALID_SOURCE_MATERIAL'));
});

test('caller-owned locator syntax is deliberately limited to nonempty strings', () => {
  const item = vector('successful-reduced-run');
  item.packet.receipt.raw_evidence.reference = 'opaque-caller-token';
  refreshReducedBytes(item.packet);
  const result = validateContextFirewallPacket(item.packet);
  assert.equal(result.valid, true);
  assert.equal(result.classification, 'VALID_WITH_UNVERIFIED_SOURCE');
});

test('raw reference absence is preservation-unconfirmed, not destruction', () => {
  const item = vectors.valid_vectors.find((entry) => entry.producer_fixture === 'provenance/raw-reference-present');
  const packet = structuredClone(item.packet);
  packet.receipt.raw_evidence.reference = null;
  packet.receipt.raw_evidence.escalation_available = false;
  packet.receipt.raw_evidence.escalation_required = true;
  packet.receipt.raw_evidence.source_evidence_disposition = 'PRESERVATION_UNCONFIRMED';
  packet.receipt.reduction_complete = false;
  packet.decision_evidence.disposition = 'NEEDS_RAW_EVIDENCE';
  packet.decision_evidence.reason_codes = ['RAW_EVIDENCE_REFERENCE_MISSING'];
  packet.receipt.semantic_payload_hash = sha256Canonical(packet.decision_evidence);
  refreshReducedBytes(packet);
  const result = validateContextFirewallPacket(packet);
  assert.equal(result.valid, true);
  assert.equal(result.raw_evidence_required, true);
  assert.equal(packet.receipt.raw_evidence.destroyed_by_reducer, false);
});

test('malformed top-level input produces specific structural violations', () => {
  const result = validateContextFirewallPacket(null);
  assert.equal(result.valid, false);
  assert.equal(result.structural_valid, false);
  assert.equal(result.internally_consistent, false);
  assert.deepEqual(result.violations.map((violation) => violation.code), ['OBJECT_REQUIRED']);
});

test('validator output is deterministic', () => {
  const item = vector('failed-test-packet');
  const options = { packetBytes: packetBytes(item.packet), sourceInput: item.source_input };
  assert.deepEqual(
    validateContextFirewallPacket(item.packet, options),
    validateContextFirewallPacket(item.packet, options),
  );
});

test('all protocol-owned vectors pass their expected result', async () => {
  const report = await runContextFirewallConformance();
  assert.equal(report.conformance, 'PASS');
  assert.equal(report.vector_count, 24);
  assert.equal(report.valid_vector_count, 9);
  assert.equal(report.invalid_vector_count, 15);
  assert.equal(report.results.every((result) => result.pass), true);
});

test('every invalid vector proves a specific failure code', async (context) => {
  const report = await runContextFirewallConformance();
  for (const result of report.results.filter((item) => item.kind === 'invalid')) {
    await context.test(result.id, () => {
      assert.equal(result.pass, true);
      assert.equal(result.actual.valid, false);
      assert.ok(result.actual.violation_codes.length > 0);
    });
  }
});

test('CLI emits machine-readable receipt-only validation', () => {
  const item = vector('successful-reduced-run');
  const result = spawnSync(process.execPath, [cliPath, 'validate-context-firewall'], {
    encoding: 'utf8',
    input: packetBytes(item.packet),
  });
  assert.equal(result.status, 0, result.stderr);
  const output = JSON.parse(result.stdout);
  assert.equal(output.classification, 'VALID_WITH_UNVERIFIED_SOURCE');
  assert.equal(output.sufficiency, 'SUFFICIENT');
});

test('CLI rejects malformed JSON with machine-readable control output', () => {
  const result = spawnSync(process.execPath, [cliPath, 'validate-context-firewall'], {
    encoding: 'utf8',
    input: '{broken',
  });
  assert.equal(result.status, 2);
  assert.equal(result.stdout, '');
  assert.deepEqual(JSON.parse(result.stderr), {
    code: 'INVALID_INVOCATION',
    message: 'packet must be valid JSON',
  });
});

test('CLI conformance output is deterministic', () => {
  const first = spawnSync(process.execPath, [cliPath, 'conformance'], { encoding: 'utf8' });
  const second = spawnSync(process.execPath, [cliPath, 'conformance'], { encoding: 'utf8' });
  assert.equal(first.status, 0, first.stderr);
  assert.equal(second.status, 0, second.stderr);
  assert.equal(first.stdout, second.stdout);
  assert.equal(JSON.parse(first.stdout).conformance, 'PASS');
});
