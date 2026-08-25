import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  canonicalJson,
  validateContextFirewallPacket,
} from '../src/context-firewall-v1.js';
import { loadContextFirewallVectors } from '../src/conformance.js';
import {
  createValidationValueReceipt,
  formatDecisionEvidenceIndicator,
  validateContextFirewallValueReceipt,
} from '../src/context-firewall-value.js';
import { validateValueReceipt } from '../src/value-receipt-v1.js';

const cliPath = fileURLToPath(new URL('../bin/decision-evidence.js', import.meta.url));
const vectors = await loadContextFirewallVectors();

function vector(id = 'successful-reduced-run') {
  const item = vectors.valid_vectors.find((candidate) => candidate.id === id);
  assert.ok(item);
  return structuredClone(item);
}

function packetBytes(packet) {
  return Buffer.from(`${canonicalJson(packet)}\n`, 'utf8');
}

function measurement(receipt, id) {
  const item = receipt.measurements.find((candidate) => candidate.id === id);
  assert.ok(item);
  return item;
}

test('accepts a valid Context Firewall value receipt', () => {
  const item = vector();
  assert.deepEqual(validateValueReceipt(item.value_receipt), { valid: true, violations: [] });
  assert.deepEqual(validateContextFirewallValueReceipt(item.value_receipt, item.packet), {
    profile: 'opsle.decision-evidence.context-firewall-value/v1',
    valid: true,
    violations: [],
  });
});

test('rejects missing fields and unsupported schema versions', () => {
  const missing = vector().value_receipt;
  delete missing.operation;
  assert.ok(validateValueReceipt(missing).violations.some((item) => item.code === 'REQUIRED_FIELD_MISSING'));
  const unsupported = vector().value_receipt;
  unsupported.schema = 'opsle.value-receipt.v2';
  assert.ok(validateValueReceipt(unsupported).violations.some((item) => item.code === 'UNSUPPORTED_SCHEMA'));
});

test('rejects invalid units, classes, and impossible numeric values', () => {
  const receipt = vector().value_receipt;
  const raw = measurement(receipt, 'raw_bytes');
  raw.unit = 'vibes';
  raw.class = 'MARKETING';
  const codes = validateValueReceipt(receipt).violations.map((item) => item.code);
  assert.ok(codes.includes('INVALID_UNIT'));
  assert.ok(codes.includes('INVALID_MEASUREMENT_CLASS'));
  const impossible = vector().value_receipt;
  measurement(impossible, 'raw_bytes').result = -1;
  assert.ok(validateValueReceipt(impossible).violations.some(
    (item) => item.code === 'INVALID_NONNEGATIVE_INTEGER',
  ));
});

test('rejects malformed and unresolved evidence references', () => {
  const receipt = vector().value_receipt;
  receipt.evidence[0].locator = 'sha256:not-valid';
  receipt.evidence[0].kind = 'CONTENT_HASH';
  measurement(receipt, 'raw_bytes').evidence_refs = ['missing'];
  const codes = validateValueReceipt(receipt).violations.map((item) => item.code);
  assert.ok(codes.includes('MALFORMED_CONTENT_HASH'));
  assert.ok(codes.includes('UNRESOLVED_EVIDENCE_REF'));
});

test('requires assumptions for estimates and models', () => {
  for (const measurementClass of ['ESTIMATED', 'MODELED']) {
    const receipt = vector().value_receipt;
    const raw = measurement(receipt, 'raw_bytes');
    raw.class = measurementClass;
    raw.aggregation = { method: null, safe: false };
    assert.ok(validateValueReceipt(receipt).violations.some((item) => item.code === 'DERIVATION_REQUIRED'));
  }
});

test('refuses unsafe modeled aggregation and uncontrolled experiments', () => {
  const modeled = vector().value_receipt;
  const raw = measurement(modeled, 'raw_bytes');
  raw.class = 'MODELED';
  raw.derivation = {
    assumptions: ['policy remains stable'],
    comparability: 'NOT_COMPARABLE',
    experiment_id: null,
    input_measurement_ids: [],
    method: 'counterfactual model',
  };
  assert.ok(validateValueReceipt(modeled).violations.some((item) => item.code === 'UNSAFE_AGGREGATION'));
  const experimental = vector().value_receipt;
  const rawExperimental = measurement(experimental, 'raw_bytes');
  rawExperimental.class = 'EXPERIMENTAL';
  rawExperimental.aggregation = { method: null, safe: false };
  assert.ok(validateValueReceipt(experimental).violations.some((item) => item.code === 'CONTROLLED_EXPERIMENT_REQUIRED'));
});

test('byte-only evidence cannot become a monetary estimate', () => {
  const receipt = vector().value_receipt;
  const cost = structuredClone(measurement(receipt, 'raw_bytes'));
  cost.id = 'estimated_cost_usd';
  cost.unit = 'usd';
  cost.class = 'ESTIMATED';
  cost.baseline = 0;
  cost.result = 0.42;
  cost.delta = 0.42;
  cost.aggregation = { method: null, safe: false };
  cost.derivation = {
    assumptions: ['published price applies'],
    comparability: 'NOT_APPLICABLE',
    experiment_id: null,
    input_measurement_ids: ['raw_bytes'],
    method: 'bytes times price',
  };
  receipt.measurements.push(cost);
  assert.ok(validateValueReceipt(receipt).violations.some((item) => item.code === 'MONETARY_ESTIMATE_WITHOUT_TOKENS'));
});

test('failure prevented cannot be exact or observed', () => {
  for (const measurementClass of ['EXACT', 'OBSERVED']) {
    const receipt = vector().value_receipt;
    const raw = measurement(receipt, 'raw_bytes');
    raw.id = 'failure_prevented_count';
    raw.class = measurementClass;
    if (measurementClass === 'OBSERVED') raw.source_verification = 'OBSERVED';
    assert.ok(validateValueReceipt(receipt).violations.some((item) => item.code === 'COUNTERFACTUAL_CLASS_MISUSE'));
  }
});

test('strict profile catches a tampered Context Firewall measurement', () => {
  const item = vector();
  measurement(item.value_receipt, 'raw_bytes').result += 1;
  const result = validateContextFirewallValueReceipt(item.value_receipt, item.packet);
  assert.equal(result.valid, false);
  assert.ok(result.violations.some((violation) => violation.code === 'MEASUREMENT_VALUE_MISMATCH'));
});

test('creates source-unverified and source-backed validation receipts', () => {
  const item = vector();
  const unverifiedResult = validateContextFirewallPacket(item.packet, {
    packetBytes: packetBytes(item.packet),
  });
  const unverified = createValidationValueReceipt(item.packet, unverifiedResult);
  assert.equal(validateValueReceipt(unverified).valid, true);
  assert.equal(measurement(unverified, 'source_backed_verification').result, false);
  const backedResult = validateContextFirewallPacket(item.packet, {
    packetBytes: packetBytes(item.packet),
    sourceInput: item.source_input,
  });
  const backed = createValidationValueReceipt(item.packet, backedResult, {
    mechanismRevision: 'a'.repeat(40),
  });
  assert.equal(validateValueReceipt(backed).valid, true);
  assert.equal(backed.mechanism.revision, 'a'.repeat(40));
  assert.equal(measurement(backed, 'source_backed_verification').result, true);
  assert.equal(measurement(backed, 'verification_claims_evaluated').result, 7);
});

test('tamper and inconsistency receipts report observed detection, not prevention', () => {
  const item = vector();
  item.packet.receipt.input_hash = `sha256:${'0'.repeat(64)}`;
  const tamperedResult = validateContextFirewallPacket(item.packet, {
    packetBytes: packetBytes(item.packet),
    sourceInput: item.source_input,
  });
  const tampered = createValidationValueReceipt(item.packet, tamperedResult);
  assert.equal(measurement(tampered, 'tamper_detected').result, true);
  assert.equal(tampered.measurements.some((candidate) => candidate.id.includes('prevented')), false);

  const inconsistentItem = vector();
  inconsistentItem.packet.receipt.measurements.original_bytes += 1;
  const inconsistentResult = validateContextFirewallPacket(inconsistentItem.packet, {
    packetBytes: packetBytes(inconsistentItem.packet),
  });
  const inconsistent = createValidationValueReceipt(inconsistentItem.packet, inconsistentResult);
  assert.equal(measurement(inconsistent, 'inconsistency_detected').result, true);
});

test('operator formats name Decision Evidence and preserves canonical output', () => {
  const item = vector();
  const result = validateContextFirewallPacket(item.packet, {
    packetBytes: packetBytes(item.packet),
    sourceInput: item.source_input,
  });
  assert.equal(
    formatDecisionEvidenceIndicator(result),
    '[Decision Evidence] source-backed packet verified | SUFFICIENT | 7 claims checked',
  );
});

test('CLI emits validation receipt sidecar without changing canonical stdout', () => {
  const item = vector();
  const directory = mkdtempSync(join(tmpdir(), 'decision-evidence-value-'));
  const packetPath = join(directory, 'packet.json');
  const sourcePath = join(directory, 'source.json');
  const receiptPath = join(directory, 'receipt.json');
  try {
    writeFileSync(packetPath, packetBytes(item.packet));
    writeFileSync(sourcePath, `${canonicalJson(item.source_input)}\n`);
    const base = spawnSync(process.execPath, [cliPath, 'validate-context-firewall', '--packet', packetPath, '--source-input', sourcePath], { encoding: 'utf8' });
    const withReceipt = spawnSync(process.execPath, [
      cliPath, 'validate-context-firewall', '--packet', packetPath, '--source-input', sourcePath,
      '--mechanism-revision', 'b'.repeat(40), '--value-receipt', receiptPath,
    ], { encoding: 'utf8' });
    assert.equal(withReceipt.status, 0, withReceipt.stderr);
    assert.equal(withReceipt.stdout, base.stdout);
    assert.equal(withReceipt.stderr, '[Decision Evidence] source-backed packet verified | SUFFICIENT | 7 claims checked\n');
    const receipt = JSON.parse(readFileSync(receiptPath, 'utf8'));
    assert.equal(validateValueReceipt(receipt).valid, true);
    assert.equal(receipt.mechanism.revision, 'b'.repeat(40));
  } finally {
    rmSync(directory, { recursive: true });
  }
});

test('CLI strictly validates the producer value receipt separately', () => {
  const item = vector();
  const directory = mkdtempSync(join(tmpdir(), 'decision-evidence-profile-'));
  const packetPath = join(directory, 'packet.json');
  const receiptPath = join(directory, 'receipt.json');
  try {
    writeFileSync(packetPath, packetBytes(item.packet));
    writeFileSync(receiptPath, `${canonicalJson(item.value_receipt)}\n`);
    const result = spawnSync(process.execPath, [
      cliPath, 'validate-context-firewall-value', '--packet', packetPath, '--receipt', receiptPath,
    ], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).valid, true);
    assert.equal(result.stderr, '[Decision Evidence] Context Firewall value receipt verified | 11 measurements checked\n');
  } finally {
    rmSync(directory, { recursive: true });
  }
});
