import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

import {
  canonicalJson,
  validateContextFirewallPacket,
} from './context-firewall-v1.js';

function clone(value) {
  return structuredClone(value);
}

function pointerParts(pointer) {
  if (pointer === '') return [];
  if (!pointer.startsWith('/')) throw new TypeError(`invalid JSON pointer: ${pointer}`);
  return pointer.slice(1).split('/').map((part) => part.replaceAll('~1', '/').replaceAll('~0', '~'));
}

function parentAt(value, pointer) {
  const parts = pointerParts(pointer);
  const final = parts.pop();
  let parent = value;
  for (const part of parts) parent = parent[part];
  return { parent, final };
}

function applyMutation(target, mutation) {
  const { parent, final } = parentAt(target, mutation.path);
  if (mutation.op === 'remove') delete parent[final];
  else if (mutation.op === 'replace') parent[final] = clone(mutation.value);
  else if (mutation.op === 'add') parent[final] = clone(mutation.value);
  else throw new TypeError(`unsupported mutation operation: ${mutation.op}`);
}

function digestCanonical(value) {
  const digest = createHash('sha256');
  digest.update(Buffer.from(canonicalJson(value), 'utf8'));
  return `sha256:${digest.digest('hex')}`;
}

function refreshDerivedPacketFields(packet, vector) {
  if (vector.refresh_semantic_hash) {
    packet.receipt.semantic_payload_hash = digestCanonical(packet.decision_evidence);
  }
  if (vector.refresh_configuration_hash) {
    packet.receipt.configuration.identity = digestCanonical({
      max_output_bytes: packet.receipt.configuration.max_output_bytes,
      policy_revision: packet.receipt.configuration.policy_revision,
      reducer_version: packet.receipt.reducer.version,
    });
  }
  if (vector.refresh_reduced_bytes) {
    let length = packet.receipt.measurements.reduced_bytes;
    for (let iteration = 0; iteration < 12; iteration += 1) {
      packet.receipt.measurements.reduced_bytes = length;
      const next = Buffer.byteLength(`${canonicalJson(packet)}\n`, 'utf8');
      if (next === length) break;
      length = next;
    }
    packet.receipt.measurements.reduced_bytes = length;
  }
}

function evaluateExpectation(result, expected) {
  const actualCodes = result.violations.map((violation) => violation.code);
  const missingCodes = (expected.violation_codes ?? [])
    .filter((code) => !actualCodes.includes(code));
  return {
    actual: {
      classification: result.classification,
      sufficiency: result.sufficiency,
      valid: result.valid,
      violation_codes: actualCodes,
    },
    pass: result.valid === expected.valid
      && result.classification === expected.classification
      && result.sufficiency === expected.sufficiency
      && missingCodes.length === 0,
  };
}

export async function loadContextFirewallVectors(url = new URL(
  '../fixtures/context-firewall-packet-v1/vectors.json',
  import.meta.url,
)) {
  return JSON.parse(await readFile(url, 'utf8'));
}

export async function runContextFirewallConformance(options = {}) {
  const vectors = options.vectors ?? await loadContextFirewallVectors();
  const baseById = new Map(vectors.valid_vectors.map((vector) => [vector.id, vector]));
  const results = [];

  for (const vector of vectors.valid_vectors) {
    const packetBytes = Buffer.from(`${canonicalJson(vector.packet)}\n`, 'utf8');
    const result = validateContextFirewallPacket(vector.packet, {
      packetBytes,
      sourceInput: vector.source_input,
    });
    const evaluation = evaluateExpectation(result, vector.expected);
    results.push({
      ...evaluation,
      id: vector.id,
      kind: 'valid',
    });
  }

  for (const vector of vectors.invalid_vectors) {
    const base = baseById.get(vector.base);
    if (!base) throw new TypeError(`unknown base vector: ${vector.base}`);
    const packet = clone(base.packet);
    const sourceInput = clone(base.source_input);
    for (const mutation of vector.packet_mutations ?? []) applyMutation(packet, mutation);
    for (const mutation of vector.source_mutations ?? []) applyMutation(sourceInput, mutation);
    refreshDerivedPacketFields(packet, vector);
    const packetBytes = Buffer.from(`${canonicalJson(packet)}\n`, 'utf8');
    const result = validateContextFirewallPacket(packet, { packetBytes, sourceInput });
    const evaluation = evaluateExpectation(result, vector.expected);
    results.push({
      ...evaluation,
      id: vector.id,
      kind: 'invalid',
    });
  }

  return {
    conformance: results.every((result) => result.pass) ? 'PASS' : 'FAIL',
    context_firewall_revision: vectors.context_firewall_revision,
    invalid_vector_count: vectors.invalid_vectors.length,
    protocol_version: vectors.protocol_version,
    results,
    valid_vector_count: vectors.valid_vectors.length,
    vector_count: results.length,
  };
}
