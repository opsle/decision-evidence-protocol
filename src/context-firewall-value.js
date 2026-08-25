import {
  CONTEXT_FIREWALL_POLICY_REVISION,
  CONTEXT_FIREWALL_REDUCER_VERSION,
} from './context-firewall-v1.js';
import { validateValueReceipt } from './value-receipt-v1.js';

export const DECISION_EVIDENCE_MECHANISM_ID = 'opsle.decision-evidence-protocol';
export const DECISION_EVIDENCE_MECHANISM_NAME = 'Decision Evidence';
export const DECISION_EVIDENCE_VERSION = '0.3.0';
export const CONTEXT_FIREWALL_VALUE_PROFILE =
  'opsle.decision-evidence.context-firewall-value/v1';

const profile = Object.freeze([
  ['raw_bytes', 'byte', 'EXACT'],
  ['initial_model_visible_bytes', 'byte', 'EXACT'],
  ['bytes_initially_avoided', 'byte', 'EXACT'],
  ['initial_reduction_ratio', 'ratio', 'EXACT'],
  ['original_evidence_events', 'event', 'EXACT'],
  ['retained_evidence_events', 'event', 'EXACT'],
  ['suppressed_evidence_events', 'event', 'EXACT'],
  ['ambiguous_evidence_events', 'event', 'EXACT'],
  ['payload_ceiling_bytes', 'byte', 'EXACT'],
  ['escalation_required', 'boolean', 'OBSERVED'],
  ['raw_locator_available', 'boolean', 'OBSERVED'],
]);

function valueById(receipt) {
  return new Map(receipt.measurements.map((item) => [item.id, item]));
}

function add(violations, code, path, message) {
  violations.push({ code, message, path });
}

function same(actual, expected) {
  return Object.is(actual, expected);
}

export function validateContextFirewallValueReceipt(receipt, packet) {
  const generic = validateValueReceipt(receipt);
  const violations = [...generic.violations];
  if (!generic.valid || packet === null || typeof packet !== 'object') {
    if (packet === null || typeof packet !== 'object') {
      add(violations, 'PACKET_REQUIRED', '/packet', 'Context Firewall packet-v1 required');
    }
    return { profile: CONTEXT_FIREWALL_VALUE_PROFILE, valid: false, violations };
  }
  if (receipt.mechanism.id !== 'opsle.context-firewall') {
    add(violations, 'MECHANISM_MISMATCH', '/mechanism/id', 'Context Firewall mechanism required');
  }
  if (receipt.mechanism.version !== CONTEXT_FIREWALL_REDUCER_VERSION) {
    add(violations, 'MECHANISM_VERSION_MISMATCH', '/mechanism/version', 'receipt and supported reducer versions differ');
  }
  if (receipt.run.id !== packet.receipt?.source?.run_id) {
    add(violations, 'RUN_ID_MISMATCH', '/run/id', 'receipt and packet run identities differ');
  }
  if (receipt.operation.id !== packet.operation_id) {
    add(violations, 'OPERATION_ID_MISMATCH', '/operation/id', 'receipt and packet operation identities differ');
  }
  if (receipt.operation.configuration_id !== packet.receipt?.configuration?.identity) {
    add(violations, 'CONFIGURATION_ID_MISMATCH', '/operation/configuration_id', 'receipt and packet configurations differ');
  }
  if (receipt.operation.policy_id !== CONTEXT_FIREWALL_POLICY_REVISION) {
    add(violations, 'POLICY_ID_MISMATCH', '/operation/policy_id', 'supported Context Firewall policy required');
  }

  const values = valueById(receipt);
  if (values.size !== profile.length) {
    add(violations, 'MEASUREMENT_PROFILE_MISMATCH', '/measurements', 'exact Context Firewall value profile required');
  }
  for (const [id, unit, measurementClass] of profile) {
    const item = values.get(id);
    if (!item) add(violations, 'MEASUREMENT_REQUIRED', '/measurements', `missing ${id}`);
    else if (item.unit !== unit || item.class !== measurementClass) {
      add(violations, 'MEASUREMENT_SEMANTICS_MISMATCH', `/measurements/${id}`, `${unit}/${measurementClass} required`);
    }
  }
  const measured = packet.receipt?.measurements ?? {};
  const original = measured.original_bytes;
  const visible = measured.reduced_bytes;
  const expected = new Map([
    ['raw_bytes', original],
    ['initial_model_visible_bytes', visible],
    ['bytes_initially_avoided', original],
    ['initial_reduction_ratio', original === 0 ? null : `${original - visible}/${original}`],
    ['original_evidence_events', measured.original_event_count],
    ['retained_evidence_events', measured.retained_evidence_count],
    ['suppressed_evidence_events', measured.suppressed_evidence_count],
    ['ambiguous_evidence_events', packet.decision_evidence?.unclassified_evidence?.length],
    ['payload_ceiling_bytes', packet.receipt?.configuration?.max_output_bytes],
    ['escalation_required', packet.receipt?.raw_evidence?.escalation_required],
    ['raw_locator_available', packet.receipt?.raw_evidence?.reference !== null],
  ]);
  for (const [id, result] of expected) {
    if (values.has(id) && !same(values.get(id).result, result)) {
      add(violations, 'MEASUREMENT_VALUE_MISMATCH', `/measurements/${id}/result`, 'receipt value contradicts packet');
    }
  }
  if (values.has('initial_model_visible_bytes')) {
    const item = values.get('initial_model_visible_bytes');
    if (!same(item.baseline, original) || !same(item.delta, visible - original)) {
      add(violations, 'MEASUREMENT_VALUE_MISMATCH', '/measurements/initial_model_visible_bytes', 'visible-byte arithmetic contradicts packet');
    }
  }
  if (values.has('bytes_initially_avoided')) {
    const item = values.get('bytes_initially_avoided');
    if (!same(item.baseline, visible) || !same(item.delta, original - visible)) {
      add(violations, 'MEASUREMENT_VALUE_MISMATCH', '/measurements/bytes_initially_avoided', 'avoided-byte arithmetic contradicts packet');
    }
  }
  violations.sort((left, right) => left.path.localeCompare(right.path) || left.code.localeCompare(right.code));
  return {
    profile: CONTEXT_FIREWALL_VALUE_PROFILE,
    valid: violations.length === 0,
    violations,
  };
}

function measurement({
  id, result, unit, measurementClass, direction, operatorDisplay,
  safeToAggregate = false,
}) {
  return {
    aggregation: { method: safeToAggregate ? 'SUM' : null, safe: safeToAggregate },
    baseline: null,
    class: measurementClass,
    delta: null,
    derivation: null,
    direction,
    evidence_refs: ['validation_result'],
    id,
    limitations: [],
    operator_display: operatorDisplay,
    result,
    source_verification: measurementClass === 'EXACT' ? 'VERIFIED' : 'OBSERVED',
    unit,
  };
}

export function verificationClaimCount(result) {
  return Object.values(result.verification ?? {}).filter(
    (state) => !['NOT_EVALUATED', 'NOT_SUPPLIED'].includes(state),
  ).length;
}

export function createValidationValueReceipt(packet, result, {
  mechanismRevision = null,
} = {}) {
  if (mechanismRevision !== null
    && (typeof mechanismRevision !== 'string' || mechanismRevision.length === 0)) {
    throw new TypeError('mechanismRevision must be a nonempty string or null');
  }
  const claims = verificationClaimCount(result);
  const sourceBacked = result.valid
    && result.verification?.input_hash === 'VERIFIED'
    && result.verification?.source_accounting === 'VERIFIED';
  const hashPerformed = Object.entries(result.verification ?? {}).some(
    ([name, state]) => name !== 'source_accounting'
      && !['NOT_EVALUATED', 'NOT_SUPPLIED'].includes(state),
  );
  const receipt = {
    evidence: [{
      id: 'validation_result',
      kind: 'JSON_POINTER',
      locator: '/',
      trust: 'VERIFIED',
    }],
    limitations: [
      'Validation reports checks, trust, sufficiency, and rejection; it does not claim a failure was prevented.',
      'Validation of a packet is not evidence that reduced context preserves model correctness.',
      sourceBacked
        ? 'Caller-supplied source material was independently matched to the packet.'
        : 'Source-backed verification was not completed successfully.',
    ],
    measurements: [
      measurement({ id: 'validation_performed', result: true, unit: 'boolean', measurementClass: 'OBSERVED', direction: 'PROTECTION_SIGNAL', operatorDisplay: false }),
      measurement({ id: 'validation_classification', result: result.classification, unit: 'state', measurementClass: 'OBSERVED', direction: 'PROTECTION_SIGNAL', operatorDisplay: true }),
      measurement({ id: 'verification_claims_evaluated', result: claims, unit: 'count', measurementClass: 'EXACT', direction: 'NEUTRAL', operatorDisplay: true, safeToAggregate: true }),
      measurement({ id: 'source_backed_verification', result: sourceBacked, unit: 'boolean', measurementClass: 'OBSERVED', direction: 'PROTECTION_SIGNAL', operatorDisplay: true }),
      measurement({ id: 'hash_verification_performed', result: hashPerformed, unit: 'boolean', measurementClass: 'OBSERVED', direction: 'PROTECTION_SIGNAL', operatorDisplay: false }),
      measurement({ id: 'evidence_sufficiency', result: result.sufficiency, unit: 'state', measurementClass: 'OBSERVED', direction: 'PROTECTION_SIGNAL', operatorDisplay: true }),
      measurement({ id: 'evidence_sufficient', result: result.evidence_sufficient, unit: 'boolean', measurementClass: 'OBSERVED', direction: 'PROTECTION_SIGNAL', operatorDisplay: false }),
      measurement({ id: 'tamper_detected', result: result.classification === 'CRYPTOGRAPHIC_MISMATCH', unit: 'boolean', measurementClass: 'OBSERVED', direction: 'PROTECTION_SIGNAL', operatorDisplay: true }),
      measurement({ id: 'inconsistency_detected', result: result.classification === 'INTERNALLY_INCONSISTENT', unit: 'boolean', measurementClass: 'OBSERVED', direction: 'PROTECTION_SIGNAL', operatorDisplay: true }),
      measurement({ id: 'raw_escalation_required', result: result.raw_evidence_required, unit: 'boolean', measurementClass: 'OBSERVED', direction: 'PROTECTION_SIGNAL', operatorDisplay: true }),
    ],
    mechanism: {
      id: DECISION_EVIDENCE_MECHANISM_ID,
      name: DECISION_EVIDENCE_MECHANISM_NAME,
      revision: mechanismRevision,
      version: DECISION_EVIDENCE_VERSION,
    },
    operation: {
      configuration_id: packet?.receipt?.configuration?.identity ?? null,
      id: packet?.operation_id ?? null,
      name: 'context-firewall-validation',
      policy_id: CONTEXT_FIREWALL_VALUE_PROFILE,
    },
    run: { id: packet?.receipt?.source?.run_id ?? null },
    schema: 'opsle.value-receipt.v1',
  };
  const checked = validateValueReceipt(receipt);
  if (!checked.valid) throw new TypeError(`internal value receipt invalid: ${checked.violations.map((item) => item.code).join(', ')}`);
  return receipt;
}

function groupedInteger(value) {
  return String(value).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

export function formatDecisionEvidenceIndicator(result) {
  const claims = groupedInteger(verificationClaimCount(result));
  if (result.classification === 'STRUCTURALLY_INVALID') {
    return '[Decision Evidence] malformed packet rejected | STRUCTURALLY_INVALID';
  }
  if (result.classification === 'CRYPTOGRAPHIC_MISMATCH') {
    return '[Decision Evidence] tampered packet rejected | CRYPTOGRAPHIC_MISMATCH';
  }
  if (result.classification === 'INTERNALLY_INCONSISTENT') {
    return '[Decision Evidence] inconsistent packet rejected | INTERNALLY_INCONSISTENT';
  }
  const sourceBacked = result.verification?.input_hash === 'VERIFIED'
    && result.verification?.source_accounting === 'VERIFIED';
  if (sourceBacked) {
    return `[Decision Evidence] source-backed packet verified | ${result.sufficiency} | ${claims} claims checked`;
  }
  return `[Decision Evidence] packet validated | source unverified | ${result.sufficiency} | ${claims} claims checked`;
}
