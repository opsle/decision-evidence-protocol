export const VALUE_RECEIPT_SCHEMA = 'opsle.value-receipt.v1';
export const MEASUREMENT_CLASSES = Object.freeze([
  'EXACT', 'OBSERVED', 'ESTIMATED', 'MODELED', 'EXPERIMENTAL',
]);

const units = new Set([
  'byte', 'event', 'count', 'ratio', 'percent', 'boolean',
  'millisecond', 'token', 'usd', 'state',
]);
const classes = new Set(MEASUREMENT_CLASSES);
const directions = new Set([
  'HIGHER_IS_VALUE', 'LOWER_IS_VALUE', 'NEUTRAL',
  'PROTECTION_SIGNAL', 'NOT_APPLICABLE',
]);
const verificationStates = new Set([
  'VERIFIED', 'OBSERVED', 'CALLER_SUPPLIED', 'UNVERIFIED',
  'NOT_APPLICABLE',
]);
const evidenceKinds = new Set([
  'CONTENT_HASH', 'JSON_POINTER', 'RUN_ARTIFACT', 'PROVIDER_RECORD',
  'URI', 'CALLER_ASSERTION',
]);
const nonsummableUnits = new Set(['ratio', 'percent', 'boolean', 'state']);
const integerUnits = new Set(['byte', 'event', 'count', 'millisecond', 'token']);
const hashPattern = /^sha256:[0-9a-f]{64}$/;
const measurementIdPattern = /^[a-z][a-z0-9_]*$/;

function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function nonempty(value) {
  return typeof value === 'string' && value.length > 0;
}

function finite(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function add(violations, code, path, message) {
  violations.push({ code, message, path });
}

function required(value, fields, path, violations) {
  for (const field of fields) {
    if (!Object.hasOwn(value, field)) {
      add(violations, 'REQUIRED_FIELD_MISSING', `${path}/${field}`, 'required field missing');
    }
  }
}

function strings(value, path, violations) {
  if (!Array.isArray(value)) {
    add(violations, 'ARRAY_REQUIRED', path, 'array required');
    return;
  }
  value.forEach((item, index) => {
    if (!nonempty(item)) add(violations, 'STRING_REQUIRED', `${path}/${index}`, 'nonempty string required');
  });
}

function nullableIdentity(value, path, violations) {
  if (value !== null && !nonempty(value)) {
    add(violations, 'INVALID_IDENTITY', path, 'nonempty string or null required');
  }
}

function validateEvidence(value, index, state, violations) {
  const path = `/evidence/${index}`;
  if (!object(value)) {
    add(violations, 'OBJECT_REQUIRED', path, 'evidence object required');
    return;
  }
  required(value, ['id', 'kind', 'locator', 'trust'], path, violations);
  if (!nonempty(value.id)) add(violations, 'INVALID_EVIDENCE_ID', `${path}/id`, 'nonempty evidence identity required');
  else if (state.evidenceIds.has(value.id)) add(violations, 'DUPLICATE_EVIDENCE_ID', `${path}/id`, 'duplicate evidence identity');
  else state.evidenceIds.add(value.id);
  if (!evidenceKinds.has(value.kind)) add(violations, 'INVALID_EVIDENCE_KIND', `${path}/kind`, 'unsupported evidence kind');
  if (!nonempty(value.locator)) add(violations, 'INVALID_EVIDENCE_LOCATOR', `${path}/locator`, 'nonempty locator required');
  else if (value.kind === 'CONTENT_HASH' && !hashPattern.test(value.locator)) {
    add(violations, 'MALFORMED_CONTENT_HASH', `${path}/locator`, 'lowercase sha256:<64 hex> required');
  }
  if (!verificationStates.has(value.trust)) add(violations, 'INVALID_TRUST_STATE', `${path}/trust`, 'unsupported trust state');
}

function validateDerivation(value, path, violations) {
  if (value === null) return;
  if (!object(value)) {
    add(violations, 'INVALID_DERIVATION', path, 'object or null required');
    return;
  }
  required(value, ['method', 'assumptions', 'input_measurement_ids', 'experiment_id', 'comparability'], path, violations);
  nullableIdentity(value.method, `${path}/method`, violations);
  strings(value.assumptions, `${path}/assumptions`, violations);
  strings(value.input_measurement_ids, `${path}/input_measurement_ids`, violations);
  nullableIdentity(value.experiment_id, `${path}/experiment_id`, violations);
  if (!['NOT_APPLICABLE', 'NOT_COMPARABLE', 'CONTROLLED'].includes(value.comparability)) {
    add(violations, 'INVALID_COMPARABILITY', `${path}/comparability`, 'unsupported comparability state');
  }
}

function validateMeasurement(value, index, state, violations) {
  const path = `/measurements/${index}`;
  if (!object(value)) {
    add(violations, 'OBJECT_REQUIRED', path, 'measurement object required');
    return;
  }
  required(value, [
    'id', 'baseline', 'result', 'delta', 'unit', 'direction', 'class',
    'evidence_refs', 'source_verification', 'operator_display', 'aggregation',
    'derivation', 'limitations',
  ], path, violations);
  if (!nonempty(value.id) || !measurementIdPattern.test(value.id)) {
    add(violations, 'INVALID_MEASUREMENT_ID', `${path}/id`, 'lowercase measurement identity required');
  } else if (state.measurementIds.has(value.id)) {
    add(violations, 'DUPLICATE_MEASUREMENT_ID', `${path}/id`, 'duplicate measurement identity');
  } else {
    state.measurementIds.add(value.id);
    state.measurementById.set(value.id, value);
  }
  if (!units.has(value.unit)) add(violations, 'INVALID_UNIT', `${path}/unit`, 'unsupported unit');
  if (!classes.has(value.class)) add(violations, 'INVALID_MEASUREMENT_CLASS', `${path}/class`, 'unsupported measurement class');
  if (!directions.has(value.direction)) add(violations, 'INVALID_DIRECTION', `${path}/direction`, 'unsupported value direction');
  if (!verificationStates.has(value.source_verification)) add(violations, 'INVALID_SOURCE_VERIFICATION', `${path}/source_verification`, 'unsupported verification state');
  if (typeof value.operator_display !== 'boolean') add(violations, 'BOOLEAN_REQUIRED', `${path}/operator_display`, 'boolean required');

  for (const field of ['baseline', 'result', 'delta']) {
    const item = value[field];
    if (item !== null && !finite(item) && typeof item !== 'string' && typeof item !== 'boolean') {
      add(violations, 'INVALID_VALUE', `${path}/${field}`, 'finite number, string, boolean, or null required');
    }
  }
  if (finite(value.baseline) && finite(value.result)) {
    if (!finite(value.delta) || Math.abs(value.delta - (value.result - value.baseline)) > 1e-12) {
      add(violations, 'DELTA_MISMATCH', `${path}/delta`, 'must equal result minus baseline');
    }
  } else if (value.delta !== null) {
    add(violations, 'DELTA_WITHOUT_NUMERIC_STATE', `${path}/delta`, 'must be null without numeric baseline and result');
  }
  if (integerUnits.has(value.unit)) {
    for (const field of ['baseline', 'result']) {
      const item = value[field];
      if (item !== null && (!Number.isSafeInteger(item) || item < 0)) {
        add(violations, 'INVALID_NONNEGATIVE_INTEGER', `${path}/${field}`, `nonnegative safe integer required for ${value.unit}`);
      }
    }
  }
  if (value.unit === 'boolean' && [value.baseline, value.result].some((item) => item !== null && typeof item !== 'boolean')) {
    add(violations, 'INVALID_BOOLEAN_MEASUREMENT', path, 'boolean unit requires boolean values');
  }
  if (value.unit === 'state' && [value.baseline, value.result].some((item) => item !== null && typeof item !== 'string')) {
    add(violations, 'INVALID_STATE_MEASUREMENT', path, 'state unit requires string values');
  }

  if (!Array.isArray(value.evidence_refs) || value.evidence_refs.length === 0) {
    add(violations, 'EVIDENCE_REFS_REQUIRED', `${path}/evidence_refs`, 'nonempty array required');
  } else {
    for (const reference of value.evidence_refs) {
      if (!state.evidenceIds.has(reference)) add(violations, 'UNRESOLVED_EVIDENCE_REF', `${path}/evidence_refs`, `unresolved evidence reference ${JSON.stringify(reference)}`);
    }
  }
  strings(value.limitations, `${path}/limitations`, violations);
  validateDerivation(value.derivation, `${path}/derivation`, violations);
  if (['ESTIMATED', 'MODELED'].includes(value.class) && (
    !object(value.derivation) || !nonempty(value.derivation.method)
    || !Array.isArray(value.derivation.assumptions) || value.derivation.assumptions.length === 0
  )) add(violations, 'DERIVATION_REQUIRED', `${path}/derivation`, `${value.class} requires method and assumptions`);
  if (value.class === 'EXPERIMENTAL' && (
    !object(value.derivation) || !nonempty(value.derivation.experiment_id)
    || value.derivation.comparability !== 'CONTROLLED'
  )) add(violations, 'CONTROLLED_EXPERIMENT_REQUIRED', `${path}/derivation`, 'EXPERIMENTAL requires controlled experiment identity');
  if (['EXACT', 'OBSERVED'].includes(value.class)
    && object(value.derivation)
    && Array.isArray(value.derivation.assumptions)
    && value.derivation.assumptions.length > 0) {
    add(violations, 'ASSUMPTIONS_EXCEED_CLASS', `${path}/derivation`, `${value.class} cannot depend on assumptions`);
  }
  if (value.class === 'EXACT' && value.source_verification !== 'VERIFIED') {
    add(violations, 'EXACT_REQUIRES_VERIFIED_SOURCE', `${path}/source_verification`, 'EXACT requires VERIFIED evidence');
  }

  if (!object(value.aggregation)
    || typeof value.aggregation.safe !== 'boolean'
    || ![null, 'SUM'].includes(value.aggregation.method)) {
    add(violations, 'INVALID_AGGREGATION', `${path}/aggregation`, 'safe boolean and SUM or null method required');
  } else {
    if (value.aggregation.safe && (
      !['EXACT', 'OBSERVED'].includes(value.class)
      || value.aggregation.method !== 'SUM'
      || nonsummableUnits.has(value.unit)
      || !finite(value.result)
    )) add(violations, 'UNSAFE_AGGREGATION', `${path}/aggregation`, 'measurement is not safely summable');
    if (!value.aggregation.safe && value.aggregation.method !== null) {
      add(violations, 'UNSAFE_AGGREGATION_METHOD', `${path}/aggregation`, 'unsafe measurement must use null method');
    }
  }
  if ((value.id?.includes('failure_prevented') || value.id?.includes('failures_prevented'))
    && ['EXACT', 'OBSERVED'].includes(value.class)) {
    add(violations, 'COUNTERFACTUAL_CLASS_MISUSE', `${path}/class`, 'prevented-failure claims require MODELED or EXPERIMENTAL evidence');
  }
}

export function validateValueReceipt(receipt) {
  const violations = [];
  if (!object(receipt)) return { valid: false, violations: [{ code: 'OBJECT_REQUIRED', message: 'receipt object required', path: '/' }] };
  required(receipt, ['schema', 'mechanism', 'run', 'operation', 'measurements', 'evidence', 'limitations'], '', violations);
  if (receipt.schema !== VALUE_RECEIPT_SCHEMA) add(violations, 'UNSUPPORTED_SCHEMA', '/schema', `only ${VALUE_RECEIPT_SCHEMA} is supported`);
  if (!object(receipt.mechanism)) add(violations, 'OBJECT_REQUIRED', '/mechanism', 'mechanism object required');
  else {
    required(receipt.mechanism, ['id', 'name', 'version', 'revision'], '/mechanism', violations);
    for (const field of ['id', 'name', 'version']) if (!nonempty(receipt.mechanism[field])) add(violations, 'INVALID_MECHANISM', `/mechanism/${field}`, 'nonempty string required');
    nullableIdentity(receipt.mechanism.revision, '/mechanism/revision', violations);
  }
  if (!object(receipt.run)) add(violations, 'OBJECT_REQUIRED', '/run', 'run object required');
  else {
    required(receipt.run, ['id'], '/run', violations);
    nullableIdentity(receipt.run.id, '/run/id', violations);
  }
  if (!object(receipt.operation)) add(violations, 'OBJECT_REQUIRED', '/operation', 'operation object required');
  else {
    required(receipt.operation, ['id', 'name', 'configuration_id', 'policy_id'], '/operation', violations);
    nullableIdentity(receipt.operation.id, '/operation/id', violations);
    if (!nonempty(receipt.operation.name)) add(violations, 'INVALID_OPERATION', '/operation/name', 'nonempty string required');
    nullableIdentity(receipt.operation.configuration_id, '/operation/configuration_id', violations);
    nullableIdentity(receipt.operation.policy_id, '/operation/policy_id', violations);
  }

  const state = { evidenceIds: new Set(), measurementIds: new Set(), measurementById: new Map() };
  if (!Array.isArray(receipt.evidence) || receipt.evidence.length === 0) add(violations, 'EVIDENCE_REQUIRED', '/evidence', 'nonempty array required');
  else receipt.evidence.forEach((value, index) => validateEvidence(value, index, state, violations));
  if (!Array.isArray(receipt.measurements) || receipt.measurements.length === 0) add(violations, 'MEASUREMENTS_REQUIRED', '/measurements', 'nonempty array required');
  else receipt.measurements.forEach((value, index) => validateMeasurement(value, index, state, violations));
  strings(receipt.limitations, '/limitations', violations);

  for (const [index, item] of (Array.isArray(receipt.measurements) ? receipt.measurements : []).entries()) {
    if (!object(item) || item.unit !== 'usd' || !['ESTIMATED', 'MODELED'].includes(item.class)) continue;
    const inputs = object(item.derivation) && Array.isArray(item.derivation.input_measurement_ids)
      ? item.derivation.input_measurement_ids : [];
    if (!inputs.some((identity) => state.measurementById.get(identity)?.unit === 'token')) {
      add(violations, 'MONETARY_ESTIMATE_WITHOUT_TOKENS', `/measurements/${index}/derivation`, 'monetary estimate requires a token measurement input');
    }
  }
  violations.sort((left, right) => left.path.localeCompare(right.path) || left.code.localeCompare(right.code));
  return { valid: violations.length === 0, violations };
}
