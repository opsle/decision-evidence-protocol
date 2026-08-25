import { createHash } from 'node:crypto';
import { TextDecoder } from 'node:util';

export const CONTEXT_FIREWALL_PACKET_PROTOCOL =
  'opsle.context-firewall.evidence-packet/v1';
export const CONTEXT_FIREWALL_INPUT_PROTOCOL =
  'opsle.context-firewall.test-run-input/v1';
export const CONTEXT_FIREWALL_REDUCER =
  '@opsle/context-firewall/test-output';
export const CONTEXT_FIREWALL_REDUCER_VERSION = '0.3.0';
export const CONTEXT_FIREWALL_POLICY_REVISION =
  'tap-subset-policy/v1';

const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const ANSI_PATTERN = /[\u001b\u009b][[\]()#;?]*(?:(?:(?:[a-zA-Z\d]*(?:;[-a-zA-Z\d/#&.:=?%@~_]+)*)?\u0007)|(?:(?:\d{1,4}(?:[;:]\d{0,4})*)?[\dA-PR-TZcf-nq-uy=><~]))/g;
const utf8Decoder = new TextDecoder('utf-8', { fatal: true });
const streamRank = new Map([['stdout', 0], ['stderr', 1]]);

const statuses = new Set(['passed', 'failed', 'indeterminate']);
const dispositions = new Set(['SUFFICIENT', 'NEEDS_RAW_EVIDENCE']);
const sourceEvidenceDispositions = new Set([
  'CALLER_REFERENCE_SUPPLIED',
  'PRESERVATION_UNCONFIRMED',
]);
const sourceCategories = new Set([
  'successful_test',
  'skipped_test',
  'failed_test',
  'failure_message',
  'assertion',
  'stack_trace',
  'failure_detail',
  'fatal_error',
  'timeout',
  'abnormal_warning',
  'aggregate_source',
  'duration_source',
  'structure',
  'informational',
  'blank',
  'unclassified',
  'unclassified_binary',
]);
const derivedCategories = [
  'aggregate_counts',
  'process_status',
  'run_verdict',
  'stream_provenance',
];
const reasonCodes = new Set([
  'AGGREGATE_CONTRADICTION',
  'EXIT_STATUS_MISSING',
  'INTERRUPTED_OUTPUT',
  'MALFORMED_UTF8',
  'NONZERO_EXIT_WITHOUT_RECOGNIZED_FAILURE',
  'OPERATION_ID_MISSING',
  'PAYLOAD_LIMIT_CRITICAL_EVIDENCE_EXCEEDED',
  'PAYLOAD_LIMIT_OMITTED_NONCRITICAL_TEXT',
  'RAW_EVIDENCE_REFERENCE_MISSING',
  'SOURCE_IDENTITY_MISSING',
  'UNCLASSIFIED_EVIDENCE',
]);
const payloadReasonCodes = new Set([
  'PAYLOAD_LIMIT_CRITICAL_EVIDENCE_EXCEEDED',
  'PAYLOAD_LIMIT_OMITTED_NONCRITICAL_TEXT',
]);
const indeterminateReasonCodes = new Set([
  'AGGREGATE_CONTRADICTION',
  'EXIT_STATUS_MISSING',
  'INTERRUPTED_OUTPUT',
  'MALFORMED_UTF8',
  'OPERATION_ID_MISSING',
  'SOURCE_IDENTITY_MISSING',
  'UNCLASSIFIED_EVIDENCE',
]);

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!isPlainObject(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]),
  );
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function sha256(value) {
  const digest = createHash('sha256');
  digest.update(value);
  return `sha256:${digest.digest('hex')}`;
}

function sameJson(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function sortedUnique(values) {
  return [...new Set(values)].sort();
}

function locatorKey(value) {
  return `${value.stream}:${value.line}`;
}

function countCategories(lines) {
  const counts = {};
  for (const line of lines) counts[line.kind] = (counts[line.kind] ?? 0) + 1;
  return Object.fromEntries(
    Object.entries(counts).sort(([left], [right]) => left.localeCompare(right)),
  );
}

function isNonemptyStringOrNull(value) {
  return value === null || (typeof value === 'string' && value.length > 0);
}

function isSafeNonnegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function isSafePositiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function addViolation(violations, kind, code, path, message) {
  const key = `${kind}\0${code}\0${path}\0${message}`;
  if (violations.some((item) => item.key === key)) return;
  violations.push({ key, kind, code, path, message });
}

function requireObject(value, path, violations) {
  if (isPlainObject(value)) return true;
  addViolation(violations, 'STRUCTURE', 'OBJECT_REQUIRED', path, 'object required');
  return false;
}

function requireArray(value, path, violations) {
  if (Array.isArray(value)) return true;
  addViolation(violations, 'STRUCTURE', 'ARRAY_REQUIRED', path, 'array required');
  return false;
}

function requireBoolean(value, path, violations) {
  if (typeof value === 'boolean') return true;
  addViolation(violations, 'STRUCTURE', 'BOOLEAN_REQUIRED', path, 'boolean required');
  return false;
}

function requireHash(value, path, violations) {
  if (typeof value === 'string' && SHA256_PATTERN.test(value)) return true;
  addViolation(
    violations,
    'STRUCTURE',
    'MALFORMED_SHA256',
    path,
    'lowercase sha256:<64 hex characters> required',
  );
  return false;
}

function requireSafeCount(value, path, violations) {
  if (isSafeNonnegativeInteger(value)) return true;
  addViolation(
    violations,
    'STRUCTURE',
    'INVALID_MEASUREMENT',
    path,
    'nonnegative safe integer required',
  );
  return false;
}

function requireNullableIdentity(value, path, violations) {
  if (isNonemptyStringOrNull(value)) return true;
  addViolation(
    violations,
    'STRUCTURE',
    'INVALID_IDENTITY',
    path,
    'nonempty string or null required',
  );
  return false;
}

function requireSortedUniqueStrings(value, path, allowed, violations) {
  if (!requireArray(value, path, violations)) return false;
  let valid = true;
  for (const [index, item] of value.entries()) {
    if (typeof item !== 'string' || !allowed.has(item)) {
      addViolation(
        violations,
        'STRUCTURE',
        'UNSUPPORTED_ENUM_VALUE',
        `${path}/${index}`,
        'unsupported value',
      );
      valid = false;
    }
  }
  if (valid && !sameJson(value, sortedUnique(value))) {
    addViolation(
      violations,
      'CONSISTENCY',
      'NONCANONICAL_SET_ORDER',
      path,
      'values must be unique and lexically sorted',
    );
  }
  return valid;
}

function validateLineEvidence(value, path, allowedCategories, streamNames, violations) {
  if (!requireObject(value, path, violations)) return false;
  let valid = true;
  if (!allowedCategories.has(value.category)) {
    addViolation(
      violations,
      'STRUCTURE',
      'INVALID_EVIDENCE_CATEGORY',
      `${path}/category`,
      'category is not valid at this location',
    );
    valid = false;
  }
  if (!isSafePositiveInteger(value.line)) {
    addViolation(
      violations,
      'STRUCTURE',
      'INVALID_LINE_LOCATOR',
      `${path}/line`,
      'positive safe integer required',
    );
    valid = false;
  }
  if (typeof value.stream !== 'string' || !streamNames.has(value.stream)) {
    addViolation(
      violations,
      'STRUCTURE',
      'INVALID_STREAM_LOCATOR',
      `${path}/stream`,
      'declared source stream required',
    );
    valid = false;
  }
  if (!requireHash(value.sha256, `${path}/sha256`, violations)) valid = false;
  const hasText = Object.hasOwn(value, 'text');
  const hasByteCount = Object.hasOwn(value, 'byte_count');
  if (hasText === hasByteCount) {
    addViolation(
      violations,
      'STRUCTURE',
      'INVALID_EVIDENCE_REPRESENTATION',
      path,
      'exactly one of text or byte_count is required',
    );
    valid = false;
  } else if (hasText && typeof value.text !== 'string') {
    addViolation(violations, 'STRUCTURE', 'STRING_REQUIRED', `${path}/text`, 'string required');
    valid = false;
  } else if (hasByteCount && !isSafeNonnegativeInteger(value.byte_count)) {
    addViolation(
      violations,
      'STRUCTURE',
      'INVALID_MEASUREMENT',
      `${path}/byte_count`,
      'nonnegative safe integer required',
    );
    valid = false;
  }
  return valid;
}

function validateSchema(packet, violations) {
  if (!requireObject(packet, '', violations)) return null;
  if (packet.protocol_version !== CONTEXT_FIREWALL_PACKET_PROTOCOL) {
    addViolation(
      violations,
      'STRUCTURE',
      'UNSUPPORTED_PACKET_VERSION',
      '/protocol_version',
      `only ${CONTEXT_FIREWALL_PACKET_PROTOCOL} is supported`,
    );
  }
  requireNullableIdentity(packet.operation_id, '/operation_id', violations);
  if (!requireObject(packet.decision_evidence, '/decision_evidence', violations)) return null;
  if (!requireObject(packet.receipt, '/receipt', violations)) return null;

  const evidence = packet.decision_evidence;
  const receipt = packet.receipt;
  if (!requireObject(receipt.source, '/receipt/source', violations)) return null;
  const declaredStreams = requireArray(receipt.source.streams, '/receipt/source/streams', violations)
    ? receipt.source.streams
    : [];
  const streamNames = new Set();
  for (const [index, stream] of declaredStreams.entries()) {
    const path = `/receipt/source/streams/${index}`;
    if (!requireObject(stream, path, violations)) continue;
    if (!streamRank.has(stream.name) || streamNames.has(stream.name)) {
      addViolation(
        violations,
        'STRUCTURE',
        'INVALID_SOURCE_STREAM',
        `${path}/name`,
        'unique stdout or stderr stream required',
      );
    } else streamNames.add(stream.name);
    requireSafeCount(stream.byte_count, `${path}/byte_count`, violations);
  }
  if (declaredStreams.length < 1 || declaredStreams.length > 2) {
    addViolation(
      violations,
      'STRUCTURE',
      'INVALID_SOURCE_STREAM_COUNT',
      '/receipt/source/streams',
      'one or two streams required',
    );
  }

  if (!requireObject(evidence.counts, '/decision_evidence/counts', violations)) return null;
  for (const field of ['passed', 'failed', 'skipped', 'total']) {
    requireSafeCount(evidence.counts[field], `/decision_evidence/counts/${field}`, violations);
  }
  if (!dispositions.has(evidence.disposition)) {
    addViolation(
      violations,
      'STRUCTURE',
      'INVALID_DISPOSITION',
      '/decision_evidence/disposition',
      'SUFFICIENT or NEEDS_RAW_EVIDENCE required',
    );
  }
  if (!statuses.has(evidence.status)) {
    addViolation(
      violations,
      'STRUCTURE',
      'INVALID_STATUS',
      '/decision_evidence/status',
      'passed, failed, or indeterminate required',
    );
  }
  requireSortedUniqueStrings(
    evidence.reason_codes,
    '/decision_evidence/reason_codes',
    reasonCodes,
    violations,
  );
  if (!requireObject(evidence.process, '/decision_evidence/process', violations)) return null;
  const { duration_ms: durationMs, exit_code: exitCode } = evidence.process;
  if (durationMs !== null && (
    typeof durationMs !== 'number' || !Number.isFinite(durationMs) || durationMs < 0
  )) {
    addViolation(
      violations,
      'STRUCTURE',
      'INVALID_DURATION',
      '/decision_evidence/process/duration_ms',
      'nonnegative finite number or null required',
    );
  }
  if (exitCode !== null && (!Number.isInteger(exitCode) || exitCode < 0 || exitCode > 255)) {
    addViolation(
      violations,
      'STRUCTURE',
      'INVALID_EXIT_CODE',
      '/decision_evidence/process/exit_code',
      'integer from 0 through 255 or null required',
    );
  }
  requireBoolean(evidence.process.interrupted, '/decision_evidence/process/interrupted', violations);
  if (!requireObject(evidence.source, '/decision_evidence/source', violations)) return null;
  requireNullableIdentity(evidence.source.id, '/decision_evidence/source/id', violations);
  requireNullableIdentity(evidence.source.run_id, '/decision_evidence/source/run_id', violations);

  const entries = [];
  const addEntry = (value, path, allowed) => {
    if (validateLineEvidence(value, path, allowed, streamNames, violations)) {
      entries.push({ value, path });
    }
  };
  if (requireArray(evidence.failures, '/decision_evidence/failures', violations)) {
    for (const [index, failure] of evidence.failures.entries()) {
      const path = `/decision_evidence/failures/${index}`;
      if (!requireObject(failure, path, violations)) continue;
      if (typeof failure.identity !== 'string' || failure.identity.length === 0) {
        addViolation(
          violations,
          'STRUCTURE',
          'INVALID_FAILURE_IDENTITY',
          `${path}/identity`,
          'nonempty string required',
        );
      }
      if (Object.hasOwn(failure, 'header')) {
        addEntry(failure.header, `${path}/header`, new Set(['failed_test']));
      }
      if (Object.hasOwn(failure, 'details')) {
        if (requireArray(failure.details, `${path}/details`, violations)) {
          for (const [detailIndex, detail] of failure.details.entries()) {
            addEntry(
              detail,
              `${path}/details/${detailIndex}`,
              new Set(['failure_message', 'assertion', 'stack_trace', 'failure_detail']),
            );
          }
        }
      }
    }
  }
  for (const [field, categories] of [
    ['fatal_errors', new Set(['fatal_error'])],
    ['timeouts', new Set(['timeout'])],
    ['warnings', new Set(['abnormal_warning'])],
    ['unclassified_evidence', new Set(['unclassified', 'unclassified_binary'])],
  ]) {
    if (requireArray(evidence[field], `/decision_evidence/${field}`, violations)) {
      for (const [index, item] of evidence[field].entries()) {
        addEntry(item, `/decision_evidence/${field}/${index}`, categories);
      }
    }
  }

  if (!requireObject(receipt.configuration, '/receipt/configuration', violations)) return null;
  requireHash(receipt.configuration.identity, '/receipt/configuration/identity', violations);
  if (receipt.configuration.max_output_bytes !== null
    && !isSafePositiveInteger(receipt.configuration.max_output_bytes)) {
    addViolation(
      violations,
      'STRUCTURE',
      'INVALID_PAYLOAD_CEILING',
      '/receipt/configuration/max_output_bytes',
      'positive safe integer or null required',
    );
  }
  if (receipt.configuration.policy_revision !== CONTEXT_FIREWALL_POLICY_REVISION) {
    addViolation(
      violations,
      'STRUCTURE',
      'UNSUPPORTED_POLICY_REVISION',
      '/receipt/configuration/policy_revision',
      `only ${CONTEXT_FIREWALL_POLICY_REVISION} is supported`,
    );
  }
  requireHash(receipt.input_hash, '/receipt/input_hash', violations);
  requireHash(receipt.semantic_payload_hash, '/receipt/semantic_payload_hash', violations);

  if (!requireObject(receipt.measurements, '/receipt/measurements', violations)) return null;
  for (const field of [
    'original_bytes',
    'original_event_count',
    'reduced_bytes',
    'retained_evidence_count',
    'suppressed_evidence_count',
  ]) {
    requireSafeCount(receipt.measurements[field], `/receipt/measurements/${field}`, violations);
  }
  if (!requireObject(receipt.payload_limit, '/receipt/payload_limit', violations)) return null;
  requireBoolean(receipt.payload_limit.affected, '/receipt/payload_limit/affected', violations);
  if (receipt.payload_limit.honored !== true) {
    addViolation(
      violations,
      'STRUCTURE',
      'PAYLOAD_LIMIT_NOT_HONORED',
      '/receipt/payload_limit/honored',
      'packet-v1 requires true',
    );
  }
  if (receipt.payload_limit.requested_bytes !== null
    && !isSafePositiveInteger(receipt.payload_limit.requested_bytes)) {
    addViolation(
      violations,
      'STRUCTURE',
      'INVALID_PAYLOAD_CEILING',
      '/receipt/payload_limit/requested_bytes',
      'positive safe integer or null required',
    );
  }

  if (!requireObject(receipt.raw_evidence, '/receipt/raw_evidence', violations)) return null;
  const raw = receipt.raw_evidence;
  if (raw.destroyed_by_reducer !== false) {
    addViolation(
      violations,
      'STRUCTURE',
      'UNSUPPORTED_DESTRUCTION_CLAIM',
      '/receipt/raw_evidence/destroyed_by_reducer',
      'this reducer contract requires false',
    );
  }
  requireBoolean(raw.escalation_available, '/receipt/raw_evidence/escalation_available', violations);
  requireBoolean(raw.escalation_required, '/receipt/raw_evidence/escalation_required', violations);
  requireNullableIdentity(raw.reference, '/receipt/raw_evidence/reference', violations);
  if (!sourceEvidenceDispositions.has(raw.source_evidence_disposition)) {
    addViolation(
      violations,
      'STRUCTURE',
      'INVALID_SOURCE_EVIDENCE_DISPOSITION',
      '/receipt/raw_evidence/source_evidence_disposition',
      'unsupported disposition',
    );
  }
  requireBoolean(
    raw.suppressed_from_model_context,
    '/receipt/raw_evidence/suppressed_from_model_context',
    violations,
  );

  if (receipt.receipt_version !== 1) {
    addViolation(
      violations,
      'STRUCTURE',
      'UNSUPPORTED_RECEIPT_VERSION',
      '/receipt/receipt_version',
      'only receipt version 1 is supported',
    );
  }
  if (!requireObject(receipt.reducer, '/receipt/reducer', violations)) return null;
  if (receipt.reducer.name !== CONTEXT_FIREWALL_REDUCER) {
    addViolation(
      violations,
      'STRUCTURE',
      'UNSUPPORTED_REDUCER',
      '/receipt/reducer/name',
      `only ${CONTEXT_FIREWALL_REDUCER} is supported`,
    );
  }
  if (receipt.reducer.version !== CONTEXT_FIREWALL_REDUCER_VERSION) {
    addViolation(
      violations,
      'STRUCTURE',
      'UNSUPPORTED_REDUCER_VERSION',
      '/receipt/reducer/version',
      `only ${CONTEXT_FIREWALL_REDUCER_VERSION} is supported`,
    );
  }
  requireBoolean(receipt.reduction_complete, '/receipt/reduction_complete', violations);

  if (!requireObject(receipt.retained, '/receipt/retained', violations)) return null;
  requireSortedUniqueStrings(
    receipt.retained.categories,
    '/receipt/retained/categories',
    new Set([...sourceCategories, ...derivedCategories]),
    violations,
  );
  requireSafeCount(receipt.retained.event_count, '/receipt/retained/event_count', violations);
  requireNullableIdentity(receipt.source.id, '/receipt/source/id', violations);
  requireNullableIdentity(receipt.source.run_id, '/receipt/source/run_id', violations);
  if (receipt.source.protocol_version !== CONTEXT_FIREWALL_INPUT_PROTOCOL) {
    addViolation(
      violations,
      'STRUCTURE',
      'UNSUPPORTED_SOURCE_PROTOCOL',
      '/receipt/source/protocol_version',
      `only ${CONTEXT_FIREWALL_INPUT_PROTOCOL} is supported`,
    );
  }

  if (!requireObject(receipt.suppressed, '/receipt/suppressed', violations)) return null;
  if (requireObject(receipt.suppressed.categories, '/receipt/suppressed/categories', violations)) {
    for (const [category, count] of Object.entries(receipt.suppressed.categories)) {
      if (!sourceCategories.has(category)) {
        addViolation(
          violations,
          'STRUCTURE',
          'INVALID_EVIDENCE_CATEGORY',
          `/receipt/suppressed/categories/${category}`,
          'unknown source evidence category',
        );
      }
      requireSafeCount(count, `/receipt/suppressed/categories/${category}`, violations);
    }
  }
  requireSafeCount(receipt.suppressed.event_count, '/receipt/suppressed/event_count', violations);
  requireBoolean(
    receipt.unclassified_evidence_present,
    '/receipt/unclassified_evidence_present',
    violations,
  );
  return { evidence, receipt, entries, declaredStreams, streamNames };
}

function addMismatch(violations, code, path, message) {
  addViolation(violations, 'CONSISTENCY', code, path, message);
}

function addCryptoMismatch(violations, code, path, message) {
  addViolation(violations, 'CRYPTOGRAPHIC', code, path, message);
}

function deriveStatus(evidence) {
  const recognizedFailure = evidence.failures.length > 0
    || evidence.fatal_errors.length > 0
    || evidence.timeouts.length > 0
    || evidence.counts.failed > 0;
  const nonzero = evidence.process.exit_code !== null && evidence.process.exit_code !== 0;
  if (recognizedFailure || nonzero) return 'failed';
  if (evidence.reason_codes.some((reason) => indeterminateReasonCodes.has(reason))) {
    return 'indeterminate';
  }
  return 'passed';
}

function expectedReceiptReasons(packet) {
  const { decision_evidence: evidence, operation_id: operationId, receipt } = packet;
  const reasons = [];
  if (receipt.unclassified_evidence_present) reasons.push('UNCLASSIFIED_EVIDENCE');
  if (evidence.process.interrupted) reasons.push('INTERRUPTED_OUTPUT');
  if (evidence.process.exit_code === null) reasons.push('EXIT_STATUS_MISSING');
  const recognizedFailure = evidence.failures.length > 0
    || evidence.fatal_errors.length > 0
    || evidence.timeouts.length > 0
    || evidence.counts.failed > 0;
  if (evidence.process.exit_code !== null
    && evidence.process.exit_code !== 0
    && !recognizedFailure) {
    reasons.push('NONZERO_EXIT_WITHOUT_RECOGNIZED_FAILURE');
  }
  if (operationId === null) reasons.push('OPERATION_ID_MISSING');
  if (evidence.source.id === null) reasons.push('SOURCE_IDENTITY_MISSING');
  if (receipt.raw_evidence.reference === null) reasons.push('RAW_EVIDENCE_REFERENCE_MISSING');
  for (const reason of evidence.reason_codes) {
    if (['AGGREGATE_CONTRADICTION', 'MALFORMED_UTF8'].includes(reason)) reasons.push(reason);
    if (payloadReasonCodes.has(reason)) reasons.push(reason);
  }
  return sortedUnique(reasons);
}

function validateConsistency(packet, schema, packetBytes, violations, claims) {
  const { evidence, receipt, entries, declaredStreams } = schema;
  const measurements = receipt.measurements;
  const reasons = evidence.reason_codes;
  const payloadReasons = reasons.filter((reason) => payloadReasonCodes.has(reason));

  if (evidence.source.id !== receipt.source.id) {
    addMismatch(violations, 'SOURCE_ID_MISMATCH', '/receipt/source/id', 'source identities differ');
  }
  if (evidence.source.run_id !== receipt.source.run_id) {
    addMismatch(violations, 'RUN_ID_MISMATCH', '/receipt/source/run_id', 'run identities differ');
  }
  const streamOrder = declaredStreams.map((stream) => stream.name);
  if (!sameJson(streamOrder, [...streamOrder].sort((left, right) => streamRank.get(left) - streamRank.get(right)))) {
    addMismatch(
      violations,
      'NONCANONICAL_STREAM_ORDER',
      '/receipt/source/streams',
      'streams must be ordered stdout then stderr',
    );
  }
  const declaredOriginalBytes = declaredStreams.reduce((sum, stream) => sum + stream.byte_count, 0);
  if (measurements.original_bytes !== declaredOriginalBytes) {
    addMismatch(
      violations,
      'ORIGINAL_BYTE_COUNT_MISMATCH',
      '/receipt/measurements/original_bytes',
      'must equal the sum of source stream byte counts',
    );
  }
  if (measurements.retained_evidence_count !== receipt.retained.event_count) {
    addMismatch(
      violations,
      'RETAINED_COUNT_MISMATCH',
      '/receipt/measurements/retained_evidence_count',
      'must equal receipt.retained.event_count',
    );
  }
  if (measurements.suppressed_evidence_count !== receipt.suppressed.event_count) {
    addMismatch(
      violations,
      'SUPPRESSED_COUNT_MISMATCH',
      '/receipt/measurements/suppressed_evidence_count',
      'must equal receipt.suppressed.event_count',
    );
  }
  if (measurements.retained_evidence_count + measurements.suppressed_evidence_count
    !== measurements.original_event_count) {
    addMismatch(
      violations,
      'EVIDENCE_ACCOUNTING_MISMATCH',
      '/receipt/measurements/original_event_count',
      'retained plus suppressed must equal original event count',
    );
  }
  const suppressedCategoryTotal = Object.values(receipt.suppressed.categories)
    .reduce((sum, count) => sum + count, 0);
  if (suppressedCategoryTotal !== receipt.suppressed.event_count) {
    addMismatch(
      violations,
      'SUPPRESSION_CATEGORY_TOTAL_MISMATCH',
      '/receipt/suppressed/categories',
      'category counts must sum to suppressed.event_count',
    );
  }

  const canonicalBytes = Buffer.from(`${canonicalJson(packet)}\n`, 'utf8');
  if (measurements.reduced_bytes !== canonicalBytes.length) {
    addMismatch(
      violations,
      'REDUCED_BYTE_COUNT_MISMATCH',
      '/receipt/measurements/reduced_bytes',
      'must equal canonical packet bytes including the final newline',
    );
  }
  claims.reduced_bytes = measurements.reduced_bytes === canonicalBytes.length
    ? 'VERIFIED'
    : 'MISMATCH';
  if (packetBytes !== undefined) {
    let supplied;
    try {
      supplied = Buffer.isBuffer(packetBytes) ? packetBytes : Buffer.from(packetBytes);
    } catch {
      supplied = null;
    }
    if (!supplied || !supplied.equals(canonicalBytes)) {
      addCryptoMismatch(
        violations,
        'NONCANONICAL_PACKET_BYTES',
        '/',
        'supplied packet bytes do not equal canonical packet-v1 serialization',
      );
      claims.packet_serialization = 'MISMATCH';
    } else claims.packet_serialization = 'VERIFIED';
  }

  const semanticHash = sha256(Buffer.from(canonicalJson(evidence), 'utf8'));
  if (semanticHash !== receipt.semantic_payload_hash) {
    addCryptoMismatch(
      violations,
      'SEMANTIC_PAYLOAD_HASH_MISMATCH',
      '/receipt/semantic_payload_hash',
      'does not match canonical decision_evidence bytes',
    );
    claims.semantic_payload_hash = 'MISMATCH';
  } else claims.semantic_payload_hash = 'VERIFIED';

  const configurationHash = sha256(Buffer.from(canonicalJson({
    max_output_bytes: receipt.configuration.max_output_bytes,
    policy_revision: receipt.configuration.policy_revision,
    reducer_version: receipt.reducer.version,
  }), 'utf8'));
  if (configurationHash !== receipt.configuration.identity) {
    addCryptoMismatch(
      violations,
      'CONFIGURATION_HASH_MISMATCH',
      '/receipt/configuration/identity',
      'does not match canonical packet configuration',
    );
    claims.configuration_identity = 'MISMATCH';
  } else claims.configuration_identity = 'VERIFIED';

  const locators = new Set();
  let unresolvedLineHashes = 0;
  let lineHashMismatch = false;
  for (const { value, path } of entries) {
    const key = locatorKey(value);
    if (locators.has(key)) {
      addMismatch(violations, 'DUPLICATE_EVIDENCE_LOCATOR', path, 'source line is represented more than once');
    }
    locators.add(key);
    if (Object.hasOwn(value, 'text')) {
      const digest = sha256(Buffer.from(value.text, 'utf8'));
      if (digest !== value.sha256) {
        addCryptoMismatch(
          violations,
          'LINE_EVIDENCE_HASH_MISMATCH',
          `${path}/sha256`,
          'does not match retained text bytes',
        );
        lineHashMismatch = true;
      }
    } else unresolvedLineHashes += 1;
  }
  claims.line_evidence_hashes = lineHashMismatch
    ? 'MISMATCH'
    : unresolvedLineHashes > 0 ? 'PARTIAL' : entries.length > 0 ? 'VERIFIED' : 'NOT_APPLICABLE';

  const retainedTextEntries = entries.filter(({ value }) => Object.hasOwn(value, 'text'));
  if (receipt.retained.event_count !== retainedTextEntries.length) {
    addMismatch(
      violations,
      'RETAINED_LINE_COUNT_MISMATCH',
      '/receipt/retained/event_count',
      'must equal the number of retained source-line texts',
    );
  }
  const expectedRetainedCategories = sortedUnique([
    ...derivedCategories,
    ...retainedTextEntries.map(({ value }) => value.category),
  ]);
  if (!sameJson(receipt.retained.categories, expectedRetainedCategories)) {
    addMismatch(
      violations,
      'RETAINED_CATEGORY_MISMATCH',
      '/receipt/retained/categories',
      'must describe the retained source-line texts plus derived evidence',
    );
  }

  if (receipt.configuration.max_output_bytes !== receipt.payload_limit.requested_bytes) {
    addMismatch(
      violations,
      'PAYLOAD_CONFIGURATION_MISMATCH',
      '/receipt/payload_limit/requested_bytes',
      'must equal configuration.max_output_bytes',
    );
  }
  if (receipt.payload_limit.requested_bytes !== null
    && measurements.reduced_bytes > receipt.payload_limit.requested_bytes) {
    addMismatch(
      violations,
      'PAYLOAD_CEILING_EXCEEDED',
      '/receipt/measurements/reduced_bytes',
      'canonical packet exceeds the declared honored ceiling',
    );
  }
  if (receipt.payload_limit.affected !== (payloadReasons.length === 1)) {
    addMismatch(
      violations,
      'PAYLOAD_ESCALATION_MISMATCH',
      '/receipt/payload_limit/affected',
      'affected must correspond to exactly one payload reason code',
    );
  }
  if (payloadReasons.length > 1) {
    addMismatch(
      violations,
      'CONTRADICTORY_PAYLOAD_REASONS',
      '/decision_evidence/reason_codes',
      'packet modes cannot declare both payload omission states',
    );
  }
  if (receipt.payload_limit.affected && receipt.payload_limit.requested_bytes === null) {
    addMismatch(
      violations,
      'MISSING_PAYLOAD_CEILING',
      '/receipt/payload_limit/requested_bytes',
      'payload-affected packet requires a ceiling',
    );
  }

  const expectedReasons = expectedReceiptReasons(packet);
  if (!sameJson(reasons, expectedReasons)) {
    addMismatch(
      violations,
      'REASON_CODE_MISMATCH',
      '/decision_evidence/reason_codes',
      'reason codes contradict derivable receipt state',
    );
  }
  const expectedDisposition = reasons.length === 0 ? 'SUFFICIENT' : 'NEEDS_RAW_EVIDENCE';
  if (evidence.disposition !== expectedDisposition) {
    addMismatch(
      violations,
      'DISPOSITION_MISMATCH',
      '/decision_evidence/disposition',
      'SUFFICIENT is permitted only when reason_codes is empty',
    );
  }
  if (receipt.raw_evidence.escalation_required !== (reasons.length > 0)) {
    addMismatch(
      violations,
      'ESCALATION_REQUIRED_MISMATCH',
      '/receipt/raw_evidence/escalation_required',
      'must match NEEDS_RAW_EVIDENCE state',
    );
  }
  if (receipt.reduction_complete !== (reasons.length === 0)) {
    addMismatch(
      violations,
      'REDUCTION_COMPLETE_MISMATCH',
      '/receipt/reduction_complete',
      'complete reduction requires no escalation reasons',
    );
  }
  if (deriveStatus(evidence) !== evidence.status) {
    addMismatch(
      violations,
      'STATUS_MISMATCH',
      '/decision_evidence/status',
      'status contradicts process, failures, counts, or uncertainty reasons',
    );
  }
  const countsAdd = evidence.counts.passed + evidence.counts.failed + evidence.counts.skipped;
  if (countsAdd !== evidence.counts.total && !reasons.includes('AGGREGATE_CONTRADICTION')) {
    addMismatch(
      violations,
      'IMPOSSIBLE_EVIDENCE_COUNTS',
      '/decision_evidence/counts/total',
      'total mismatch requires AGGREGATE_CONTRADICTION',
    );
  }
  if (evidence.counts.failed !== evidence.failures.length
    && !reasons.includes('AGGREGATE_CONTRADICTION')) {
    addMismatch(
      violations,
      'FAILURE_COUNT_MISMATCH',
      '/decision_evidence/counts/failed',
      'failed count must equal represented failures absent an aggregate contradiction',
    );
  }
  if (reasons.includes('MALFORMED_UTF8') && !evidence.unclassified_evidence
    .some((item) => item.category === 'unclassified_binary')) {
    addMismatch(
      violations,
      'MALFORMED_UTF8_EVIDENCE_MISSING',
      '/decision_evidence/unclassified_evidence',
      'MALFORMED_UTF8 requires an unclassified_binary locator',
    );
  }
  if (receipt.unclassified_evidence_present
    !== (evidence.unclassified_evidence.length > 0)) {
    addMismatch(
      violations,
      'UNCLASSIFIED_FLAG_MISMATCH',
      '/receipt/unclassified_evidence_present',
      'must match unclassified_evidence presence',
    );
  }

  const criticalOmission = reasons.includes('PAYLOAD_LIMIT_CRITICAL_EVIDENCE_EXCEEDED');
  for (const [index, failure] of evidence.failures.entries()) {
    const hasRegion = Object.hasOwn(failure, 'header') && Object.hasOwn(failure, 'details');
    if (!hasRegion && !criticalOmission) {
      addMismatch(
        violations,
        'FAILURE_REGION_MISSING',
        `/decision_evidence/failures/${index}`,
        'failure header and details may be omitted only in compact escalation mode',
      );
    }
    if (criticalOmission && hasRegion) {
      addMismatch(
        violations,
        'INVALID_COMPACT_PACKET',
        `/decision_evidence/failures/${index}`,
        'compact escalation omits all critical source-line text',
      );
    }
  }
  if (criticalOmission && (
    evidence.fatal_errors.length > 0
    || evidence.timeouts.length > 0
    || receipt.retained.event_count !== 0
  )) {
    addMismatch(
      violations,
      'INVALID_COMPACT_PACKET',
      '/decision_evidence',
      'compact escalation cannot retain critical source-line text',
    );
  }
  if (!receipt.payload_limit.affected && entries.some(({ value }) => !Object.hasOwn(value, 'text'))) {
    addMismatch(
      violations,
      'UNDECLARED_TEXT_SUPPRESSION',
      '/decision_evidence',
      'hash-only line references require a payload-affected packet',
    );
  }

  const hasReference = receipt.raw_evidence.reference !== null;
  if (receipt.raw_evidence.escalation_available !== hasReference) {
    addMismatch(
      violations,
      'RAW_ESCALATION_AVAILABILITY_MISMATCH',
      '/receipt/raw_evidence/escalation_available',
      'availability means only that a caller reference was supplied',
    );
  }
  const expectedSourceDisposition = hasReference
    ? 'CALLER_REFERENCE_SUPPLIED'
    : 'PRESERVATION_UNCONFIRMED';
  if (receipt.raw_evidence.source_evidence_disposition !== expectedSourceDisposition) {
    addMismatch(
      violations,
      'RAW_EVIDENCE_DISPOSITION_MISMATCH',
      '/receipt/raw_evidence/source_evidence_disposition',
      'disposition contradicts caller reference presence',
    );
  }
  if (receipt.raw_evidence.suppressed_from_model_context
    !== (receipt.suppressed.event_count > 0)) {
    addMismatch(
      violations,
      'SUPPRESSION_STATE_MISMATCH',
      '/receipt/raw_evidence/suppressed_from_model_context',
      'must match whether any source events were suppressed',
    );
  }
}

function decodeStrictBase64(value) {
  if (typeof value !== 'string'
    || value.length % 4 !== 0
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new TypeError('invalid base64 stream data');
  }
  return Buffer.from(value, 'base64');
}

function normalizeSuppliedStreams(options) {
  if (options.sourceInput !== undefined && options.sourceStreams !== undefined) {
    throw new TypeError('supply sourceInput or sourceStreams, not both');
  }
  if (options.sourceInput !== undefined) {
    const input = options.sourceInput;
    if (!isPlainObject(input) || !Array.isArray(input.streams)) {
      throw new TypeError('sourceInput with streams is required');
    }
    const streams = input.streams.map((stream) => {
      if (!isPlainObject(stream) || !streamRank.has(stream.name) || typeof stream.data !== 'string') {
        throw new TypeError('sourceInput stream must contain stdout/stderr string data');
      }
      const encoding = stream.encoding ?? 'utf8';
      if (!['utf8', 'base64'].includes(encoding)) throw new TypeError('unsupported stream encoding');
      return {
        name: stream.name,
        bytes: encoding === 'base64' ? decodeStrictBase64(stream.data) : Buffer.from(stream.data, 'utf8'),
      };
    });
    return { streams: normalizeStreamList(streams), sourceInput: input };
  }
  if (options.sourceStreams !== undefined) {
    if (!Array.isArray(options.sourceStreams)) throw new TypeError('sourceStreams must be an array');
    const streams = options.sourceStreams.map((stream) => {
      if (!isPlainObject(stream) || !streamRank.has(stream.name)) {
        throw new TypeError('source stream name must be stdout or stderr');
      }
      let bytes;
      if (typeof stream.bytes === 'string') bytes = Buffer.from(stream.bytes, 'utf8');
      else if (Buffer.isBuffer(stream.bytes) || stream.bytes instanceof Uint8Array) {
        bytes = Buffer.from(stream.bytes);
      } else throw new TypeError('source stream bytes required');
      return { name: stream.name, bytes };
    });
    return { streams: normalizeStreamList(streams), sourceInput: null };
  }
  return null;
}

function normalizeStreamList(streams) {
  if (streams.length < 1 || streams.length > 2) throw new TypeError('one or two source streams required');
  const names = new Set();
  for (const stream of streams) {
    if (names.has(stream.name)) throw new TypeError(`duplicate ${stream.name} stream`);
    names.add(stream.name);
  }
  return [...streams].sort((left, right) => streamRank.get(left.name) - streamRank.get(right.name));
}

function streamDigest(streams) {
  const digest = createHash('sha256');
  for (const stream of streams) {
    digest.update(Buffer.from(`${stream.name}\0${stream.bytes.length}\0`, 'utf8'));
    digest.update(stream.bytes);
    digest.update(Buffer.from('\0', 'utf8'));
  }
  return `sha256:${digest.digest('hex')}`;
}

function splitLines(text) {
  if (text.length === 0) return [];
  const lines = text.split('\n');
  if (text.endsWith('\n')) lines.pop();
  return lines;
}

function classifyFailureDetail(clean) {
  if (/^\s*(?:operator|expected|actual|diff|code):/i.test(clean)) return 'assertion';
  if (/^\s*(?:[A-Za-z]*Error:|at\s+|.*\([^()]+:\d+:\d+\)\s*$)/.test(clean)) return 'stack_trace';
  if (/^\s*(?:error|message|cause):/i.test(clean)) return 'failure_message';
  return 'failure_detail';
}

function independentlyClassify(streams) {
  const lines = [];
  const failures = [];
  const fatalErrors = [];
  const timeouts = [];
  const warnings = [];
  const unclassified = [];
  const summaryValues = new Map();
  const summaryConflicts = [];
  const observed = { passed: 0, failed: 0, skipped: 0 };
  let malformedUtf8 = false;

  for (const stream of streams) {
    let text;
    try {
      text = utf8Decoder.decode(stream.bytes);
    } catch {
      malformedUtf8 = true;
      if (stream.bytes.length > 0) {
        const line = {
          stream: stream.name,
          line: 1,
          text: `[non-UTF-8 ${stream.bytes.length} bytes; ${sha256(stream.bytes)}]`,
          kind: 'unclassified_binary',
        };
        lines.push(line);
        unclassified.push(line);
      }
      continue;
    }
    let currentFailure = null;
    for (const [index, rawLine] of splitLines(text).entries()) {
      const line = { stream: stream.name, line: index + 1, text: rawLine };
      const clean = rawLine.replace(/\r$/, '').replace(ANSI_PATTERN, '');
      const marker = clean.match(/^\s*(not ok|ok)\b(?:\s+\d+)?(?:\s*-\s*)?(.*)$/);
      const summary = clean.match(/^\s*#\s*(tests|pass|fail|skipped)\s+(\d+)\s*$/);
      if (marker) {
        currentFailure = null;
        const directive = marker[2].match(/\s+#\s*(SKIP|TODO)\b.*$/i);
        const identity = marker[2].replace(/\s+#\s*(?:SKIP|TODO)\b.*$/i, '').trim()
          || '(unnamed test)';
        if (marker[1] === 'ok' && directive?.[1].toUpperCase() === 'SKIP') {
          line.kind = 'skipped_test';
          observed.skipped += 1;
        } else if (marker[1] === 'ok') {
          line.kind = 'successful_test';
          observed.passed += 1;
        } else if (directive?.[1].toUpperCase() === 'TODO') {
          line.kind = 'unclassified';
          unclassified.push(line);
        } else {
          line.kind = 'failed_test';
          observed.failed += 1;
          currentFailure = { identity, header: line, details: [] };
          failures.push(currentFailure);
        }
      } else if (summary) {
        currentFailure = null;
        line.kind = 'aggregate_source';
        const key = summary[1] === 'pass' ? 'passed'
          : summary[1] === 'fail' ? 'failed' : summary[1];
        const value = Number(summary[2]);
        if (summaryValues.has(key) && summaryValues.get(key) !== value) summaryConflicts.push(key);
        summaryValues.set(key, value);
      } else if (currentFailure && !/^\s*(?:TAP version \d+|1\.\.\d+|#\s*Subtest:.*)\s*$/.test(clean)) {
        line.kind = classifyFailureDetail(clean);
        currentFailure.details.push(line);
      } else if (/^\s*(?:TAP version \d+|1\.\.\d+|#\s*Subtest:.*|---|\.\.\.)\s*$/.test(clean)) {
        currentFailure = null;
        line.kind = 'structure';
      } else {
        const fatal = clean.match(/^\s*(?:#\s*)?(?:FATAL|RUNNER CRASH|UNCAUGHT):\s*(.+)$/);
        const timeout = clean.match(/^\s*(?:#\s*)?TIMEOUT:\s*(.+)$/);
        const warning = clean.match(/^\s*(?:#\s*)?(?:WARNING|WARN):\s*(.+)$/);
        if (fatal) {
          line.kind = 'fatal_error';
          fatalErrors.push(line);
        } else if (timeout) {
          line.kind = 'timeout';
          timeouts.push(line);
        } else if (warning) {
          line.kind = 'abnormal_warning';
          warnings.push(line);
        } else if (/^\s*#\s*(?:duration_ms\s+\d+(?:\.\d+)?|note:\s*.*)\s*$/.test(clean)) {
          line.kind = clean.includes('duration_ms') ? 'duration_source' : 'informational';
        } else if (/^\s*$/.test(clean)) line.kind = 'blank';
        else {
          line.kind = 'unclassified';
          unclassified.push(line);
        }
      }
      lines.push(line);
    }
  }
  const counts = {
    passed: summaryValues.get('passed') ?? observed.passed,
    failed: summaryValues.get('failed') ?? observed.failed,
    skipped: summaryValues.get('skipped') ?? observed.skipped,
    total: summaryValues.get('tests')
      ?? ((summaryValues.has('passed') || summaryValues.has('failed') || summaryValues.has('skipped'))
        ? (summaryValues.get('passed') ?? 0) + (summaryValues.get('failed') ?? 0)
          + (summaryValues.get('skipped') ?? 0)
        : observed.passed + observed.failed + observed.skipped),
  };
  const contradictions = [...summaryConflicts];
  for (const key of ['passed', 'failed', 'skipped']) {
    if (summaryValues.has(key) && summaryValues.get(key) !== observed[key]) contradictions.push(key);
  }
  if (summaryValues.has('tests')
    && summaryValues.get('tests') !== observed.passed + observed.failed + observed.skipped) {
    contradictions.push('total');
  }
  return {
    lines,
    failures,
    fatalErrors,
    timeouts,
    warnings,
    unclassified,
    counts,
    contradictions: sortedUnique(contradictions),
    malformedUtf8,
  };
}

function expectedSourceReasons(packet, parsed) {
  const reasons = [];
  const evidence = packet.decision_evidence;
  const recognizedFailure = parsed.failures.length > 0
    || parsed.fatalErrors.length > 0
    || parsed.timeouts.length > 0
    || parsed.counts.failed > 0;
  const nonzero = evidence.process.exit_code !== null && evidence.process.exit_code !== 0;
  if (parsed.unclassified.length > 0) reasons.push('UNCLASSIFIED_EVIDENCE');
  if (parsed.malformedUtf8) reasons.push('MALFORMED_UTF8');
  if (parsed.contradictions.length > 0) reasons.push('AGGREGATE_CONTRADICTION');
  if (evidence.process.interrupted) reasons.push('INTERRUPTED_OUTPUT');
  if (evidence.process.exit_code === null) reasons.push('EXIT_STATUS_MISSING');
  if (nonzero && !recognizedFailure) reasons.push('NONZERO_EXIT_WITHOUT_RECOGNIZED_FAILURE');
  if (packet.operation_id === null) reasons.push('OPERATION_ID_MISSING');
  if (evidence.source.id === null) reasons.push('SOURCE_IDENTITY_MISSING');
  if (packet.receipt.raw_evidence.reference === null) reasons.push('RAW_EVIDENCE_REFERENCE_MISSING');
  for (const reason of evidence.reason_codes) {
    if (payloadReasonCodes.has(reason)) reasons.push(reason);
  }
  return sortedUnique(reasons);
}

function compareLocatorList(actual, expected, path, violations) {
  const actualLocators = actual.map((item) => locatorKey(item));
  const expectedLocators = expected.map((item) => locatorKey(item));
  if (!sameJson(actualLocators, expectedLocators)) {
    addMismatch(
      violations,
      'SOURCE_EVIDENCE_LOCATOR_MISMATCH',
      path,
      'source evidence locators do not match independent classification',
    );
  }
}

function verifySource(packet, schema, supplied, violations, claims) {
  const { streams, sourceInput } = supplied;
  const { evidence, receipt, entries } = schema;
  const digest = streamDigest(streams);
  if (digest !== receipt.input_hash) {
    addCryptoMismatch(
      violations,
      'INPUT_HASH_MISMATCH',
      '/receipt/input_hash',
      'does not match independently framed source bytes',
    );
    claims.input_hash = 'MISMATCH';
  } else claims.input_hash = 'VERIFIED';

  const expectedStreamReceipt = streams.map((stream) => ({
    byte_count: stream.bytes.length,
    name: stream.name,
  }));
  if (!sameJson(receipt.source.streams, expectedStreamReceipt)) {
    addMismatch(
      violations,
      'SOURCE_STREAM_RECEIPT_MISMATCH',
      '/receipt/source/streams',
      'stream names or byte counts do not match supplied source bytes',
    );
  }
  if (sourceInput) {
    const source = isPlainObject(sourceInput.source) ? sourceInput.source : {};
    const process = isPlainObject(sourceInput.process) ? sourceInput.process : {};
    const expectedMetadata = {
      operation_id: typeof sourceInput.operation_id === 'string' && sourceInput.operation_id.length > 0
        ? sourceInput.operation_id : null,
      protocol_version: sourceInput.protocol_version,
      source_id: typeof source.id === 'string' && source.id.length > 0 ? source.id : null,
      run_id: typeof source.run_id === 'string' && source.run_id.length > 0 ? source.run_id : null,
      raw_evidence_ref: typeof source.raw_evidence_ref === 'string' && source.raw_evidence_ref.length > 0
        ? source.raw_evidence_ref : null,
      exit_code: process.exit_code ?? null,
      duration_ms: process.duration_ms ?? null,
      interrupted: process.interrupted ?? false,
    };
    const packetMetadata = {
      operation_id: packet.operation_id,
      protocol_version: receipt.source.protocol_version,
      source_id: receipt.source.id,
      run_id: receipt.source.run_id,
      raw_evidence_ref: receipt.raw_evidence.reference,
      exit_code: evidence.process.exit_code,
      duration_ms: evidence.process.duration_ms,
      interrupted: evidence.process.interrupted,
    };
    if (!sameJson(expectedMetadata, packetMetadata)) {
      addMismatch(
        violations,
        'SOURCE_METADATA_MISMATCH',
        '/receipt/source',
        'packet provenance or process state does not match supplied source input',
      );
    }
  }

  const parsed = independentlyClassify(streams);
  const lineByLocator = new Map(parsed.lines.map((line) => [locatorKey(line), line]));
  let sourceLineMismatch = false;
  for (const { value, path } of entries) {
    const sourceLine = lineByLocator.get(locatorKey(value));
    if (!sourceLine
      || sourceLine.kind !== value.category
      || sha256(Buffer.from(sourceLine.text, 'utf8')) !== value.sha256
      || (Object.hasOwn(value, 'text') && sourceLine.text !== value.text)
      || (Object.hasOwn(value, 'byte_count')
        && Buffer.byteLength(sourceLine.text, 'utf8') !== value.byte_count)) {
      addCryptoMismatch(
        violations,
        'SOURCE_LINE_MISMATCH',
        path,
        'line locator, category, bytes, or digest does not match supplied source',
      );
      sourceLineMismatch = true;
    }
  }
  if (!sourceLineMismatch && entries.length > 0) claims.line_evidence_hashes = 'VERIFIED';

  if (!sameJson(evidence.counts, parsed.counts)) {
    addMismatch(
      violations,
      'SOURCE_AGGREGATE_MISMATCH',
      '/decision_evidence/counts',
      'counts do not match independent source classification',
    );
  }
  const expectedReasons = expectedSourceReasons(packet, parsed);
  if (!sameJson(evidence.reason_codes, expectedReasons)) {
    addMismatch(
      violations,
      'SOURCE_REASON_MISMATCH',
      '/decision_evidence/reason_codes',
      'reason codes do not match independent source classification',
    );
  }
  if (receipt.unclassified_evidence_present !== (parsed.unclassified.length > 0)) {
    addMismatch(
      violations,
      'SOURCE_UNCLASSIFIED_MISMATCH',
      '/receipt/unclassified_evidence_present',
      'unclassified flag does not match supplied source',
    );
  }
  if (receipt.measurements.original_event_count !== parsed.lines.length) {
    addMismatch(
      violations,
      'SOURCE_EVENT_COUNT_MISMATCH',
      '/receipt/measurements/original_event_count',
      'does not match independently parsed source events',
    );
  }

  if (evidence.failures.length !== parsed.failures.length
    || evidence.failures.some((failure, index) => failure.identity !== parsed.failures[index]?.identity)) {
    addMismatch(
      violations,
      'SOURCE_FAILURE_IDENTITY_MISMATCH',
      '/decision_evidence/failures',
      'failure identities do not match supplied source',
    );
  }
  const compact = evidence.reason_codes.includes('PAYLOAD_LIMIT_CRITICAL_EVIDENCE_EXCEEDED');
  if (!compact) {
    compareLocatorList(
      evidence.failures.flatMap((failure) => failure.header ? [failure.header, ...failure.details] : []),
      parsed.failures.flatMap((failure) => [failure.header, ...failure.details]),
      '/decision_evidence/failures',
      violations,
    );
    compareLocatorList(evidence.fatal_errors, parsed.fatalErrors, '/decision_evidence/fatal_errors', violations);
    compareLocatorList(evidence.timeouts, parsed.timeouts, '/decision_evidence/timeouts', violations);
  }
  compareLocatorList(evidence.warnings, parsed.warnings, '/decision_evidence/warnings', violations);
  compareLocatorList(
    evidence.unclassified_evidence,
    parsed.unclassified,
    '/decision_evidence/unclassified_evidence',
    violations,
  );

  const retainedLocators = new Set(entries
    .filter(({ value }) => Object.hasOwn(value, 'text'))
    .map(({ value }) => locatorKey(value)));
  const retainedLines = parsed.lines.filter((line) => retainedLocators.has(locatorKey(line)));
  const suppressedLines = parsed.lines.filter((line) => !retainedLocators.has(locatorKey(line)));
  if (receipt.retained.event_count !== retainedLines.length
    || receipt.suppressed.event_count !== suppressedLines.length
    || !sameJson(receipt.suppressed.categories, countCategories(suppressedLines))) {
    addMismatch(
      violations,
      'SOURCE_SUPPRESSION_ACCOUNTING_MISMATCH',
      '/receipt/suppressed',
      'retained/suppressed accounting does not match independent source classification',
    );
  }
  claims.source_accounting = violations.some((item) => [
    'SOURCE_AGGREGATE_MISMATCH',
    'SOURCE_REASON_MISMATCH',
    'SOURCE_UNCLASSIFIED_MISMATCH',
    'SOURCE_EVENT_COUNT_MISMATCH',
    'SOURCE_FAILURE_IDENTITY_MISMATCH',
    'SOURCE_EVIDENCE_LOCATOR_MISMATCH',
    'SOURCE_SUPPRESSION_ACCOUNTING_MISMATCH',
  ].includes(item.code)) ? 'MISMATCH' : 'VERIFIED';
}

function resultClassification(violations, sourceSupplied) {
  if (violations.some((item) => item.kind === 'STRUCTURE')) return 'STRUCTURALLY_INVALID';
  if (violations.some((item) => item.kind === 'CRYPTOGRAPHIC')) return 'CRYPTOGRAPHIC_MISMATCH';
  if (violations.some((item) => item.kind === 'CONSISTENCY')) return 'INTERNALLY_INCONSISTENT';
  return sourceSupplied ? 'VALID' : 'VALID_WITH_UNVERIFIED_SOURCE';
}

/**
 * Validate a Context Firewall packet-v1 object independently.
 *
 * `packetBytes` verifies the exact canonical output serialization.
 * `sourceInput` accepts the producer's public input envelope and verifies both
 * metadata and exact stream bytes. `sourceStreams` accepts only raw streams as
 * `{ name, bytes }` entries. Supply at most one source form.
 */
export function validateContextFirewallPacket(packet, options = {}) {
  const violations = [];
  const claims = {
    configuration_identity: 'NOT_EVALUATED',
    input_hash: 'NOT_SUPPLIED',
    line_evidence_hashes: 'NOT_EVALUATED',
    packet_serialization: options.packetBytes === undefined ? 'NOT_SUPPLIED' : 'NOT_EVALUATED',
    reduced_bytes: 'NOT_EVALUATED',
    semantic_payload_hash: 'NOT_EVALUATED',
    source_accounting: 'NOT_SUPPLIED',
  };
  const schema = validateSchema(packet, violations);
  let supplied = null;
  try {
    supplied = normalizeSuppliedStreams(options);
  } catch (error) {
    addViolation(
      violations,
      'STRUCTURE',
      'INVALID_SOURCE_MATERIAL',
      '/source_material',
      error.message,
    );
  }

  if (schema && !violations.some((item) => item.kind === 'STRUCTURE')) {
    validateConsistency(packet, schema, options.packetBytes, violations, claims);
    if (supplied) verifySource(packet, schema, supplied, violations, claims);
  }

  violations.sort((left, right) => (
    left.kind.localeCompare(right.kind)
    || left.path.localeCompare(right.path)
    || left.code.localeCompare(right.code)
    || left.message.localeCompare(right.message)
  ));
  const publicViolations = violations.map(({ key: _key, ...item }) => item);
  const classification = resultClassification(violations, Boolean(supplied));
  const valid = publicViolations.length === 0;
  const declared = schema?.evidence?.disposition ?? 'UNKNOWN';
  const sufficiency = !valid ? 'INVALID'
    : declared === 'NEEDS_RAW_EVIDENCE' ? 'NEEDS_RAW_EVIDENCE' : 'SUFFICIENT';
  const cryptographicVerification = violations.some((item) => item.kind === 'CRYPTOGRAPHIC')
    ? 'MISMATCH'
    : claims.input_hash === 'VERIFIED' && claims.packet_serialization === 'VERIFIED'
      ? 'VERIFIED' : 'PARTIAL';
  const rawReceipt = schema?.receipt?.raw_evidence;
  return {
    classification,
    cryptographic_verification: cryptographicVerification,
    evidence_sufficient: sufficiency === 'SUFFICIENT',
    protocol_version: packet?.protocol_version ?? null,
    raw_evidence: rawReceipt ? {
      destroyed_by_reducer: rawReceipt.destroyed_by_reducer,
      locator_verification: rawReceipt.reference === null
        ? 'NOT_SUPPLIED' : 'CALLER_CLAIM_ONLY',
      source_evidence_disposition: rawReceipt.source_evidence_disposition,
      suppressed_from_model_context: rawReceipt.suppressed_from_model_context,
    } : null,
    raw_evidence_required: sufficiency === 'NEEDS_RAW_EVIDENCE',
    structural_valid: !violations.some((item) => item.kind === 'STRUCTURE'),
    internally_consistent: publicViolations.length === 0,
    sufficiency,
    valid,
    verification: claims,
    violations: publicViolations,
  };
}
