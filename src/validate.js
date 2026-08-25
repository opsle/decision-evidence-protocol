const statuses = new Set(['passed','failed','partial','indeterminate']);
export function validateEnvelope(value) {
  const errors=[]; if (!value || typeof value !== 'object') return { ok:false, errors:['object required'] };
  if (!statuses.has(value.status)) errors.push('invalid status');
  if (!value.provenance || typeof value.provenance.source !== 'string') errors.push('provenance.source required');
  if ('raw_output' in value && !value.raw_output_escalation_reason) errors.push('raw output requires escalation reason');
  if (value.passed_count != null && (!Number.isInteger(value.passed_count) || value.passed_count < 0)) errors.push('passed_count invalid');
  return { ok: errors.length === 0, errors };
}
