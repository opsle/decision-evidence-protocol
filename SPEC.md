# Specification

Status: experimental prototype contract.

Versioned Context Firewall profile:
`opsle.decision-evidence.context-firewall-validation/v1`.

## Compatibility boundary

The primitive accepts generic structured input and emits generic structured output. It must not require a Taslos Tasks database, worker, scheduler, package, runtime path, or private service.

## Inputs

- `protocol_version`: explicit version.
- `operation_id`: stable idempotency identity.
- `policy_revision`: the exact policy/configuration revision.
- `subject`: vendor-neutral request data required by this concept.
- `evidence`: observable artifacts with provenance.

## Outputs

- `status`: accepted, rejected, deferred, or indeterminate.
- `reason`: durable structured reason.
- `changed_entities`: bounded identities, never ambient state.
- `evidence`: provenance-linked receipts.
- `uncertainty`: explicit unknowns.

## Invariants

- The protocol remains vendor neutral.
- Unknown or unavailable evidence is explicit.
- Raw output is referenced, not embedded by default.
- Protocol growth requires measured decision value.

The Context Firewall packet-v1 validation profile additionally enforces the
normative invariants in
[`docs/context-firewall-packet-v1.md`](docs/context-firewall-packet-v1.md).

## Visible Value validation

Version 0.3.0 validates `opsle.value-receipt.v1` structure and measurement-class
semantics. The Context Firewall value profile independently cross-checks the 11
producer measurements against the packet rather than trusting their labels.
Byte evidence cannot become a token, cost, latency, correctness, or
failure-prevention claim. `ESTIMATED` and `MODELED` values require inspectable
assumptions; `EXPERIMENTAL` requires controlled comparability evidence; modeled,
experimental, ratio, percent, boolean, and state values are not directly summed.

Packet validation may produce a sibling Decision Evidence value receipt. It
records validation, classification, evaluated verification claims, source-backed
and hash verification, sufficiency, tamper/inconsistency detection, and raw
escalation. A rejection is directly observed; the receipt never claims a failure
was prevented.

Canonical validation JSON remains on stdout. One named `[Decision Evidence]`
indicator is written to stderr, and the full receipt is written only to a
caller-requested deterministic sidecar.

## Failure behavior

Missing required authority or evidence fails closed. Unsupported optional data remains explicit and does not silently widen behavior. Implementations must document idempotency, crash consistency, and raw-evidence escalation.

## Versioning

Breaking semantic changes require a new protocol version. New optional fields require evidence that they affect a real decision.

The Context Firewall profile supports only evidence packet v1, receipt version
1, test-run input v1, reducer 0.3.0, and TAP-subset policy v1. Unsupported
versions are rejected explicitly; they are not interpreted as compatible.
