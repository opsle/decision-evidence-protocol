# Context Firewall evidence packet v1 validation profile

Status: normative experimental conformance profile.

Profile version:
`opsle.decision-evidence.context-firewall-validation/v1`.

Producer contract:
`opsle.context-firewall.evidence-packet/v1` at Context Firewall revision
`dd34bd9f681314761f1ca87f339648bf611811f3`.

## What a validated receipt establishes

Receipt-only validation establishes that the packet uses the supported version,
has the required typed fields, is internally consistent, has valid hash syntax,
has a correct canonical configuration identity and semantic-payload hash, has
correct retained/suppressed arithmetic, has a fixed-point canonical output byte
measurement, and cannot present encoded escalation state as sufficient evidence.

When exact source bytes are supplied, validation additionally establishes that:

1. the framed stdout/stderr SHA-256 input identity matches;
2. per-stream and total byte counts match;
3. every retained or hash-addressed source locator resolves to the supplied
   line, category, byte count, and digest;
4. the strict TAP-subset classification, aggregate counts, failure identities,
   ambiguity state, and reason codes match an independent implementation; and
5. retained and suppressed source event counts and suppression categories match
   independent classification.

When the original packet bytes are supplied, validation also proves that the
bytes are the producer's canonical lexical-key JSON with exactly one final
newline.

## What it does not establish

A receipt-only result cannot prove the input hash or source-derived
classification. It returns `VALID_WITH_UNVERIFIED_SOURCE`, and the input-hash and
source-accounting claim states remain `NOT_SUPPLIED`.

The raw-evidence locator is caller-owned. `CALLER_REFERENCE_SUPPLIED` means only
that the producer received a nonempty string. It does not establish existence,
availability, immutability, access authorization, retention duration, or byte
identity of an external artifact. `PRESERVATION_UNCONFIRMED` means no locator was
supplied. Neither state says the reducer destroyed evidence; packet v1 requires
`destroyed_by_reducer: false`.

Packet v1 contains a SHA-256 identity for canonical `decision_evidence`, not for
the entire packet. A whole-packet hash would be self-referential. The validator
checks canonical packet bytes directly when supplied and checks the canonical
fixed-point `reduced_bytes` measurement in every validation.

Most importantly, receipt validation does not prove that reduced evidence is
adequate for a model to make a correct decision. That is a comparative EXP-001
question requiring frozen tasks, a correctness oracle, model/provider
configuration, experimental arms, and measured runs. None are part of this
profile.

## Structural and identity invariants

The validator rejects unsupported or malformed values rather than applying
loose compatibility:

- packet protocol is exactly evidence packet v1;
- receipt version is exactly 1;
- source protocol is exactly test-run input v1;
- reducer identity is exactly
  `@opsle/context-firewall/test-output` version `0.2.0`;
- policy revision is exactly `tap-subset-policy/v1`;
- source, run, operation, and raw-reference identities are either nonempty
  strings or `null`, according to packet v1;
- streams are one or two unique `stdout`/`stderr` entries in canonical order;
- SHA-256 claims are lowercase `sha256:` plus 64 hexadecimal characters;
- counts and byte measurements are nonnegative JavaScript safe integers;
- payload ceilings are positive safe integers or `null`; and
- line locators use declared streams and positive safe integer line numbers.

No URL scheme is imposed on `raw_evidence.reference`; Context Firewall accepts
any nonempty caller-owned locator string. Empty or non-string values are
malformed.

## Cryptographic and canonical invariants

The validator always independently recomputes:

- configuration identity from canonical ceiling, policy, and reducer version;
- semantic payload identity from canonical `decision_evidence`;
- each retained line digest when its text is present; and
- canonical packet length, including its final newline.

With source bytes, it also recomputes input framing and SHA-256, plus line
digests and byte counts for hash-only line references. Without those bytes,
input and hash-only source claims are explicitly partial or not supplied.

## Evidence and suppression accounting invariants

The validator enforces:

- `retained_evidence_count == retained.event_count`;
- `suppressed_evidence_count == suppressed.event_count`;
- retained plus suppressed equals `original_event_count`;
- suppression category counts sum to `suppressed.event_count`;
- retained event count equals the number of model-visible source-line texts;
- retained categories equal the four derived categories plus the unique
  categories of retained source-line texts;
- suppressed-from-context is true exactly when suppressed event count is
  nonzero;
- stream byte counts sum to `original_bytes`; and
- with source supplied, all event totals and categories match independent
  source classification.

No equation equates test counts with source event counts. Structural lines,
aggregate source lines, notes, blanks, and unclassified events are source events
but are not tests. A test-count sum mismatch is permitted only when
`AGGREGATE_CONTRADICTION` explicitly makes the receipt insufficient.

Hash-only warning or unclassified locators remain model-visible references, but
the underlying source events count as suppressed because their text is not
visible. This matches packet-v1 accounting rather than inventing a second event.

## Measurement and payload invariants

- `reduced_bytes` equals canonical packet bytes including the final newline.
- Declared ceiling and requested ceiling are identical.
- A non-null honored ceiling cannot be smaller than `reduced_bytes`.
- Payload-affected state has exactly one applicable payload reason.
- Reference mode explicitly declares omitted noncritical text.
- Compact mode explicitly declares critical evidence exceeded, retains failure
  identities, retains no source-line text, and is always insufficient.
- Negative, non-finite, fractional, unsafe-integer, and contradictory numeric
  records are rejected.

The validator does not require reduced bytes to be smaller than original bytes.
Small valid receipts can expand because provenance has fixed cost.

## Sufficiency and escalation

`SUFFICIENT` is valid only when `reason_codes` is empty,
`escalation_required` is false, and `reduction_complete` is true.

Any uncertainty or omission reason requires all of:

- disposition `NEEDS_RAW_EVIDENCE`;
- `evidence_sufficient: false`;
- `raw_evidence_required: true`;
- `escalation_required: true`; and
- `reduction_complete: false`.

This covers ambiguous/unclassified evidence, malformed UTF-8, aggregate
contradiction, interrupted or missing process state, missing provenance,
unexplained nonzero exit, missing raw reference, noncritical text omission, and
critical evidence exceeding the ceiling.

Suppressed evidence with a caller reference is retrievable only as a caller
claim. Suppressed evidence without a reference is preservation-unconfirmed.
Retained evidence is model-visible. Critical omitted evidence requires raw
escalation. These states are not interchangeable.

## Conformance and interoperability

Run self-contained tests and vectors:

```bash
npm test
npm run conformance
```

Run the separate exact-revision producer proof:

```bash
node \
  tools/verify-context-firewall-interop.js \
  ../context-firewall
```

Normal CI uses only checked-in protocol vectors. The interoperability command
loads the read-only sibling checkout to generate current packets for normal
success, failure, suppression-heavy, and raw-escalation cases, then rejects a
tampered copy. It is deterministic and launches no model or provider workload.
