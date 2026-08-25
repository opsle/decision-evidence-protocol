# Decision Evidence Protocol

> Experimental Opsle research. Claims are hypotheses until evidence supports them.

## Problem

Agents repeatedly parse provider-specific prose and tool chatter to recover the same small set of decision facts.

## Hypothesis

A small structured envelope can improve interoperability and reduce context while preserving escalation to raw evidence.

## Mechanism

Emit status, exit state, changed entities, warnings/errors, test counts,
repository revisions, duration, verification, uncertainty, provenance,
artifacts, and an explicit raw-output escalation reason only when applicable.

The reference implementation also independently validates Context Firewall
`opsle.context-firewall.evidence-packet/v1` packets. It does not import or call
Context Firewall. With source bytes, it recomputes hashes, reclassifies the
documented TAP subset, verifies retained line locators, and derives suppression
accounting independently.

## Why it matters

The Opsle thesis asks: **What if we stopped using intelligence for work that doesn’t require intelligence?** This project isolates one candidate boundary so it can be falsified and measured independently.

## Non-goals

A universal event schema, embedding raw logs by default, or expanding fields without demonstrated decision value.

## Public API

```js
import {
  createValidationValueReceipt,
  validateContextFirewallPacket,
  validateContextFirewallValueReceipt,
  validateValueReceipt,
} from '@opsle/decision-evidence-protocol';

const result = validateContextFirewallPacket(
  packet,
  {
    packetBytes,
    sourceInput,
  },
);

const producerReceiptResult = validateContextFirewallValueReceipt(
  contextFirewallValueReceipt,
  packet,
);

const validationReceipt = createValidationValueReceipt(
  packet,
  result,
  { mechanismRevision },
);
```

`sourceInput` is optional and uses Context Firewall's public input shape. A
caller that has only stream bytes can instead supply `sourceStreams` as
`{ name, bytes }` entries. Supplying neither validates the receipt internally
and returns `VALID_WITH_UNVERIFIED_SOURCE`; it never reports the input hash as
independently verified.

The structured result includes:

- `classification`: `VALID`, `VALID_WITH_UNVERIFIED_SOURCE`,
  `STRUCTURALLY_INVALID`, `INTERNALLY_INCONSISTENT`, or
  `CRYPTOGRAPHIC_MISMATCH`;
- `sufficiency`: `SUFFICIENT`, `NEEDS_RAW_EVIDENCE`, or `INVALID`;
- `verification`: per-claim states for configuration, source, semantic payload,
  retained line hashes, canonical packet bytes, measurements, and accounting;
- `raw_evidence`: suppression, preservation, destruction, and caller-locator
  claim state, with locator verification explicitly `CALLER_CLAIM_ONLY`; and
- `violations`: stable path-specific failure objects.

`NEEDS_RAW_EVIDENCE` is valid protocol output but
`evidence_sufficient` is always false.

## CLI

Validate canonical packet bytes from stdin:

```bash
node ./bin/decision-evidence.js \
  validate-context-firewall
```

Validate a packet and its source input:

```bash
node ./bin/decision-evidence.js \
  validate-context-firewall \
  --packet packet.json \
  --source-input source.json
```

Output is canonical machine-readable JSON. Exit code 0 means a valid receipt,
including valid-but-insufficient escalation receipts; callers must inspect
`sufficiency`. Exit code 1 means validation failure. Invocation or JSON errors
use exit code 2.

Successful validation also emits one stable named operator line on stderr, for
example:

```text
[Decision Evidence] source-backed packet verified | SUFFICIENT | 7 claims checked
```

Canonical stdout remains byte-identical whether or not a full validation receipt
is requested:

```bash
node ./bin/decision-evidence.js \
  validate-context-firewall \
  --packet packet.json \
  --source-input source.json \
  --mechanism-revision REVISION \
  --value-receipt value-receipt.json
```

The producer's separate Context Firewall receipt can be cross-checked against
the packet with `validate-context-firewall-value --receipt ... --packet ...`.
Neither full receipt nor stderr should be merged automatically into compact
decision-relevant model context.

The Visible Value receipt reports performed checks, trust, sufficiency,
rejections, and escalation. It does not claim token/cost/latency savings,
preserved model correctness, or a failure prevented.

## Verification

```bash
npm run lint
npm test
npm run conformance
npm run determinism
```

The self-contained conformance corpus contains 24 public-safe vectors: 9 valid
producer packets and 15 intentional structural, consistency, boundary, and
cryptographic failures. See
[the packet-v1 profile](docs/context-firewall-packet-v1.md).

The separately run cross-repository compatibility proof is:

```bash
node \
  tools/verify-context-firewall-interop.js \
  ../context-firewall
```

It requires the exact documented read-only Context Firewall revision and does
not create a runtime or CI dependency on that repository.

## Current maturity

The authoritative lifecycle stage is recorded by
[Opsle Research](https://github.com/opsle/research). The packet-v1 validator,
automated failure tests, conformance vectors, and exact-revision interoperability
proof establish a narrow verification claim. They do not establish comparative
benefit, benchmark readiness, or model correctness.

## Existing evidence

The generic envelope validator remains available. Context Firewall packet-v1
interoperability is now executable and deterministic at the revisions recorded
in the authoritative Opsle registry.

## Evidence still missing

Other tool classes, independent implementations beyond Context Firewall,
measured decision adequacy, comparative benchmarks, and replication remain
missing.

## Benchmark strategy

Correctness gates every comparison. Planned measures:

- correctness
- envelope bytes
- raw escalations
- adapter coverage
- parse failures
- decision latency

See [BENCHMARK.md](BENCHMARK.md) for experiment rules. No benchmark numbers are claimed.

## Relationship to other Opsle research

This project is part of [Opsle Research](https://github.com/opsle/research). Opsle Tasks is the future public name of the integrated reference system from which several ideas emerged. Its active development migration to the Opsle organization is intentionally deferred.

## Relationship to future Opsle Tasks

Future Opsle Tasks may consume this project through an adapter only after evidence supports integration. The active predecessor, Taslos Tasks, remains unchanged and has no dependency on this repository.

## Installation status

A small dependency-free reference prototype is included for falsification and interface feedback. It is not production-ready.

## Known limitations

- A syntactically valid source hash is not independently verified without
  supplied source bytes.
- `raw_evidence.reference` is caller-owned. Validation proves only whether a
  nonempty reference was declared, not whether its target exists, is immutable,
  is available, or contains the claimed bytes.
- Packet v1 hashes canonical `decision_evidence`; it has no self-referential
  whole-packet hash. The validator instead checks exact canonical packet bytes
  when supplied and always checks the fixed-point `reduced_bytes` measurement.
- The strict TAP-subset classifier is not arbitrary TAP or general log support.
- A valid receipt does not prove that a model will make a correct decision from
  reduced evidence. That remains the planned EXP-001 question, and no model or
  provider experiment is run here.

## License

Apache-2.0. See [LICENSE](LICENSE).
