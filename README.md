# Decision Evidence Protocol

> Experimental Opsle research. Claims are hypotheses until evidence supports them.

## Problem

Agents repeatedly parse provider-specific prose and tool chatter to recover the same small set of decision facts.

## Hypothesis

A small structured envelope can improve interoperability and reduce context while preserving escalation to raw evidence.

## Mechanism

Emit status, exit state, changed entities, warnings/errors, test counts, repository revisions, duration, verification, uncertainty, provenance, artifacts, and an explicit raw-output escalation reason only when applicable.

## Why it matters

The Opsle thesis asks: **What if we stopped using intelligence for work that doesn’t require intelligence?** This project isolates one candidate boundary so it can be falsified and measured independently.

## Non-goals

A universal event schema, embedding raw logs by default, or expanding fields without demonstrated decision value.

## Current maturity

**PROTOTYPE** under the [Opsle maturity model](https://github.com/opsle/research/blob/main/MATURITY.md).

## Existing evidence

Structured provider results and operational metrics show feasibility inside one system. Cross-tool adequacy is unverified.

## Evidence still missing

Adapter trials across test, Git, build, lint, typecheck, shell, and deployment tools; versioning and conformance rules.

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

Adapter trials across test, Git, build, lint, typecheck, shell, and deployment tools; versioning and conformance rules.

## License

Apache-2.0. See [LICENSE](LICENSE).
