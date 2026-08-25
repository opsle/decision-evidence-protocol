# Theory

## Observation

Agents repeatedly parse provider-specific prose and tool chatter to recover the same small set of decision facts.

## Hypothesis

A small structured envelope can improve interoperability and reduce context while preserving escalation to raw evidence.

## Proposed mechanism

Emit status, exit state, changed entities, warnings/errors, test counts, repository revisions, duration, verification, uncertainty, provenance, artifacts, and an explicit raw-output escalation reason only when applicable.

## Falsifiable requirements

1. The protocol remains vendor neutral.
2. Unknown or unavailable evidence is explicit.
3. Raw output is referenced, not embedded by default.
4. Protocol growth requires measured decision value.

## Disconfirming results

The hypothesis should be weakened or rejected if a comparable baseline passes the same correctness gate and this mechanism provides no repeatable benefit, or if the mechanism introduces safety/correctness failures that bounded revisions do not resolve. Negative results remain in `experiments/`.

## Uncertainty

Adapter trials across test, Git, build, lint, typecheck, shell, and deployment tools; versioning and conformance rules.
