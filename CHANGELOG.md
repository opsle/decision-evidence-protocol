# Changelog

## 0.3.0 - 2026-08-25

- Added dependency-free `opsle.value-receipt.v1` validation and strict Context
  Firewall receipt cross-checking at producer revision
  `953c48f1cfd154d6b7ed10b51b87fe54e4df45f2`.
- Added sibling validation receipts, deterministic sidecars, and named
  `[Decision Evidence]` stderr indicators without changing canonical stdout.
- Added exact/observed class, trust, aggregation, counterfactual, tamper,
  inconsistency, source-verification, and invalid-state coverage.
- This is conformance evidence, not EXP-001, causal benefit, or proof that a
  failure was prevented.

## 0.2.0 - 2026-08-25

- Added an independent Context Firewall packet-v1 validator and stable API.
- Added machine-readable receipt-only and source-backed CLI validation.
- Added 24 public-safe conformance vectors with tamper, accounting, escalation,
  version, hash, provenance, and numeric boundary failures.
- Added exact-revision cross-repository interoperability verification without a
  runtime dependency.
- Documented structural versus cryptographic verification, source suppression,
  raw-evidence limitations, and the EXP-001 boundary.

## 0.1.0 - 2026-08-25

- Published initial theory, falsifiable specification, benchmark plan, architecture, and provenance.
- Marked maturity PROTOTYPE.
- Added no benchmark claims.
