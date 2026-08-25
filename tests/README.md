# Test strategy

Tests map to named invariants in `SPEC.md` and the Context Firewall packet-v1
profile. They include adversarial structural, internal-consistency,
cryptographic, provenance, sufficiency, deterministic-output, malformed-input,
and numeric boundary cases.

Passing tests establish validator behavior at one exact revision. They do not
establish model correctness or comparative context-reduction benefit.
