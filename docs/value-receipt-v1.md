# Value receipt v1 profile

Decision Evidence accepts only `opsle.value-receipt.v1` and enforces the
program-owned Visible Value semantics without importing another repository.

The generic validator checks required identities, units, measurement classes,
finite values, one delta sign convention, evidence references, source trust,
inspectable estimation/model assumptions, controlled experiment identity, safe
aggregation, and counterfactual claim misuse.

The Context Firewall profile additionally requires exactly raw/visible/avoided
bytes, an exact non-summable ratio, original/retained/suppressed/ambiguous event
counts, payload ceiling, escalation, and raw-locator state. Every value is
cross-checked against the packet. A structurally valid generic receipt with a
wrong raw-byte value is invalid for this profile.

Packet validation emits its own sibling receipt with observed validation state
and exact evaluated-claim count. It reports tamper or inconsistency detection,
not failure prevention. Full receipts use API return values or a caller-requested
sidecar; canonical decision JSON remains on stdout and one named operator line
remains on stderr.
