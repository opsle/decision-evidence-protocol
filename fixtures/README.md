# Conformance fixtures

`context-firewall-packet-v1/vectors.json` is a public-safe, protocol-owned corpus
generated from the exact Context Firewall revision recorded in the file.

The 9 valid vectors cover successful reduction, failed and multi-failure tests,
large success suppression, a caller raw reference, ordinary and ambiguous raw
escalation, ceiling-triggered critical omission, and an exact payload boundary.

The 15 invalid vectors cover missing fields, unsupported versions, malformed and
wrong hashes, tampered source bytes, impossible bytes and event counts,
contradictory suppression, invalid escalation, negative and overflow-like
measurements, malformed raw locators, false sufficiency, and wrong canonical
output measurement.

Normal CI never imports Context Firewall. Maintainers can refresh vectors only
from the pinned read-only producer revision:

```bash
node \
  tools/generate-context-firewall-vectors.js \
  --context-firewall ../context-firewall
```

Review generator and vector diffs before accepting a producer revision change.
