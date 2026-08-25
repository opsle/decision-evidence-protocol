# Reference surface

This directory contains dependency-free, deliberately narrow validators.

- `validate.js` preserves the original generic envelope prototype.
- `context-firewall-v1.js` independently validates Context Firewall packet-v1
  receipts, hashes, source evidence, accounting, and escalation state.
- `conformance.js` runs the checked-in protocol vector corpus.

The implementation supports falsification and interoperability. It is not a
production authorization or containment boundary.
