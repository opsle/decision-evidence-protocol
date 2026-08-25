# Architecture

```text
generic input → Decision Evidence Protocol → generic output
```

```text
packet-v1 ────────────────┐
                         ├→ independent validator → structured result
optional source bytes ───┘
```

## Ports

- Input adapter: translates a host’s observable state into the generic contract.
- Core: deterministic policy/mechanism under test.
- Evidence store: immutable or append-only artifacts where required.
- Output adapter: returns a bounded receipt to the host.

## Independence

Host-specific adapters are optional and removable. Disabling the project should return the host to its prior behavior. No core module may import Taslos Tasks internals.

The Context Firewall profile is a separately implemented classifier and receipt
auditor. Repository-local tests consume checked-in vectors. The optional
cross-repository proof dynamically imports an exact read-only producer checkout
only from a development tool, never from the package runtime or normal CI.
