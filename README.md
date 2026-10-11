# lattivant-platform

The shared foundation of [Lattivant](https://github.com/karkat983), an evidence-first security
platform. Every engine — the AuthZ Fuzzer, AgentTrace, EastWest — speaks the same event
language and writes through the same ingestion, storage and access-control primitives defined
here, so findings from different sources can be normalized, stored and correlated as one body
of evidence.

This repository is pure Rust, no I/O beyond the filesystem evidence store, and has no
engine-specific logic. It is the contract the engines depend on.

## Crates

| Crate | What it provides |
|-------|------------------|
| [`lattivant-event`](crates/lattivant-event) | The canonical event envelope: a single, versioned shape every engine emits. Separates **event time** from **ingestion time**, **observed** facts from **inferred** conclusions, and always names a **tenant** and a **provenance**. Pure data plus validation, canonical JSON, and content fingerprints. |
| [`lattivant-tenancy`](crates/lattivant-tenancy) | Tenant isolation and role-based access control. A `TenantContext` carries who is asking, for which tenant, in what role; every access checks both the role's permission and tenant ownership before a query runs — defence in depth alongside database row-level security. |
| [`lattivant-evidence`](crates/lattivant-evidence) | Content-addressed, tenant-scoped evidence storage. A blob's id *is* the SHA-256 of its content, so storage can `verify` that a blob still matches its reference. In-memory and filesystem backends. |
| [`lattivant-ingest`](crates/lattivant-ingest) | The front door for events: parse → size check → validate → dedup, routing each input to **accepted**, **duplicate** (idempotent by id or content fingerprint) or **quarantined** (never silently dropped). Queries are always tenant-scoped. |

## Design principles

These hold across every crate and every engine built on top:

- **Evidence over inference.** The envelope keeps a producer's *conclusion* ("this was an
  attack") strictly apart from a raw *observation* ("this response had status 200"), so a
  correlator never treats the two with equal weight. A finding is only as strong as the
  evidence retrievable behind it.
- **Tenant isolation is not optional.** Every stored record names a tenant; every read names a
  tenant; a cross-tenant access returns nothing or an error, before any work is done.
- **Idempotent, lossless ingestion.** Producers retry and replay. Ingestion deduplicates on
  the producer's id and on a content fingerprint, and quarantines — never drops — anything it
  cannot accept, so no signal is lost to a bad producer or a schema bug.
- **Content addressing for integrity.** Evidence is stored by the hash of its bytes, so a
  reference doubles as a tamper-evidence proof.
- **No secrets in records.** Identities and events carry non-secret identifiers only, never
  credentials.

## Building

```sh
cargo test          # all crates
cargo clippy --all-targets
```

Requires a recent stable Rust toolchain (edition 2021, rustc ≥ 1.80).

## License

MIT. See [LICENSE](LICENSE).
