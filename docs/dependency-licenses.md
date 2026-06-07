# Dependency license policy

Kraken UI is licensed under MIT. Direct application dependencies are
selected with an MIT or BSD license option.

The mandatory stack introduces additional licenses through transitive
dependencies:

- Ammonia uses MPL-2.0 components such as `cssparser`.
- Rustls and its cryptographic providers use Apache-2.0 and ISC components.
- SeaORM/SQLx URL and TLS support use Unicode-3.0, Zlib and
  CDLA-Permissive-2.0 components.

These licenses are explicitly listed in `deny.toml`; unknown registries, Git
dependencies, wildcard versions, yanked crates and security advisories remain
blocked. Removing these exceptions would require replacing at least one
mandatory framework or security library.
