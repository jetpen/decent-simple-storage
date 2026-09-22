# Decentralized Simple Storage

Decentralized Simple Storage is an object storage provider that works
in combination with [Decentralized
Registry](https://github.com/jetpen/decent-registry) and
[Decentralized Identity](https://github.com/jetpen/decent-identity) in
the [Decentralized
Ecosystem](https://github.com/jetpen/decent-ecosystem).

The proposed design uses operator-approved quotas, allowlisted content
types, scoped capabilities for object operations, and SHA-256-based
Provider Records for discovery; object content itself stays outside
the Registry/DHT.

The GitHub issues describe a specification and implementation target,
not functionality verified as implemented in this
repository. Enrollment and quotas, capability enforcement, object
lifecycle and abuse controls, Provider Record behavior, and
account-entity onboarding remain open design work.
