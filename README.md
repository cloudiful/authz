# cloudiful-authz

`cloudiful-authz` is a small, domain-neutral Rust authorization library for
trusted applications. It answers one question: may this already-authenticated
principal perform this exact action on this resource in this domain?

The library uses Casbin as the decision engine with domain-role semantics. It is
not an authentication service, token issuer, session store, identity provider,
database, or policy administration UI.

## Decision contract

- `Authorizer::authorize(&AuthzRequest, Authority<'_>)` is the single decision
  entry point. A request carries only the operation and context: resource,
  action, receiving audience, optional credential, and optional server.
- Subject identity, domain, and current roles come from `Authority`.
  `Authority::Snapshot { subject, domain, facts_revision }` evaluates the
  immutable assignment snapshot and denies a differing revision.
  `Authority::Registered(&ResolvedRoles)` evaluates trusted current roles in a
  domain that must already be registered. `Authority::Resolved(&ResolvedRoles)`
  evaluates the same facts for a syntactically valid unregistered domain on the
  caller's proof that it currently exists.
- `ResolvedRoles` binds the full principal and exact domain to its roles. Live
  authority never falls back to or unions snapshot assignments, and it has no
  assignment revision.
- Principal identity is the pair of kind and id; principal and role identifiers
  are separate namespaces.
- Roles are explicit registered capability sets, not an ordered enum.
- Role assignments are domain-scoped. Optional domain hierarchy is expanded
  downward into effective Casbin assignments.
- Credential and server attenuation are typed grants over domain, resource
  kind, optional exact resource id, and action. Unrestricted and an empty grant
  set are different.
- Public-read is a trusted snapshot access mode with exact grants; it still
  applies credential and server attenuation.
- Registered resource/action names come only from role capabilities and
  public-read grants; credential or server grants cannot register names.
- The resource domain must equal the authority domain. Unknown domains deny
  snapshot and registered live decisions; resources, actions, stale facts, and
  engine errors deny. Malformed service audiences and credential audience
  mismatches deny.
- Row-level SQL visibility, leases, approvals, quotas, and IP rules remain
  application responsibilities.

An `Authorizer` is an immutable snapshot with a facts revision. The core rejects
a snapshot request whose revision differs from the snapshot. The calling
application owns freshness: it must supply a revision from authoritative current
data, refresh at membership or admin changes, and keep live per-request checks
where a snapshot cannot meet its consistency requirements. Revision comparison
alone does not make a dynamic membership adapter current.

For live-fact consumers, `Authority::Registered` and `Authority::Resolved` carry
caller-resolved `ResolvedRoles` bound to the full principal and exact domain.
They evaluate the roles through the same Casbin capabilities without mutating or
rebuilding the engine, never fall back to snapshot assignments, and leave
credential and server attenuation mandatory. The caller owns live freshness; the
core adds no revision database or invalidation service. Use `Resolved` only when
the caller has authoritatively established that the target domain currently
exists and the supplied roles are its current effective roles.

## Usage

```rust
use cloudiful_authz::{
    Action, Authority, Authorizer, AuthorizerConfig, AuthzRequest, Capability, FactsRevision,
    PrincipalRef, ResolvedRoles, ResourceKind, ResourceRef, RoleId, RoleSpec, ServiceId, Subject,
};

async fn example() -> Result<(), Box<dyn std::error::Error>> {
    let principal = PrincipalRef::human("42");
    let mut config = AuthorizerConfig::new(
        FactsRevision(1),
        ["docs"],
        [RoleSpec {
            id: RoleId::from("viewer"),
            capabilities: [Capability::new("page", "read")].into(),
        }],
    );
    config.assignments.push(cloudiful_authz::RoleAssignment {
        principal: principal.clone(),
        role: RoleId::from("viewer"),
        domain: "docs".into(),
    });
    let authorizer = Authorizer::new(config).await?;

    let request = AuthzRequest {
        resource: ResourceRef {
            kind: ResourceKind::from("page"),
            id: None,
            domain: "docs".into(),
        },
        action: Action::from("read"),
        audience: ServiceId::from("docs-service"),
        credential: None,
        server: None,
    };

    let snapshot = Authority::Snapshot {
        subject: Subject::Principal(principal.clone()),
        domain: "docs".into(),
        facts_revision: FactsRevision(1),
    };
    assert!(authorizer.authorize(&request, snapshot).is_allowed());

    let current = ResolvedRoles::new(principal, "docs", ["viewer"]);
    assert!(
        authorizer
            .authorize(&request, Authority::Registered(&current))
            .is_allowed()
    );
    Ok(())
}
```

A dynamic group domain needs no registration, only a trusted current lookup:

```rust
let facts = ResolvedRoles::new(PrincipalRef::human("42"), "group:alpha", ["viewer"]);
let request = AuthzRequest {
    resource: ResourceRef {
        kind: ResourceKind::from("page"),
        id: None,
        domain: "group:alpha".into(),
    },
    action: Action::from("read"),
    audience: ServiceId::from("docs-service"),
    credential: None,
    server: None,
};
assert!(
    authorizer
        .authorize(&request, Authority::Resolved(&facts))
        .is_allowed()
);
```

Runnable examples are in [`examples/`](examples): a minimal service principal,
a domain member inheriting a parent assignment, a live-resolved-role decision
that changes on the next request without rebuilding the engine, and a
fresh-dynamic-domain decision using one engine.

## Documentation

- [`docs/authorization-model.md`](docs/authorization-model.md): contract,
  invariants, Casbin model, freshness, and API.
- [`docs/consumer-mapping.md`](docs/consumer-mapping.md): verified consumer
  behavior, compatibility mapping, migration order, and unresolved choices.

## Development

```sh
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo test --locked
cargo clippy --all-targets --locked
cargo doc --no-deps --locked
```
