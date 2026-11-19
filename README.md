# cloudiful-authz

`cloudiful-authz` is a small, domain-neutral Rust authorization library for
trusted applications. It answers one question: may this already-authenticated
principal perform this exact action on this resource in this domain?

The library uses Casbin as the decision engine with domain-role semantics. It is
not an authentication service, token issuer, session store, identity provider,
database, or policy administration UI.

## Decision contract

- Principal identity is the pair of kind and id; principal and role identifiers
  are separate namespaces.
- Roles are explicit registered capability sets, not an ordered enum.
- Role assignments are domain-scoped. Optional domain hierarchy is expanded
  downward into effective Casbin assignments.
- Credential and server attenuation are typed grants over domain, resource
  kind, optional exact resource id, and action. Unrestricted and an empty grant
  set are different.
- Public-read is a trusted access mode with exact grants; it still applies
  credential and server attenuation.
- Registered resource/action names come only from role capabilities and
  public-read grants; credential or server grants cannot register names.
- `Authorizer::authorize_with_roles` accepts trusted per-request roles resolved
  from current introspection or SQL, without rebuilding the engine or reading
  stale assignment snapshots. It binds those roles to the full principal and
  exact request domain and still applies audience, credential, and server
  restrictions.
- `Authorizer::authorize_with_resolved_domain` additionally admits a
  syntactically valid domain that is not registered in the authorizer. The
  caller must have established that the domain currently exists and must
  supply its effective roles; syntactic validity alone grants nothing.
- Unknown domains deny snapshot and registered live decisions; resources,
  actions, stale facts, and engine errors deny. Malformed service audiences and
  credential audience mismatches deny.
- Row-level SQL visibility, leases, approvals, quotas, and IP rules remain
  application responsibilities.

An `Authorizer` is an immutable snapshot with a facts revision. The core rejects
a request whose revision differs from the snapshot. The calling application
owns freshness: it must supply a revision from authoritative current data,
refresh at membership or admin changes, and keep live per-request checks where
a snapshot cannot meet its consistency requirements. Revision comparison alone
does not make a dynamic membership adapter current.

For live-fact consumers, `authorize_with_roles` takes a caller-resolved
`ResolvedRoles` bound to the full principal and exact domain. It evaluates the
roles through the same Casbin capabilities without mutating or rebuilding the
engine, never falls back to snapshot assignments, and leaves credential and
server attenuation mandatory. The caller owns live freshness; the core adds no
revision database or invalidation service. When the domain itself is dynamic,
`authorize_with_resolved_domain` applies the same checks but also accepts a
syntactically valid unregistered domain, on the caller's authority that the
target domain exists and the supplied roles are its current effective roles.

## Usage

```rust
use std::collections::BTreeSet;
use cloudiful_authz::{
    Action, AuthzRequest, Authorizer, AuthorizerConfig, Capability, DomainHierarchy,
    DomainId, FactsRevision, PrincipalId, PrincipalKind, PrincipalRef, ResourceKind,
    ResourceRef, RoleAssignment, RoleId, RoleSpec, ServiceId, Subject,
};

async fn example() -> Result<(), Box<dyn std::error::Error>> {
    let principal = PrincipalRef {
        kind: PrincipalKind::Human,
        id: PrincipalId::new("42"),
    };

    let authorizer = Authorizer::new(AuthorizerConfig {
        facts_revision: FactsRevision(1),
        domains: vec![DomainId::new("docs")],
        roles: vec![RoleSpec {
            id: RoleId::new("viewer"),
            capabilities: BTreeSet::from([Capability {
                resource: ResourceKind::new("page"),
                action: Action::new("read"),
            }]),
        }],
        assignments: vec![RoleAssignment {
            principal: principal.clone(),
            role: RoleId::new("viewer"),
            domain: DomainId::new("docs"),
        }],
        global_assignments: vec![],
        hierarchy: DomainHierarchy::default(),
        public_read: BTreeSet::new(),
    }).await?;

    let request = AuthzRequest {
        subject: Subject::Principal(principal),
        domain: DomainId::new("docs"),
        resource: ResourceRef {
            kind: ResourceKind::new("page"),
            id: None,
            domain: DomainId::new("docs"),
        },
        action: Action::new("read"),
        audience: ServiceId::new("docs-service"),
        facts_revision: FactsRevision(1),
        credential: None,
        server: None,
    };

    assert!(authorizer.authorize(&request).is_allowed());
    Ok(())
}
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
```
