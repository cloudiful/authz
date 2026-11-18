# Authorization model

Status: implemented core contract, revised after parent review of record 5618
and then implemented for P1. Current consumer behavior is recorded in
[`consumer-mapping.md`](consumer-mapping.md); this document specifies the
contract the `cloudiful-authz` crate implements. Consumer adapter integration,
especially dynamic-facts freshness, remains unresolved and is not provided by
the core.

## 1. Scope and non-goals

`cloudiful-authz` is an authorization decision library, not an authentication
service. It receives an already-authenticated subject, a domain, a resource, an
action, optional credential attenuation, and optional server attenuation, then
returns allow or deny.

Out of scope for the first crate:

- password, session, token lifecycle, token signing, hashing, storage, and
  revocation transport;
- identity-provider protocols and login flows;
- a central authorization service, network policy endpoint, or admin UI;
- persistence, SQL, row visibility, leases, approvals, quotas, and IP rules;
- consumer contract crates and business-specific role names inside the core;
- automatic cross-project token trust;
- a general policy language exposed to callers;
- credential authentication, signature verification, expiry, revocation, and
  audience discovery; those stay in the credential-issuing or authentication
  layer.

Consumers that do not need authorization do not take a dependency on this
crate. Embedding it necessarily brings Casbin as the decision engine; it does
not add SQL, HTTP, session, or consumer-contract dependencies.

## 2. Terms

| Term | Meaning |
| --- | --- |
| Principal | An authenticated human, service, or application identity, identified by both kind and id. A credential is not a principal. |
| Subject | Either a principal or the trusted public-read access mode. |
| Domain | A permission boundary. Domains may have an explicit parent relationship. |
| Resource | A resource kind, an optional exact resource id, and the domain that owns it. |
| Action | An exact registered operation name. |
| Capability | The exact pair `(resource kind, action)`. |
| Role | A named, explicitly registered capability set. Roles are not a global ordered enum. |
| Role assignment | `(principal, role, domain)`; the principal has that role in that domain. |
| Grant | A typed attenuation entry over `(domain, resource kind, optional exact resource id, action)`. |
| Attenuation | `Unrestricted` or an explicit set of grants. No wildcard syntax exists. |
| Audience | The service a credential was issued for. It is separate from the permission domain. |
| Facts revision | The opaque version of the trusted assignment and role facts used to build an authorizer. |

An application principal is a principal kind, not a group. Group membership is a
domain-scoped role assignment, never an application identity.

## 3. Invariants

1. Authentication precedes authorization. The core never derives a principal
   or a public access mode from a client-supplied claim.
2. Principal identity is the pair `(kind, id)`. Credential binding and role
   assignments use that pair; an id alone is never a principal identity.
3. Principal and role identifiers occupy separate namespaces. A principal whose
   id equals a role id cannot acquire that role by identity collision.
4. Authority comes only from trusted current assignments, the static role
   schema, or an explicitly registered public-read grant. Client input cannot
   name a role, capability, domain, grant, or audience and thereby gain
   authority.
5. Every request names exactly one domain. A resource from another domain is
   denied.
6. Capability matching is exact. There is no implicit wildcard, implicit
   administrator superuser, rank-based implication, read-to-shell implication,
   or implicit domain-descendant grant.
7. A credential or server attenuation can only subtract authority. It is a set
   of typed grants, never independent domain and capability sets whose Cartesian
   product could authorize an unlisted combination.
8. `Unrestricted` and an empty grant set are distinct: unrestricted applies no
   attenuation, while an empty set authorizes nothing.
9. Unknown roles, domains, resource kinds, actions, malformed input, stale facts,
   and engine errors deny. A credential audience mismatch denies when a
   credential is present.
10. Membership and allow decisions are not cached by the core. An immutable
    authorizer snapshot has an explicit revision and consumer-owned freshness
    contract.
11. SQL row visibility, leases, approvals, quotas, and IP rules remain mandatory
    external checks. This crate does not replace them and must not be used as a
    post-fetch row filter.

## 4. Decision inputs

A request contains:

- subject: either a typed `(principal kind, principal id)` or the trusted
  public-read mode;
- request domain;
- resource kind, optional exact resource id, and resource domain;
- exact action;
- the receiving service audience;
- facts revision;
- optional credential context;
- optional server context.

The credential context contains:

- the full principal the credential was issued to;
- the credential audience;
- `Attenuation`: `Unrestricted` or a set of typed grants.

The server context contains `Attenuation`: `Unrestricted` or a set of typed
grants. It has no principal and no audience; it describes the deployment's
maximum permission surface.

The optional resource id is exact evidence for the application's later
row-level check. It can narrow an attenuation grant, but it never widens subject
authority and never replaces SQL visibility.

## 5. Grant matching and attenuation

A grant is:

```text
(domain, resource kind, optional exact resource id, action)
```

Matching is exact on domain, resource kind, and action. For the optional
resource id:

- a kind-wide grant (`None`) matches any request resource id of that kind,
  including a request without an id;
- an exact-id grant (`Some(id)`) matches only a request whose resource id is
  exactly `Some(id)`;
- a request without a resource id is never authorized by an exact-id grant,
  because the request has not established which object it addresses.

A `Grants` set is a union of entries. Multi-domain credentials and group-scoped
keys list one grant per permitted domain; domains never expand through the
role hierarchy for attenuation. An empty set authorizes nothing. `Unrestricted`
is an explicit constructor and is never produced by parsing an empty,
wildcard, or unknown value.

Capability strings alone are not a valid public interface. Consumers convert
their stored token formats into typed grants at the boundary and reject unknown
resources, actions, domains, or access levels before constructing the
attenuation.

The registered resource/action universe is derived only from configured role
capabilities and public-read grants at authorizer construction. A resource kind
or action that appears only in a credential or server grant does not register a
name, cannot make an otherwise unknown request valid, and cannot widen policy.
Grant matching is a further restriction on an already registered capability.

## 6. Allow/deny algorithm

The decision is allow only when every applicable step passes.

1. Check the facts revision against the authorizer snapshot; a mismatch denies
   `StaleFacts` before any authority decision.
2. Validate the receiving `ServiceId` and, when a credential is present, the
   credential `ServiceId`. Empty, control-bearing, or wildcard audience values
   deny `InvalidAudience` in both principal and public-read paths.
3. Validate the request domain, resource kind, and action against the
   registered schema.
4. Require `resource.domain == request.domain`; otherwise deny
   `CrossDomainResource`.
5. Determine subject authority:
   - principal: ask Casbin whether the principal has a role in the request
     domain whose registered capability set contains
     `(resource.kind, action)`;
   - public-read: require an exact registered public-read grant for the
     request domain, resource kind, optional exact id, and action. Public-read
     has no role inheritance and no anonymous role.
6. If a credential context is present:
   - for a principal subject, deny `CredentialPrincipalMismatch` unless the
     credential's full `(kind, id)` equals the request principal;
   - deny `CredentialAudienceMismatch` unless the credential audience equals
     the receiving service audience;
   - deny `CredentialGrantMissing` unless the credential attenuation admits the
     request.
7. If a server context is present, deny `ServerGrantMissing` unless its
   attenuation admits the request.
8. Allow. Any internal engine error denies `EngineError`; it is never converted
   to allow.

The stable denial-reason precedence is stale facts, malformed audience,
validation, cross-domain, subject authority, credential, server, engine error. Applications normally map
every denial to their own forbidden response and may log the reason, but must
not leak role or policy detail to the caller.

Public-read is a subject-authority branch inside this algorithm, not a bypass.
A request on a public-read route still evaluates any present credential and
server attenuation. If the route carries a personal access token, the token is
authenticated outside the core and its grants still apply; public visibility
never makes an invalid, expired, revoked, or overreaching token valid.

## 7. Casbin model and identity namespaces

The crate owns a fixed Casbin model. Callers cannot supply a model string or a
policy language.

```ini
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.obj == p.obj && r.act == p.act
```

- `p(role_subject, resource_kind, action)` is one registered role capability.
- `g(principal_subject, role_subject, domain)` is one effective role
  assignment.
- `r.sub` is the encoded principal subject, `r.dom` is the request domain,
  `r.obj` is the resource kind, and `r.act` is the exact action.
- Casbin's domain-role relation performs the membership decision. The matcher
  does not contain a handwritten rank comparator, role switch, or business-name
  branch.

### Identity encoding

Principal and role subjects are encoded into disjoint namespaces before they
reach Casbin. The encoding uses distinct prefixes and length-prefixed
components, so no principal id can equal a role subject and no separator in an
id can forge another identity. For example, a principal is encoded from both
kind and id, while a role is encoded from the role id under a role-only prefix.
The exact encoding is internal; callers use typed values and never construct
Casbin subject strings.

- `PrincipalRef` equality is `(kind, id)`, never `id` alone.
- Role assignment, credential binding, and the principal branch all use the
  full `PrincipalRef`.
- A principal id that happens to equal a role id remains a principal subject
  and cannot trigger a reflexive role match.
- Empty and control-bearing identifiers are rejected at initialization or
  request validation. Separator-like or prefix-like content is not rejected;
  length-prefixed encoding keeps it injective across principal kinds, ids, and
  roles.

Role capabilities are static for the lifetime of an `Authorizer`. Role presets
such as viewer, maintainer, owner, and admin are registered explicit sets; the
core has no global role enum and no role ordering. A consumer that needs a
superset relationship expresses it by listing the capabilities explicitly in
the role spec.

### Domain binding

Every `g` row carries a domain. A role assignment in domain `acme` does not
authorize `other` unless the hierarchy expansion below adds the assignment to
`other`.

### Domain hierarchy and inheritance

The optional hierarchy is an explicit list of `(child, parent)` edges supplied
from trusted configuration or data. At authorizer construction the core:

1. validates that every domain is registered and the hierarchy is acyclic;
2. computes the transitive descendant set of every domain;
3. inserts `g(principal, role, child)` for every direct assignment
   `(principal, role, parent)` and every descendant `child` of `parent`;
4. inserts explicit global assignments into every registered domain.

Inheritance is downward only and preserves the role, not a numeric rank. A
principal with several inherited roles receives the union of their capability
sets. Lexical path prefixes are never treated as hierarchy.

Attenuation grants do not inherit through the domain hierarchy. A token scoped
to `group:acme` does not implicitly cover `group:acme/team`; a product that
wants descendant coverage must issue explicit grants or define a separate,
approved expansion rule.

### Delegation

Delegation is a domain-layer operation, not an authorization-engine feature.
A consumer that exposes membership management must:

- require an explicit `membership.grant` capability for the actor in that
  domain;
- require that the granted role's registered capability set is a subset of the
  actor's effective capabilities in that domain;
- require a separate owner-level grant for assigning the owner role or any
  capability the actor does not hold itself;
- never let an actor grant a role merely because it can edit other members.

The core exposes role specs for subset checks; it does not implement consumer
membership endpoints.

## 8. Namespace and tenant matching

- Domains are opaque exact identifiers. Wildcards, prefix matching, and
  case-folding are invalid.
- A namespace or tenant path is canonicalized by the consumer before it becomes
  a domain id. Two spellings that the consumer considers equivalent must map to
  one id before authorization.
- Unknown domain ids deny. The core never creates a domain on demand.
- Domain hierarchy comes only from trusted edges. A path-like name does not
  imply a parent.
- Cross-domain resource access is denied even when the principal has authority
  in both domains; the caller must make the request in the resource's domain.
- Grant domains are exact. A multi-domain credential is a set of separate
  grants, not a wildcard domain.

## 9. Credentials, audience, and non-escalation

A credential is evidence of authentication and an attenuation layer. It is
never a role assignment.

- The credential's bound principal uses the full `(kind, id)` pair and must
  equal the request principal on the principal branch.
- The credential audience is compared with the receiving service audience and
  is separate from the permission domain. Matching domain strings cannot
  substitute for audience validation. The consumer must take the audience from
  the verified credential, never from an unvalidated header, route parameter,
  or domain id; the core compares the values but does not authenticate the
  credential.
- The credential attenuation can only remove capabilities from subject
  authority. It cannot add a role or capability.
- `Unrestricted` means the credential imposes no attenuation. `Grants(empty)`
  means the credential authorizes nothing.
- A token whose audience is a different service is rejected even when its
  permission domain happens to match.
- Revoked, expired, disabled, or unverifiable credentials are rejected by the
  authentication/credential layer. The core receives only active trusted
  credential facts and does not perform signature, expiry, or revocation
  checks.
- Unknown resources or actions in a stored credential map grant nothing; the
  consumer must reject or drop them before constructing grants.

Server attenuation uses the same typed grant matching and the same
unrestricted-versus-empty rule. A deployment with no configured server ceiling
passes `Unrestricted`; a deployment configured with an empty grant set passes
`Grants(empty)` and denies every capability.

## 10. Public, system, and administrator attributes

- **Public-read** is an explicit trusted access mode with separately registered
  exact public-read grants. It has no inherited roles, no anonymous role, and
  no client-declared identity. A route selects `Subject::PublicRead`; a client
  cannot request it. The public branch still applies credential and server
  attenuation.
- **System** is a protected resource attribute. There is no system bypass and
  no implicit owner or admin exception. A consumer denies normal roles on
  system resources unless it explicitly registers a system-only capability and
  assigns it to the intended control-plane principal.
- **Admin** is an ordinary registered role with an explicitly enumerated
  control-plane capability set. It has no wildcard matcher and no automatic
  private-data access. Legacy administrator exceptions are preserved only by
  explicitly registering the capabilities the current administrator already
  exercises. Any actual user or token authority change is a product decision,
  not a core default.
- A global administrator assignment is an explicit trusted assignment expanded
  into each registered domain. It is not an implicit superuser and grants only
  the role's enumerated capabilities.

## 11. Immutable snapshots, live facts, and freshness

### The unresolved constraint

Some consumers, especially Context69 group membership and Stock project
membership, currently read live facts per request. An immutable Casbin
`Authorizer` is a snapshot of role schema and assignments. It cannot by itself
promise that a request decision reflects a membership or admin change that
happened after construction. P0 must not claim adapter viability for dynamic
membership without a concrete refresh and admission design.

### Two models compared

| Model | Strength | Cost and limitation |
| --- | --- | --- |
| Per-request live facts | Reflects the current source-of-truth membership at decision time; no stale snapshot admission | Repeats source queries, duplicates policy reads in the consumer, and is not an immutable engine snapshot |
| Long-lived assignment snapshot | Cheap immutable decisions and a single async startup build | Decisions are only current as of the snapshot revision; a refresh and admission contract is mandatory |

### Required refresh and admission contract

The core adds a facts revision to the API and rejects stale admission:

- `AuthorizerConfig` carries the trusted `FactsRevision` used to build the
  snapshot.
- `AuthzRequest` carries the revision the consumer observed from the same
  trusted source that produced the assignments.
- `Authorizer::authorize` denies `StaleFacts` when the request revision differs
  from the snapshot revision.
- `Authorizer::facts_revision()` exposes the snapshot revision.

The implemented `Authorizer` stores its snapshot revision and applies this check
before authority evaluation. It does not obtain the current revision itself.

A consumer must obtain the current revision before admitting a request to a
snapshot decision. The revision source is the consumer's responsibility: a
transactional policy-revision row, a monotic local revision bumped on every
membership/admin change, or another trusted mechanism. If the consumer cannot
obtain a current revision, it must not use a long-lived snapshot for that
decision.

On a membership, role-schema, or hierarchy change:

1. the source transaction increments the facts revision;
2. the process builds a new immutable `Authorizer` from current trusted facts
   (not per request);
3. the process atomically replaces the old authorizer;
4. an old-snapshot request with a new revision is denied `StaleFacts` until the
   replacement is installed, and a request carrying an old revision after the
   swap is also denied; the consumer retries after refresh.

The core does not implement a distributed invalidation bus. Each process
refreshes independently. A deployment that cannot observe a shared revision must use live
facts in the consumer or accept a stated staleness boundary; it must not claim
current-fact authorization. No per-request full Casbin rebuild is an acceptable
implementation.

### API consequence

The revision fields and `DenyReason::StaleFacts` are part of the implemented
minimal API. The live-facts path remains unresolved for consumers that cannot
supply a current revision; those consumers keep their existing live check in the
migration instead of pretending a snapshot is current.

## 12. Lists, queries, and row visibility

Authorizing a list endpoint is necessary but not sufficient. The consumer must
apply SQL row visibility and domain/tenant filters before fetching or
paginating, then apply any per-row policy mandated by its data model.

- Do not fetch rows and filter them after the database.
- Do not turn a list decision into a per-row allow decision without a defined
  row-level predicate.
- A denied collection request returns no rows; a partially visible collection
  is a consumer SQL responsibility, not a core post-filter.
- Pagination counts must be computed under the same visibility predicate.
- An exact resource-id grant can narrow a token, but it does not replace the
  SQL predicate for a list or object read.

## 13. Initialization lifecycle and errors

`Authorizer::new(config)` is asynchronous and explicit at application startup
or at a defined refresh boundary. It:

- builds the fixed model with Casbin;
- validates the role schema, assignments, domains, hierarchy, public-read
  grants, and facts revision;
- inserts `p` policies and expanded `g` assignments into an in-memory adapter;
- returns a typed initialization error without starting a partial authorizer.

Initialization errors include duplicate role ids, duplicate configured domain
ids, unknown role in an assignment, unknown domain in an assignment or
hierarchy, cycles in the hierarchy, invalid (empty or control-bearing)
identifiers, invalid public-read grants, and Casbin model or adapter failure.
Repeated effective assignments are deduplicated; configured domains and roles
are not.

`authorize(&self, request)` is synchronous, allocation-light, and safe to call
concurrently. There is no lazy `OnceCell`, no `block_on`, no spawned
initialization thread, no per-request engine construction, and no fallback to
allow on initialization or enforcement failure.

The consumer owns the authorizer's lifetime. It stores an immutable
`Arc<Authorizer>` and replaces it at the revision refresh boundary, or builds it
once at startup when its facts are static. `Clone` of `Authorizer` is cheap and
shares the immutable engine state.

## 14. Proposed minimal Rust API

The public names are implemented as shown; later refinements must preserve the
semantics.

```rust
pub struct PrincipalId(pub String);
pub struct DomainId(pub String);
pub struct RoleId(pub String);
pub struct ResourceKind(pub String);
pub struct ResourceId(pub String);
pub struct Action(pub String);
pub struct ServiceId(pub String);
pub struct FactsRevision(pub u64);

pub enum PrincipalKind {
    Human,
    Service,
    Application,
}

pub struct PrincipalRef {
    pub kind: PrincipalKind,
    pub id: PrincipalId,
}

pub enum Subject {
    Principal(PrincipalRef),
    PublicRead,
}

pub struct Capability {
    pub resource: ResourceKind,
    pub action: Action,
}

pub struct Grant {
    pub domain: DomainId,
    pub resource: ResourceKind,
    pub resource_id: Option<ResourceId>,
    pub action: Action,
}

pub enum Attenuation {
    Unrestricted,
    Grants(BTreeSet<Grant>),
}

pub struct RoleSpec {
    pub id: RoleId,
    pub capabilities: BTreeSet<Capability>,
}

pub struct RoleAssignment {
    pub principal: PrincipalRef,
    pub role: RoleId,
    pub domain: DomainId,
}

pub struct GlobalAssignment {
    pub principal: PrincipalRef,
    pub role: RoleId,
}

pub struct DomainHierarchy {
    pub edges: Vec<(DomainId, DomainId)>, // child, parent
}

pub struct PublicReadGrant {
    pub domain: DomainId,
    pub resource: ResourceKind,
    pub resource_id: Option<ResourceId>,
    pub action: Action,
}

pub struct AuthorizerConfig {
    pub facts_revision: FactsRevision,
    pub domains: Vec<DomainId>,
    pub roles: Vec<RoleSpec>,
    pub assignments: Vec<RoleAssignment>,
    pub global_assignments: Vec<GlobalAssignment>,
    pub hierarchy: DomainHierarchy,
    pub public_read: BTreeSet<PublicReadGrant>,
}

pub struct CredentialContext {
    pub principal: PrincipalRef,
    pub audience: ServiceId,
    pub grants: Attenuation,
}

pub struct ServerContext {
    pub grants: Attenuation,
}

pub struct ResourceRef {
    pub kind: ResourceKind,
    pub id: Option<ResourceId>,
    pub domain: DomainId,
}

pub struct AuthzRequest {
    pub subject: Subject,
    pub domain: DomainId,
    pub resource: ResourceRef,
    pub action: Action,
    pub audience: ServiceId,
    pub facts_revision: FactsRevision,
    pub credential: Option<CredentialContext>,
    pub server: Option<ServerContext>,
}

pub enum DenyReason {
    UnknownDomain,
    UnknownResource,
    UnknownAction,
    CrossDomainResource,
    NoSubjectAuthority,
    StaleFacts,
    InvalidAudience,
    CredentialPrincipalMismatch,
    CredentialAudienceMismatch,
    CredentialGrantMissing,
    ServerGrantMissing,
    EngineError,
}

pub enum Decision {
    Allow,
    Deny(DenyReason),
}

pub enum InitError {
    DuplicateRole(RoleId),
    DuplicateDomain(DomainId),
    UnknownRole(RoleId),
    UnknownDomain(DomainId),
    InvalidPublicReadGrant,
    HierarchyCycle,
    InvalidIdentifier(String),
    Engine(String),
}

impl Authorizer {
    pub async fn new(config: AuthorizerConfig) -> Result<Self, InitError>;
    pub fn authorize(&self, request: &AuthzRequest) -> Decision;
    pub fn facts_revision(&self) -> FactsRevision;
    pub fn role_capabilities(&self, role: &RoleId) -> Option<&BTreeSet<Capability>>;
}
```

`InitError::Engine` carries only a private diagnostic suitable for logs; public
error text must not expose policy internals. The caller maps every `Decision::
Deny` to its own forbidden response.

## 15. Usage examples

The examples use compact helper constructors for readability; the public
structs are exposed directly. Every request carries the same revision as its
snapshot in these examples.

### Domain group membership

```rust
let authorizer = Authorizer::new(AuthorizerConfig {
    facts_revision: FactsRevision(17),
    domains: vec![domain("group:acme"), domain("group:acme/team")],
    roles: vec![
        role("viewer", &[("content", "read"), ("content", "search")]),
        role("maintainer", &[("content", "read"), ("content", "search"), ("content", "write")]),
        role("owner", &[("content", "read"), ("content", "search"), ("content", "write"),
                        ("membership", "grant"), ("group", "manage")]),
    ],
    assignments: vec![assignment(
        PrincipalRef { kind: PrincipalKind::Human, id: principal_id("42") },
        "maintainer",
        "group:acme",
    )],
    global_assignments: vec![],
    hierarchy: hierarchy(&[("group:acme/team", "group:acme")]),
    public_read: BTreeSet::new(),
}).await?;

// Inherited maintainer authority in the child domain.
assert!(matches!(
    authorizer.authorize(&request(principal("human", "42"), "group:acme/team", "content", "write")),
    Decision::Allow
));
// Maintainer authority does not grant owner membership management.
assert!(matches!(
    authorizer.authorize(&request(principal("human", "42"), "group:acme/team", "membership", "grant")),
    Decision::Deny(_)
));
```

The consumer's membership endpoint additionally applies the delegation subset
check from section 7. A principal whose id is the string `viewer` remains
`principal:human:viewer` and never becomes `role:viewer`.

### Stock read, write, run, shell, and legacy compatibility

```rust
let legacy_workspace_write = Grant {
    domain: domain("workspace:bound-7"),
    resource: resource("workspace"),
    resource_id: None,
    action: action("write"),
};
let legacy_shell = Grant {
    domain: domain("workspace:bound-7"),
    resource: resource("workspace"),
    resource_id: None,
    action: action("shell"),
};
// Legacy adapter expansion: current workspace:write includes shell execution.
let credential = CredentialContext {
    principal: PrincipalRef { kind: PrincipalKind::Human, id: principal_id("42") },
    audience: service("stock-mcp"),
    grants: Attenuation::Grants(BTreeSet::from([legacy_workspace_write, legacy_shell])),
};

let roles = vec![
    role("reader", &[("project", "read"), ("workspace", "read"), ("project", "run")]),
    role("editor", &[("project", "read"), ("workspace", "read"), ("project", "run"),
                     ("project", "write"), ("workspace", "write"), ("workspace", "shell")]),
    role("owner", &[("project", "read"), ("workspace", "read"), ("project", "run"),
                    ("project", "write"), ("workspace", "write"), ("workspace", "shell"),
                    ("project", "delete"), ("membership", "manage")]),
];
```

The legacy mapping keeps shell reachable under workspace write by explicit
expansion; it is not silently removed. The target behavior change, separating
shell into its own capability and requiring a later product approval, is
recorded in `consumer-mapping.md`. The example above reflects the legacy
capability set, not a claim that shell is implied by content write.

The account-token permission map becomes typed grants. `code_projects: read`
maps to project read capabilities; `code_projects: write` maps to the exact
legacy write/run capabilities; `workspace: write` maps to workspace read, write,
and shell for compatibility; `workspace: read` maps to read only. The exact
legacy table is in `consumer-mapping.md`.

### Desk application principal and three layers

```rust
let subject = Subject::Principal(PrincipalRef {
    kind: PrincipalKind::Application,
    id: principal_id("app:reporting"),
});

let config = AuthorizerConfig {
    roles: vec![role("desk-app", &[("workspace", "read"), ("workspace", "search"),
                                   ("workspace", "shell"), ("workspace", "patch")])],
    assignments: vec![assignment(
        PrincipalRef { kind: PrincipalKind::Application, id: principal_id("app:reporting") },
        "desk-app",
        "workspace:bound-7",
    )],
    // ...
};

let request = AuthzRequest {
    subject,
    domain: domain("workspace:bound-7"),
    resource: resource("workspace", Some("bound-7"), "workspace:bound-7"),
    action: action("patch"),
    audience: service("desk-foreman"),
    facts_revision: FactsRevision(4),
    credential: Some(CredentialContext {
        principal: PrincipalRef { kind: PrincipalKind::Application, id: principal_id("app:reporting") },
        audience: service("desk-foreman"),
        grants: Attenuation::Grants(BTreeSet::from([Grant {
            domain: domain("workspace:bound-7"),
            resource: resource("workspace"),
            resource_id: Some(resource_id("bound-7")),
            action: action("patch"),
        }])),
    }),
    server: Some(ServerContext {
        grants: Attenuation::Grants(BTreeSet::from([Grant {
            domain: domain("workspace:bound-7"),
            resource: resource("workspace"),
            resource_id: None,
            action: action("patch"),
        }])),
    }),
};
```

Numeric limits, network policy, workspace binding, and write leases remain
consumer checks. The engine only decides the scoped action.

### Prompt-ferry inference versus control

```rust
// A request client key is a credential restricted to inference requests.
let inference = AuthzRequest {
    subject: Subject::Principal(PrincipalRef {
        kind: PrincipalKind::Human,
        id: principal_id("9"),
    }),
    domain: domain("gateway"),
    resource: resource("inference", Some("chat"), "gateway"),
    action: action("request"),
    audience: service("prompt-ferry"),
    facts_revision: FactsRevision(3),
    credential: Some(CredentialContext {
        principal: PrincipalRef { kind: PrincipalKind::Human, id: principal_id("9") },
        audience: service("prompt-ferry"),
        grants: Attenuation::Grants(BTreeSet::from([Grant {
            domain: domain("gateway"),
            resource: resource("inference"),
            resource_id: None,
            action: action("request"),
        }])),
    }),
    server: None,
};

// Usage and control remain session/admin capabilities; an inference key
// cannot reach them even if the same user is an administrator.
```

A group-scoped or multi-domain key lists one exact grant per domain and, where
needed, an exact resource id. It does not get a Cartesian product of domains and
capabilities and does not inherit descendant domains.

### Stock-factor and stock-import admin data

```rust
let grants = Attenuation::Grants(BTreeSet::from([Grant {
    domain: domain("factor-admin"),
    resource: resource("admin_data"),
    resource_id: None,
    action: action("read"),
}]));

// The service registers an explicit administrative data role.
let roles = vec![role("admin-data", &[("admin_data", "read"), ("admin_data", "write")])];

// A bearer token's admin_data read grant maps to the read grant only; the
// request also requires the principal to hold the role.
let credential = CredentialContext {
    principal: PrincipalRef { kind: PrincipalKind::Human, id: principal_id("7") },
    audience: service("stock-factor"),
    grants,
};
```

A session has `Attenuation::Unrestricted`; a bearer token has a typed grant set.
The current `is_admin AND token ceiling` conjunction is preserved by requiring
the role assignment plus the credential attenuation.

## 16. Implementation boundary and tests

The crate is the `cloudiful-authz` package at version `0.1.0`, edition 2024,
`publish = false`, with Casbin pinned to verified stable `2.20.0` and its
lockfile committed. No SQL, HTTP, token, session, or consumer-contract
dependency belongs in the core; Casbin is the engine dependency.

Permanent pure tests cover:

- an assignment in one domain does not authorize another domain;
- parent-domain assignment authorizes a descendant domain, and a refreshed
  snapshot with a removed assignment no longer does;
- exact role capabilities allow only the registered `(resource, action)` pair;
- a role without a capability is denied even when another role has it in a
  different domain;
- a principal id equal to a role id does not acquire that role;
- credential principal kind/id mismatch, audience mismatch, missing grant, and
  an explicitly empty grant set deny; unrestricted passes;
- server unrestricted versus empty behaves differently;
- multi-domain grants authorize only the listed domain/action/resource-id
  combinations and never their Cartesian product;
- an exact-id grant does not authorize a request without a resource id;
- public-read grants allow only the exact public capability, still apply
  credential/server grants, and never inherit a role;
- stale facts revision denies;
- application principal is not a group and receives no implicit role;
- administrator role has no wildcard capability and no private-data bypass;
- malformed receiving or credential audiences deny in both principal and
  public-read modes;
- unknown role/domain/resource/action and engine error deny;
- duplicate configured domains, duplicate roles, unknown references, invalid
  public-read grants, and hierarchy cycles fail initialization.

The fixed gates are `cargo fmt --all -- --check`,
`cargo check --all-targets --locked`, `cargo test --locked`,
`cargo clippy --all-targets --locked`, and `git diff --check`.

## 17. Open decisions and blockers

These are not implementation details and must be resolved before the relevant
consumer migration, not guessed in code.

1. **Dynamic-facts architecture.** Some consumers cannot supply a current
   revision cheaply at admission. Decide whether they accept a revisioned
   snapshot boundary, keep live facts in the consumer, or need a future
   live-facts API. The core does not pretend snapshot mode is a drop-in for
   Context69 group membership or Stock project membership.
2. **Delegation boundary.** Confirm that member-edit permission never implies
   the right to grant owner or higher authority. The target rule is stricter
   than Context69's current behavior.
3. **Administrator capability sets.** Enumerate the capabilities each existing
   administrator actually needs. Preserve current authority only by explicit
   capabilities; any effective user/token authority change returns to the user.
4. **Stock workspace shell.** Decide when to split shell from legacy workspace
   write. The current behavior remains in the legacy mapping until then.
5. **Public-read scope.** Confirm the exact public-read grants per route,
   including whether an optional resource id is needed.
6. **Exact-object token ceilings.** Confirm which consumers need exact
   resource-id grants and how their token formats represent them.
7. **Audience topology.** Confirm the service/audience identifiers each
   credential issuer uses; domain ids must not be reused as audiences.
8. **Prompt-ferry scoped keys.** Approve schema, snapshot wire change,
   management API, and revocation propagation before enabling scoped keys.
9. **Desk application scopes.** Confirm that application default scopes are
   subject authority and that token/server grants remain attenuation only.
