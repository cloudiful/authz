# Consumer mapping

Status: consumer mapping for the implemented core (P1 snapshot API plus the P2
trusted live-resolved-role entrypoint). No consumer migration is implemented.
This document separates behavior verified by reading the named source files
from target design and from paths that were not inspected. No consumer was
modified, built, or run for this mapping.

## 1. Evidence and confidence

Source was read read-only on 2026-11-19. No `.env`, credential, or production
data was accessed.

| Repository | Revision read | Confidence and limits |
| --- | --- | --- |
| Context69 | `d900054` working tree; Casbin branch `phasegent/103-75cd88` at `8023b76` | HTTP/group/MCP authorization read. PR104 branch is not merged into `main`; its Casbin adapter is inspected as the current implementation proposal, not as released behavior. |
| stock-goes-stonk | `5870bc642` | HTTP route classification, account-token permission map, code-project authority read. |
| desk-foreman | `fb32d1b` | Scope intersection, limits, actor/principal construction read. |
| prompt-ferry | `c9f67e4` | Admin gate, client-key/inference paths, bridge snapshot shape read. |
| stock-factor | uncommitted working tree (no `HEAD`) | `admin_data_allows` and middleware read. |
| stock-import | `f8ed587` | `admin_data_allows` and middleware read. |
| stock-gateway | `7c5bbbe` | Credential introspection, account-token resources, permission policy read. |
| gov-info | `4d0affe` | Public router and outbound Context69 PAT configuration read. |
| s3-cleaner | `ec6c4bc` | Per-target webhook token path read. |
| stock-operator | `bc2adb7` | Server token and live-operation confirmation token paths read. |
| modern-rtx | `a466344` | Session-token authentication path sampled; full route authorization not audited. |

Runtime behavior, database state, and unlisted handlers were not inspected.
Where a mapping depends on an unread handler it is marked target or pending.

## 2. Vocabulary mapping

| Current vocabulary | Target model |
| --- | --- |
| User id / account id | `PrincipalRef { kind, id }`; kind and id are both part of identity |
| `is_admin` flag | Explicit `admin` role capability set; no wildcard superuser |
| Membership role rank (`owner` > `maintainer` > `viewer`) | Explicit role capability sets, with legacy superset preserved by listing capabilities |
| Project `reader`/`editor`, owner user id | `reader`/`editor`/`owner` role sets, with execution and member/delete capabilities separated |
| Application default scopes | Subject-authority role capability set (application principal) |
| Token scopes / permission map / `admin_data` level | Typed credential grant set over domain, resource kind, optional exact resource id, and action |
| Independent token domains plus capabilities | One grant per permitted combination; never a Cartesian product |
| Server scopes / configured limits | Server grant set and consumer limit checks |
| Public visibility | Exact registered public-read grant; a trusted access mode, not a role |
| System project / protected row | Resource attribute; no implicit owner/admin bypass |
| Group, project, namespace, workspace | Domain (explicit hierarchy where verified) |
| PAT `group_scope` | One exact grant per named group/domain; no prefix or descendant expansion |
| Audience / service | `ServiceId`, kept separate from permission `DomainId` |

Principal and role identifiers are encoded into separate Casbin namespaces, so a
principal whose id equals a role id cannot acquire that role reflexively. The
mapping below never relies on a bare id for identity.

## 3. Core consumer matrix

### 3.1 Context69

**Verified current behavior**

- `MembershipRole::{Viewer, Maintainer, Owner}` is a numeric rank enum
  (`crates/context69-contracts-namespace/src/namespace.rs`).
- `get_group_for_user` and list queries inherit membership down the group tree
  and take the maximum rank; a public group is visible without a membership,
  while a private group requires a non-null role
  (`src/sql/db/namespaces/get_group_for_user.sql`,
  `list_accessible_groups_for_user.sql`).
- `require_group_role` compares rank (`src/api/group_access.rs`).
- Maintainer can update groups and upsert memberships; owner is required for
  moving a group (`src/db/namespaces.rs`). The current membership upsert does
  not stop a maintainer from assigning `owner`.
- PAT scopes are exact `search`, `workspace`, `library`, `sources`, `settings`,
  and `admin`; a token with `admin` scope can only be created by an
  administrator (`crates/context69-contracts-auth/src/auth.rs`,
  `src/services/personal_access_tokens.rs`).
- `TokenGroupScope` restricts a token to named group ids; an empty restricted
  set allows nothing; unrestricted tokens and sessions keep historical behavior
  (`src/authorization.rs`).
- The PR104 adapter uses Casbin `p = sub, obj, act` with `g` absent and a
  rank-derived policy set; it is a useful object-level baseline but not the
  final domain-role model (`8023b76:crates/context69-authz/src/lib.rs`).
- MCP applies exact PAT scopes per tool/resource
  (`8023b76:src/mcp/authorization.rs`).
- `is_admin` is a global user flag used by group visibility, translations, and
  admin user management.
- Group membership is currently read from live SQL per request; the profile
  that produced `group.current_role` is not a long-lived policy snapshot.

**Legacy mapping**

| Current | Legacy target mapping |
| --- | --- |
| Viewer | `viewer` role: content read/search capabilities |
| Maintainer | `maintainer` role: viewer capabilities plus content write/modify |
| Owner | `owner` role: maintainer capabilities plus group/membership management |
| Parent membership inheritance | Domain hierarchy `child group -> parent group`; same role inherited, union of roles if multiple |
| Public group read | Exact public-read grant for the route/domain/resource; not viewer membership |
| PAT scope | Typed credential grants: one grant per domain, resource kind, optional exact resource id, and action |
| PAT `group_scope` | Exact grant domains for the named group ids; `All` or absent means unrestricted; no descendant expansion |
| `is_admin` | Explicit `admin` control-plane role; current private-data/group powers must be enumerated as capabilities, not kept as blanket bypass |

**Target differences and gaps**

- Replace numeric rank with role capability sets. Preserve the current
  owner-superset-maintainer-superset-viewer behavior by explicit capabilities.
- Maintainer membership management stays, but granting `owner` or a capability
  the actor does not hold requires the delegation checks in
  `authorization-model.md` section 7. This is stricter than current behavior.
- Admin scope no longer implies private group data or every content action.
- **Freshness:** Context69 resolves group membership from live SQL per request.
  The P2 `Authorizer::authorize_with_roles` entrypoint fits that shape: the
  consumer keeps its live SQL membership read and passes trusted
  `ResolvedRoles` for the full principal and exact group domain. The core then
  applies its registered role capabilities and the shared audience, credential,
  and server checks without rebuilding the engine or relying on a snapshot
  revision. This removes the core-side blocker for live membership decisions.
  The consumer still owns freshness and admission: it must resolve roles from
  verified current data, never from client claims or an old cached snapshot.
  The core provides no revision database or distributed invalidation.

**Wave A.** Do not rewrite Context69 PR104. After the shared crate is delivered
at an immutable revision, replace the local rank comparator with the shared
domain-role adapter where the live path is settled. Keep the existing SQL
inheritance query as the trusted role source and pass its result through
`authorize_with_roles`; do not move group membership to a long-lived snapshot
and do not rebuild Casbin per request. Remove the duplicate policy only in a
scoped migration.

### 3.2 stock-goes-stonk

**Verified current behavior**

- Code-project roles are `reader` and `editor`
  (`external/stock-sdk/crates/stock-sdk-core/src/lib.rs`).
- `project_can_manage` allows an administrator, owner, or editor; system
  projects are never manageable (`crates/stock-code-service/src/service.rs`).
- `project_can_execute_for_member` allows administrators, owner, any member
  (reader or editor), and the public visibility attribute; git-backed projects
  additionally need a head commit. Reader therefore includes run.
- `project_can_delete` allows only an administrator or owner; editors and
  readers cannot delete.
- Member management is owner-only (`project_can_delete` reused by
  `project_can_manage_members`).
- Account tokens carry a resource map of 12 resources
  (`market`, `news`, `watchlist`, `portfolio`, `sim`, `code_projects`,
  `workspace`, `ai`, `runner`, `admin_users`, `admin_data`, `admin_system`)
  with `none`/`read`/`write`; write includes read and `none` is dropped
  (`stock-gateway` `stock_mcp_tokens.rs`).
- Administrative resources require a live administrator in addition to the
  token grant (`AccountTokenResource::is_admin`).
- HTTP route classification maps paths to resources and session-only routes;
  conditional STT routes can admit either account or admin-system write and the
  handler checks the exact resource (`crates/stock-http-support/src/account_token.rs`).
- `workspace` combines reading/listing, editing, and running shell commands in
  the bound workspace.
- A workspace write grant is required for shell tools; a code-project write
  grant alone is not workspace access
  (`crates/stock-mcp-core/src/server/token_policy.rs`).

**Legacy mapping**

| Current | Legacy target mapping |
| --- | --- |
| Project `reader` | `reader` role: project read, workspace read, project run |
| Project `editor` | `editor` role: reader plus project write and workspace write, not delete or member management; legacy `workspace: write` also expands to shell |
| Project owner | `owner` role: editor plus project delete and membership management; the same legacy workspace shell expansion applies |
| Project administrator | Explicit administrative project capabilities, not blanket private-data access; legacy admin exceptions stay explicit |
| `is_system` | Protected resource attribute; no role bypass |
| `visibility_kind == public` | Exact public run/read grant at the route layer; still applies token/server attenuation |
| `code_projects: read/write` | Typed credential grants over project read/write/run capabilities |
| `workspace: read` | Typed credential grant over workspace read and listing |
| `workspace: write` | **Legacy explicit expansion:** workspace read, workspace write, and shell execution, preserving current behavior |
| `admin_users`, `admin_data`, `admin_system` grants | Typed credential grants plus the current live-administrator requirement; admin legacy exceptions are enumerated, not unified away |

**Target differences and gaps**

- Execution is explicit, never implied by content write.
- Shell is currently reachable through `workspace: write`; the legacy mapping
  preserves that by explicit expansion. Separating shell into its own
  capability is a later approved behavior change, not silently removed now.
- Splitting shell changes token authority and needs user approval.
- Admin is explicit and enumerated; current `is_admin` behavior must be audited
  before migration so no user loses authority silently.

**Wave B.** Full HTTP/MCP/project migration after Wave A, preserving SQL
visibility, public/system attributes, legacy workspace shell, and existing
route behavior behind focused regression gates.

### 3.3 desk-foreman

**Verified current behavior**

- Scopes are `workspace.read`, `workspace.search`, `workspace.shell`, and
  `workspace.patch` (`src/policy.rs`).
- Application, token, and server scopes are intersected; numeric resource
  limits take the minimum and network is enabled only when every layer enables
  it (`AccessPolicy::from_layers`).
- Principals are internal users, application subjects, or isolated application
  principals; application subject requests carry a workspace binding and
  lease owner (`src/actor.rs`).
- Write access to resource-owned workspaces additionally requires the binding's
  write lease; the check is repeated under the binding lock for mutating entry
  points.

**Legacy mapping**

| Current | Legacy target mapping |
| --- | --- |
| `workspace.read/search/shell/patch` | Four exact capabilities |
| Application default scopes | Subject-authority role capability set for the application principal |
| Token scopes | Typed credential grant set; one grant per scope, domain, and exact resource id where applicable |
| Server scopes | Typed server grant set |
| Numeric limits / network flag | Consumer constraint checks; not engine capabilities |
| Workspace binding and write lease | Consumer checks; not replaced by the engine |
| Principal `application:<id>:<external-user>:<workspace>` | Application principal with its own `(kind, id)` identity; not a group |

**Target differences and gaps**

- The application is a machine principal, not a group; external user id and
  workspace key are part of the principal/binding context owned by desk.
- Shell is separate from patch and from read/write.
- The three layers remain intersection, but each layer is a set of typed grants,
  not independent domain and capability sets.
- Exact object grants require the request to carry the same resource id.

**Wave B.** Migrate after the shared API is stable; keep lease fencing and
resource limits untouched.

### 3.4 prompt-ferry

**Verified current behavior**

- Administrative handlers use `ensure_admin`, which requires a session user
  with `is_admin` (`src/worker_admin/state.rs` and `src/worker_admin/handlers/`).
- Client keys are generated with a hash and prefix; the bridge snapshot carries
  `ClientRoute { key_hash, key_prefix, user_id, route_id }`
  (`src/keys.rs`, `src/bridge/protocol.rs`).
- Existing client keys are inference/request credentials, not management
  credentials; management uses sessions. They do not carry per-action scopes.
- Usage and control surfaces require an administrator session.
- New scoped client keys are not implemented.

**Legacy mapping**

| Current | Legacy target mapping |
| --- | --- |
| Session `is_admin` | Explicit admin/control-plane capability set |
| Client key route | Credential bound to the full route principal with an inference-request grant |
| Inference request | Exact `inference.request` capability and matching audience |
| Usage and control | Separate capabilities requiring a session/admin credential; never implied by inference |
| `ConfigSnapshot` / `ClientRoute` wire shape | Preserved until an explicit snapshot/schema phase |
| Group-scoped or multi-domain key | One exact grant per permitted domain/resource/action; no Cartesian product and no descendant expansion |

**Target differences and gaps**

- A client key must never reach usage or control actions even when its user is
  an administrator.
- The key's audience is the prompt-ferry service, not a permission domain.
- Scoped key management needs a schema, snapshot compatibility, management API,
  and revocation propagation phase. Do not silently add scopes to the current
  wire contract.

**Wave C.** Defer scoped-key migration until its own phase plan exists.

### 3.5 stock-factor

**Verified current behavior**

- `admin_data_allows` reads only the `admin_data` permission map: `write`
  allows every method, `read` allows only `GET`/`HEAD`, anything else denies
  (`apps/stock-factor/src/auth.rs`).
- Middleware requires `identity.is_admin` and, for bearer credentials, the
  `admin_data_allows` result. A session bypasses the token map but still needs
  `is_admin`.
- The service introspection client verifies the gateway response binding,
  `no-store`, and credential kind (`auth.rs`).

**Legacy mapping**

| Current | Legacy target mapping |
| --- | --- |
| `is_admin` | Explicit admin-data role assignment; legacy admin exception stays explicit |
| `admin_data: read` | Typed credential grant for the read action |
| `admin_data: write` | Typed credential grants for read plus write actions |
| Session credential | `Attenuation::Unrestricted` |
| Bearer credential | `Attenuation::Grants(...)` |
| Missing or unknown level | Empty/denied grant set, never an implicit grant |

**Target differences and gaps**

- Preserve the current conjunction: role authority AND bearer attenuation.
  Session credentials keep unrestricted attenuation.
- The duplicated function should be deleted only when both factor and import
  migrate through a scoped issue.

**Wave A deferral.** Do not start stock-factor migration in this wave. Its
worktree has no `HEAD` and its files are untracked, so there is no immutable
revision to pin or diff against. It stays on its legacy behaviour until the
repository has a committed baseline; do not initialize, commit, or sweep that
working tree as part of this mapping.

### 3.6 stock-import

**Verified current behavior**

- `crates/stock-import-http/src/identity.rs::admin_data_allows` is byte-for-byte
  equivalent in behavior to stock-factor's function.
- The middleware uses the same `is_admin` plus bearer `admin_data` conjunction
  (`crates/stock-import-http/src/lib.rs`).
- Import handlers additionally use `identity.is_admin` for scoping imported
  data and retry/action authority (`crates/stock-import-http/src/imports/`).

**Legacy mapping and target differences** are identical to stock-factor. The
per-handler `is_admin` scoping must be enumerated as capabilities rather than
replaced blindly. Legacy admin exceptions stay explicit.

**Wave A.** This is the first eligible consumer. Its committed revision
(`f8ed587`) has a verifiable baseline, so it can migrate together with the
gateway contract revision it actually pins. Adoption uses the live-resolved
role path for its introspection-derived identity, preserves the current
`is_admin` plus bearer `admin_data` conjunction as explicit capabilities and
typed grants, and keeps per-handler admin scoping enumerated.

### 3.7 stock-gateway

**Verified current behavior**

- The gateway is the credential authority for Stock account tokens and the
  introspection endpoint.
- `AuthorizationPolicy::allows` is `is_admin || permissions contains exact
  permission`; an administrator matches any permission
  (`crates/stock-gateway-auth/src/permissions.rs`).
- Account token resources and access levels are the 12-resource map described
  in 3.2; admin resources require a live administrator.
- Introspection rejects malformed/duplicate credentials, enforces session versus
  bearer binding, returns `Cache-Control: no-store`, and never falls back from
  a bearer to a cookie (`crates/stock-gateway-service/src/introspection.rs`).

**Legacy mapping**

| Current | Legacy target mapping |
| --- | --- |
| `is_admin || permission` | Explicit admin capability set; legacy admin exceptions remain enumerated. Remove the blanket match only after current authority is mapped. |
| Token resource/access map | Typed credential grants |
| Live-administrator requirement for admin resources | Administrative role assignment plus credential grants |
| Introspection wire contract | Preserved; shared crate does not replace token storage or resolution |
| Audience | Add/validate a service audience separately from resource/domain; gateway remains the credential authority |

**Target differences and gaps**

- The gateway can use the shared crate to validate capability names and typed
  grants, but token issuance, hashing, storage, expiry, and revocation stay in
  the gateway.
- Any change to administrator authority needs user approval.

**Wave A coordination.** Gateway contract changes precede or accompany
stock-import migration. Do not change the snapshot/HTTP contract silently.
Consumers pin different gateway contract revisions (the revisions listed in
section 1); preserve each pinned contract and verify that the fields a consumer
reads are compatible before changing it. Do not assume one shared revision
across the Stock consumers.

### 3.8 gov-info

**Verified current behavior**

- Inbound API routes are public/read-only with no authentication middleware
  (`crates/gov-info-api/src/handlers/`).
- The only credential is an outbound Context69 PAT: `ctx_pat_` personal access
  token, base URL, and group path configured together
  (`crates/gov-info-core/src/config/validate.rs`,
  `crates/gov-info-context69/src/service.rs`).

**Mapping**

- No inbound engine dependency and no new inbound authentication.
- The outbound PAT is a typed credential attenuation scoped to the minimum
  Context69 grants and exact group/domain ids needed for the import flow.
- Validate least-privilege mapping during Wave D; do not add a public API auth
  layer merely to count a consumer.

### 3.9 Light consumers

| Consumer | Verified credential model | Decision |
| --- | --- | --- |
| s3-cleaner | Per-target webhook bearer token checked in constant time; `HEAD /` probe has no auth | No engine dependency; retain static token check. The token is a single-purpose webhook credential, not a role system. |
| stock-operator | Server auth token; live operations use short-lived one-time confirmation tokens and audit state | No engine dependency; retain token and confirmation/lease checks. |
| modern-rtx | Per-connection session token authenticates a client; protocol routes carry application behavior | No engine dependency from this sample; a full route-authority audit would be required before any adoption. |

These are real credentials but not evidence of an RBAC requirement. Do not add
Casbin or a role model to them artificially.

## 4. Migration order

1. **Shared crate delivery (P1).** Freeze the API and tests from
   `authorization-model.md`; deliver an immutable revision or tag. No consumer
   writes.
2. **Wave A.** Context69 adapter, stock-import, and stock-gateway
   credential/capability mapping. Context69 keeps its existing SQL membership
   query as the trusted role source and calls the live-resolved-role entrypoint;
   do not rewrite PR104. stock-import is the first eligible migration because
   it has a committed baseline; stock-factor is deferred until it has one. The
   gateway contract revision each consumer pins is preserved. Duplicate
   `admin_data` interpretation is removed only through scoped issues.
3. **Wave B.** Stock full HTTP/MCP/project migration and desk
   machine/workspace/ceiling migration. Preserve SQL visibility, public/system
   attributes, legacy workspace shell, limits, and leases.
4. **Wave C.** Prompt-ferry inference/control actions and the separately
   planned scoped-key contract, snapshot compatibility, and revocation
   propagation.
5. **Wave D.** gov-info service-credential least-privilege validation and light
   consumer assessment. No new public inbound auth.

Each consumer migration needs its own linked repository issue with an exact
current-to-target capability map, focused regression gates, its own independent
final review, and its own PR. No cross-repo merge, deploy, or automatic token
trust is assumed.

## 5. Dependency pinning and rollout gates

- During local integration, point the consumer at a path or a pinned immutable
  shared-crate revision; never a floating branch.
- After delivery, pin the exact git revision or tag and commit the consumer
  lockfile.
- Pin Casbin exactly at the verified stable `2.20.0` in the shared crate and
  verify its documentation for the selected version.
- Keep every existing token format, route contract, snapshot shape, and
  database schema until a scoped migration phase explicitly changes it.
- Prefer a shadow mode: compute the shared decision alongside the legacy check,
  log only mismatches, then cut over behind a configuration gate.
- Roll back by restoring the legacy check; do not roll back by mutating tokens,
  roles, or data.
- A consumer migration that would broaden or reduce existing authority is
  blocked for an explicit product decision, not resolved by a default.

## 6. Pending product choices

The detailed list is in `authorization-model.md` section 17. The blocking ones
for migration are:

1. Context69 live-facts admission ownership: the core live-resolved-role path
   exists, so the remaining choice is how the consumer guarantees that resolved
   roles come from verified current data. A revisioned snapshot boundary is no
   longer required for these decisions.
2. Context69 maintainer-to-owner delegation restriction (target is stricter
   than current behavior).
3. Enumerated administrator capability sets for Context69, Stock, Stock
   gateway, and prompt-ferry; any effective authority change returns to the
   user. Legacy admin exceptions remain explicit.
4. Stock workspace shell separation from legacy workspace write and the
   resulting token authority change.
5. Exact public-read grants per route, including optional resource ids.
6. Exact-object token ceilings and their token-format representation.
7. Service/audience identifiers and the distinction from permission domains.
8. Prompt-ferry scoped-key schema, snapshot, management API, and revocation
   design.
9. Desk application-scope semantics as subject authority versus an additional
   attenuation layer.
