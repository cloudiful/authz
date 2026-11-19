use std::collections::BTreeSet;

use cloudiful_authz::{
    Action, Attenuation, Authority, Authorizer, AuthorizerConfig, AuthzRequest, Capability,
    CredentialContext, Decision, DenyReason, DomainHierarchy, DomainId, FactsRevision,
    GlobalAssignment, Grant, InitError, PrincipalKind, PrincipalRef, PublicReadGrant,
    ResolvedRoles, ResourceId, ResourceKind, ResourceRef, RoleAssignment, RoleId, RoleSpec,
    ServerContext, ServiceId, Subject,
};

fn domain(value: &str) -> DomainId {
    DomainId::from(value)
}

fn role(id: &str, capabilities: &[(&str, &str)]) -> RoleSpec {
    RoleSpec {
        id: RoleId::from(id),
        capabilities: capabilities
            .iter()
            .map(|(resource, action)| Capability::new(*resource, *action))
            .collect(),
    }
}

fn principal(kind: PrincipalKind, id: &str) -> PrincipalRef {
    PrincipalRef::new(kind, id)
}

fn assignment(principal: PrincipalRef, role: &str, domain_value: &str) -> RoleAssignment {
    RoleAssignment {
        principal,
        role: RoleId::from(role),
        domain: domain(domain_value),
    }
}

fn public_grant(
    domain_value: &str,
    resource: &str,
    id: Option<&str>,
    action: &str,
) -> PublicReadGrant {
    PublicReadGrant {
        domain: domain(domain_value),
        resource: ResourceKind::from(resource),
        resource_id: id.map(ResourceId::from),
        action: Action::from(action),
    }
}

fn config() -> AuthorizerConfig {
    let mut config = AuthorizerConfig::new(
        FactsRevision(7),
        ["tenant:a", "tenant:a/child", "tenant:b", "admin"],
        vec![
            role("viewer", &[("content", "read"), ("content", "list")]),
            role(
                "maintainer",
                &[
                    ("content", "read"),
                    ("content", "list"),
                    ("content", "write"),
                ],
            ),
            role(
                "owner",
                &[
                    ("content", "read"),
                    ("content", "list"),
                    ("content", "write"),
                    ("membership", "grant"),
                    ("domain", "manage"),
                ],
            ),
            role("admin", &[("admin", "read"), ("admin", "write")]),
            role("machine", &[("job", "run")]),
        ],
    );
    config.assignments = vec![
        assignment(
            principal(PrincipalKind::Human, "42"),
            "maintainer",
            "tenant:a",
        ),
        assignment(principal(PrincipalKind::Human, "42"), "viewer", "tenant:b"),
        assignment(
            principal(PrincipalKind::Service, "7"),
            "machine",
            "tenant:a",
        ),
        assignment(principal(PrincipalKind::Human, "1"), "admin", "admin"),
    ];
    config.hierarchy = DomainHierarchy {
        edges: vec![(domain("tenant:a/child"), domain("tenant:a"))],
    };
    config.public_read = BTreeSet::from([public_grant("tenant:a", "content", None, "read")]);
    config
}

fn dynamic_config() -> AuthorizerConfig {
    AuthorizerConfig::new(
        FactsRevision(11),
        ["service"],
        vec![
            role("viewer", &[("content", "read"), ("content", "list")]),
            role(
                "maintainer",
                &[
                    ("content", "read"),
                    ("content", "list"),
                    ("content", "write"),
                ],
            ),
            role("owner", &[("membership", "grant")]),
            role("admin", &[("admin", "read")]),
        ],
    )
}

fn request(domain_value: &str, resource: &str, action: &str) -> AuthzRequest {
    AuthzRequest {
        resource: ResourceRef {
            kind: ResourceKind::from(resource),
            id: None,
            domain: domain(domain_value),
        },
        action: Action::from(action),
        audience: ServiceId::from("svc"),
        credential: None,
        server: None,
    }
}

fn snapshot(subject: Subject, domain_value: &str, revision: u64) -> Authority<'static> {
    Authority::Snapshot {
        subject,
        domain: domain(domain_value),
        facts_revision: FactsRevision(revision),
    }
}

fn snapshot_human(id: &str, domain_value: &str, revision: u64) -> Authority<'static> {
    snapshot(
        Subject::Principal(principal(PrincipalKind::Human, id)),
        domain_value,
        revision,
    )
}

fn human(id: &str, domain_value: &str) -> Authority<'static> {
    snapshot_human(id, domain_value, 7)
}

fn public_read(domain_value: &str) -> Authority<'static> {
    snapshot(Subject::PublicRead, domain_value, 7)
}

fn grant(domain_value: &str, resource: &str, id: Option<&str>, action: &str) -> Grant {
    Grant {
        domain: domain(domain_value),
        resource: ResourceKind::from(resource),
        resource_id: id.map(ResourceId::from),
        action: Action::from(action),
    }
}

fn grants(entries: impl IntoIterator<Item = Grant>) -> Attenuation {
    Attenuation::grants(entries)
}

fn resolved(principal: PrincipalRef, domain_value: &str, roles: &[&str]) -> ResolvedRoles {
    ResolvedRoles::new(principal, domain_value, roles.iter().copied())
}

fn registered(resolved: &ResolvedRoles) -> Authority<'_> {
    Authority::Registered(resolved)
}

fn resolved_authority(resolved: &ResolvedRoles) -> Authority<'_> {
    Authority::Resolved(resolved)
}

async fn authorizer_with(config: AuthorizerConfig) -> Authorizer {
    Authorizer::new(config).await.expect("authorizer builds")
}

#[tokio::test]
async fn domain_assignment_is_isolated_and_parent_role_inherits_downward() {
    let authorizer = authorizer_with(config()).await;

    assert!(
        authorizer
            .authorize(
                &request("tenant:a", "content", "write"),
                human("42", "tenant:a")
            )
            .is_allowed()
    );
    assert!(
        authorizer
            .authorize(
                &request("tenant:a/child", "content", "write"),
                human("42", "tenant:a/child")
            )
            .is_allowed()
    );
    assert_eq!(
        authorizer.authorize(
            &request("tenant:b", "content", "write"),
            human("42", "tenant:b")
        ),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );
}

#[tokio::test]
async fn rebuilt_snapshot_revokes_a_removed_assignment() {
    let first = authorizer_with(config()).await;
    assert!(
        first
            .authorize(
                &request("tenant:a/child", "content", "write"),
                snapshot_human("42", "tenant:a/child", 7)
            )
            .is_allowed()
    );

    let mut next = config();
    next.facts_revision = FactsRevision(8);
    next.assignments
        .retain(|assignment| assignment.principal != principal(PrincipalKind::Human, "42"));
    let second = authorizer_with(next).await;

    assert_eq!(
        second.authorize(
            &request("tenant:a/child", "content", "write"),
            snapshot_human("42", "tenant:a/child", 8)
        ),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );
}

#[tokio::test]
async fn exact_capability_and_unknown_universe_are_enforced() {
    let authorizer = authorizer_with(config()).await;

    assert!(
        authorizer
            .authorize(
                &request("tenant:a", "content", "read"),
                human("42", "tenant:a")
            )
            .is_allowed()
    );
    assert_eq!(
        authorizer.authorize(
            &request("tenant:a", "content", "delete"),
            human("42", "tenant:a")
        ),
        Decision::Deny(DenyReason::UnknownAction)
    );
    assert_eq!(
        authorizer.authorize(
            &request("tenant:a", "unknown", "read"),
            human("42", "tenant:a")
        ),
        Decision::Deny(DenyReason::UnknownResource)
    );
}

#[tokio::test]
async fn principal_kind_and_role_name_collisions_do_not_grant_authority() {
    let authorizer = authorizer_with(config()).await;

    let service_with_human_id = snapshot(
        Subject::Principal(principal(PrincipalKind::Service, "42")),
        "tenant:a",
        7,
    );
    assert_eq!(
        authorizer.authorize(
            &request("tenant:a", "content", "write"),
            service_with_human_id
        ),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );

    let principal_named_like_a_role = snapshot(
        Subject::Principal(principal(PrincipalKind::Human, "maintainer")),
        "tenant:a",
        7,
    );
    assert_eq!(
        authorizer.authorize(
            &request("tenant:a", "content", "write"),
            principal_named_like_a_role
        ),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );
}

#[tokio::test]
async fn unrestricted_and_empty_credential_and_server_attenuation_differ() {
    let authorizer = authorizer_with(config()).await;
    let mut credential_request = request("tenant:b", "content", "read");

    credential_request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::from("svc"),
        grants: Attenuation::unrestricted(),
    });
    assert!(
        authorizer
            .authorize(&credential_request, human("42", "tenant:b"))
            .is_allowed()
    );

    credential_request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::from("svc"),
        grants: Attenuation::deny_all(),
    });
    assert_eq!(
        authorizer.authorize(&credential_request, human("42", "tenant:b")),
        Decision::Deny(DenyReason::CredentialGrantMissing)
    );

    let mut server_base = request("tenant:b", "content", "read");
    server_base.server = Some(ServerContext {
        grants: Attenuation::unrestricted(),
    });
    assert!(
        authorizer
            .authorize(&server_base, human("42", "tenant:b"))
            .is_allowed()
    );

    server_base.server = Some(ServerContext {
        grants: Attenuation::deny_all(),
    });
    assert_eq!(
        authorizer.authorize(&server_base, human("42", "tenant:b")),
        Decision::Deny(DenyReason::ServerGrantMissing)
    );
}

#[tokio::test]
async fn multi_domain_grants_do_not_form_a_cartesian_product() {
    let mut config = config();
    config.assignments.push(assignment(
        principal(PrincipalKind::Human, "43"),
        "maintainer",
        "tenant:a",
    ));
    config.assignments.push(assignment(
        principal(PrincipalKind::Human, "43"),
        "maintainer",
        "tenant:b",
    ));
    let authorizer = authorizer_with(config).await;

    let mut request = request("tenant:a", "content", "write");
    request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "43"),
        audience: ServiceId::from("svc"),
        grants: grants([
            grant("tenant:a", "content", None, "read"),
            grant("tenant:b", "content", None, "write"),
        ]),
    });
    assert_eq!(
        authorizer.authorize(&request, human("43", "tenant:a")),
        Decision::Deny(DenyReason::CredentialGrantMissing)
    );

    request.resource.domain = domain("tenant:b");
    assert!(
        authorizer
            .authorize(&request, human("43", "tenant:b"))
            .is_allowed()
    );
}

#[tokio::test]
async fn exact_resource_grants_require_the_same_exact_id() {
    let authorizer = authorizer_with(config()).await;

    let mut request = request("tenant:b", "content", "read");
    request.resource.id = Some(ResourceId::from("doc-1"));
    request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::from("svc"),
        grants: grants([grant("tenant:b", "content", Some("doc-1"), "read")]),
    });
    assert!(
        authorizer
            .authorize(&request, human("42", "tenant:b"))
            .is_allowed()
    );

    request.resource.id = Some(ResourceId::from("doc-2"));
    assert_eq!(
        authorizer.authorize(&request, human("42", "tenant:b")),
        Decision::Deny(DenyReason::CredentialGrantMissing)
    );

    request.resource.id = None;
    assert_eq!(
        authorizer.authorize(&request, human("42", "tenant:b")),
        Decision::Deny(DenyReason::CredentialGrantMissing)
    );

    request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::from("svc"),
        grants: grants([grant("tenant:b", "content", None, "read")]),
    });
    assert!(
        authorizer
            .authorize(&request, human("42", "tenant:b"))
            .is_allowed()
    );
}

#[tokio::test]
async fn credential_principal_and_audience_mismatches_deny() {
    let authorizer = authorizer_with(config()).await;
    let mut request = request("tenant:b", "content", "read");
    request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "43"),
        audience: ServiceId::from("svc"),
        grants: Attenuation::unrestricted(),
    });
    assert_eq!(
        authorizer.authorize(&request, human("42", "tenant:b")),
        Decision::Deny(DenyReason::CredentialPrincipalMismatch)
    );

    request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Service, "42"),
        audience: ServiceId::from("svc"),
        grants: Attenuation::unrestricted(),
    });
    assert_eq!(
        authorizer.authorize(&request, human("42", "tenant:b")),
        Decision::Deny(DenyReason::CredentialPrincipalMismatch)
    );

    request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::from("other"),
        grants: Attenuation::unrestricted(),
    });
    assert_eq!(
        authorizer.authorize(&request, human("42", "tenant:b")),
        Decision::Deny(DenyReason::CredentialAudienceMismatch)
    );
}

#[tokio::test]
async fn public_read_is_limited_and_still_attenuated() {
    let authorizer = authorizer_with(config()).await;
    let mut read_request = request("tenant:a", "content", "read");
    assert!(
        authorizer
            .authorize(&read_request, public_read("tenant:a"))
            .is_allowed()
    );

    read_request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "unknown"),
        audience: ServiceId::from("svc"),
        grants: Attenuation::deny_all(),
    });
    assert_eq!(
        authorizer.authorize(&read_request, public_read("tenant:a")),
        Decision::Deny(DenyReason::CredentialGrantMissing)
    );

    read_request.credential = None;
    read_request.server = Some(ServerContext {
        grants: Attenuation::deny_all(),
    });
    assert_eq!(
        authorizer.authorize(&read_request, public_read("tenant:a")),
        Decision::Deny(DenyReason::ServerGrantMissing)
    );

    read_request.server = None;
    let write = request("tenant:a", "content", "write");
    assert_eq!(
        authorizer.authorize(&write, public_read("tenant:a")),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );
}

#[tokio::test]
async fn unknown_domains_and_cross_domain_resources_deny() {
    let authorizer = authorizer_with(config()).await;

    let unknown = request("tenant:missing", "content", "read");
    assert_eq!(
        authorizer.authorize(&unknown, human("42", "tenant:missing")),
        Decision::Deny(DenyReason::UnknownDomain)
    );

    let mut cross_domain = request("tenant:a", "content", "read");
    cross_domain.resource.domain = domain("tenant:b");
    assert_eq!(
        authorizer.authorize(&cross_domain, human("42", "tenant:a")),
        Decision::Deny(DenyReason::CrossDomainResource)
    );
}

#[tokio::test]
async fn public_read_exact_id_grants_require_the_same_id() {
    let mut config = config();
    config.public_read =
        BTreeSet::from([public_grant("tenant:a", "content", Some("doc-1"), "read")]);
    let authorizer = authorizer_with(config).await;

    let mut request = request("tenant:a", "content", "read");
    request.resource.id = Some(ResourceId::from("doc-1"));
    assert!(
        authorizer
            .authorize(&request, public_read("tenant:a"))
            .is_allowed()
    );

    request.resource.id = Some(ResourceId::from("doc-2"));
    assert_eq!(
        authorizer.authorize(&request, public_read("tenant:a")),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );

    request.resource.id = None;
    assert_eq!(
        authorizer.authorize(&request, public_read("tenant:a")),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );
}

#[tokio::test]
async fn malformed_audiences_deny_in_principal_and_public_modes() {
    let authorizer = authorizer_with(config()).await;

    let mut principal_empty = request("tenant:a", "content", "read");
    principal_empty.audience = ServiceId::from("");
    assert_eq!(
        authorizer.authorize(&principal_empty, human("42", "tenant:a")),
        Decision::Deny(DenyReason::InvalidAudience)
    );

    let mut principal_control = request("tenant:a", "content", "read");
    principal_control.audience = ServiceId::from("svc\n");
    assert_eq!(
        authorizer.authorize(&principal_control, human("42", "tenant:a")),
        Decision::Deny(DenyReason::InvalidAudience)
    );

    let mut principal_wildcard = request("tenant:a", "content", "read");
    principal_wildcard.audience = ServiceId::from("*");
    assert_eq!(
        authorizer.authorize(&principal_wildcard, human("42", "tenant:a")),
        Decision::Deny(DenyReason::InvalidAudience)
    );

    let mut credential_empty = request("tenant:a", "content", "read");
    credential_empty.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::from(""),
        grants: Attenuation::unrestricted(),
    });
    assert_eq!(
        authorizer.authorize(&credential_empty, human("42", "tenant:a")),
        Decision::Deny(DenyReason::InvalidAudience)
    );

    let mut public_empty = request("tenant:a", "content", "read");
    public_empty.audience = ServiceId::from("");
    assert_eq!(
        authorizer.authorize(&public_empty, public_read("tenant:a")),
        Decision::Deny(DenyReason::InvalidAudience)
    );

    let mut public_credential_wildcard = request("tenant:a", "content", "read");
    public_credential_wildcard.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::from("*"),
        grants: Attenuation::unrestricted(),
    });
    assert_eq!(
        authorizer.authorize(&public_credential_wildcard, public_read("tenant:a")),
        Decision::Deny(DenyReason::InvalidAudience)
    );
}

#[tokio::test]
async fn stale_facts_revision_denies_before_authority() {
    let authorizer = authorizer_with(config()).await;
    let request = request("tenant:a", "content", "read");
    assert_eq!(
        authorizer.authorize(&request, snapshot_human("42", "tenant:a", 6)),
        Decision::Deny(DenyReason::StaleFacts)
    );
    assert_eq!(authorizer.facts_revision(), FactsRevision(7));
}

#[tokio::test]
async fn admin_has_no_wildcard_and_application_has_no_implicit_role() {
    let authorizer = authorizer_with(config()).await;
    let admin = request("admin", "admin", "read");
    assert!(
        authorizer
            .authorize(&admin, human("1", "admin"))
            .is_allowed()
    );

    let admin_delete = request("admin", "admin", "delete");
    assert_eq!(
        authorizer.authorize(&admin_delete, human("1", "admin")),
        Decision::Deny(DenyReason::UnknownAction)
    );

    let application = snapshot(
        Subject::Principal(principal(PrincipalKind::Application, "app")),
        "tenant:a",
        7,
    );
    assert_eq!(
        authorizer.authorize(&request("tenant:a", "job", "run"), application),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );
}

#[tokio::test]
async fn duplicate_assignments_are_deduplicated() {
    let mut config = config();
    let duplicate = assignment(
        principal(PrincipalKind::Human, "42"),
        "maintainer",
        "tenant:a",
    );
    config.assignments.push(duplicate);
    let authorizer = authorizer_with(config).await;
    assert!(
        authorizer
            .authorize(
                &request("tenant:a", "content", "write"),
                human("42", "tenant:a")
            )
            .is_allowed()
    );
}

#[tokio::test]
async fn live_roles_allow_without_snapshot_assignment_or_matching_revision() {
    let authorizer = authorizer_with(config()).await;
    let request = request("tenant:a", "content", "read");
    let facts = resolved(
        principal(PrincipalKind::Human, "99"),
        "tenant:a",
        &["viewer"],
    );

    assert!(
        authorizer
            .authorize(&request, registered(&facts))
            .is_allowed()
    );
}

#[tokio::test]
async fn live_roles_bind_to_the_authority_principal_and_request_domain() {
    let authorizer = authorizer_with(config()).await;
    let request = request("tenant:a", "content", "read");

    let malformed_principal =
        resolved(principal(PrincipalKind::Human, ""), "tenant:a", &["viewer"]);
    assert_eq!(
        authorizer.authorize(&request, registered(&malformed_principal)),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );

    let group_b_facts = resolved(
        principal(PrincipalKind::Human, "42"),
        "tenant:b",
        &["viewer"],
    );
    assert_eq!(
        authorizer.authorize(&request, registered(&group_b_facts)),
        Decision::Deny(DenyReason::CrossDomainResource)
    );
}

#[tokio::test]
async fn live_unknown_roles_and_empty_roles_deny_the_request() {
    let authorizer = authorizer_with(config()).await;
    let request = request("tenant:a", "content", "read");

    let unknown_role = resolved(
        principal(PrincipalKind::Human, "42"),
        "tenant:a",
        &["viewer", "missing"],
    );
    assert_eq!(
        authorizer.authorize(&request, registered(&unknown_role)),
        Decision::Deny(DenyReason::UnknownRole)
    );

    let empty = resolved(principal(PrincipalKind::Human, "42"), "tenant:a", &[]);
    assert_eq!(
        authorizer.authorize(&request, registered(&empty)),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );
}

#[tokio::test]
async fn live_roles_do_not_fall_back_to_or_union_snapshot_assignments() {
    let authorizer = authorizer_with(config()).await;
    let mut request = request("tenant:a", "content", "write");

    let no_live_roles = resolved(principal(PrincipalKind::Human, "42"), "tenant:a", &[]);
    assert_eq!(
        authorizer.authorize(&request, registered(&no_live_roles)),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );

    let only_viewer = resolved(
        principal(PrincipalKind::Human, "42"),
        "tenant:a",
        &["viewer"],
    );
    assert_eq!(
        authorizer.authorize(&request, registered(&only_viewer)),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );
    assert!(
        authorizer
            .authorize(&request, human("42", "tenant:a"))
            .is_allowed()
    );

    request.action = Action::from("read");
    assert!(
        authorizer
            .authorize(&request, registered(&only_viewer))
            .is_allowed()
    );
}

#[tokio::test]
async fn live_role_removal_denies_on_the_next_request_without_rebuild() {
    let authorizer = authorizer_with(config()).await;
    let request = request("admin", "admin", "read");
    let with_admin = resolved(principal(PrincipalKind::Human, "1"), "admin", &["admin"]);
    let without_admin = resolved(principal(PrincipalKind::Human, "1"), "admin", &[]);

    assert!(
        authorizer
            .authorize(&request, registered(&with_admin))
            .is_allowed()
    );
    assert_eq!(
        authorizer.authorize(&request, registered(&without_admin)),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );
}

#[tokio::test]
async fn live_admin_is_an_ordinary_explicit_role_with_no_wildcard() {
    let authorizer = authorizer_with(config()).await;
    let admin_read = request("tenant:a", "admin", "read");
    let admin_delete = request("tenant:a", "admin", "delete");
    let facts = resolved(principal(PrincipalKind::Human, "1"), "tenant:a", &["admin"]);

    assert!(
        authorizer
            .authorize(&admin_read, registered(&facts))
            .is_allowed()
    );
    assert_eq!(
        authorizer.authorize(&admin_delete, registered(&facts)),
        Decision::Deny(DenyReason::UnknownAction)
    );

    let content_write = request("tenant:a", "content", "write");
    assert_eq!(
        authorizer.authorize(&content_write, registered(&facts)),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );
}

#[tokio::test]
async fn live_authority_is_principal_only_and_role_like_ids_do_not_self_authorize() {
    let authorizer = authorizer_with(config()).await;
    let role_like_request = request("tenant:a", "admin", "read");
    let empty = resolved(principal(PrincipalKind::Human, "admin"), "tenant:a", &[]);
    assert_eq!(
        authorizer.authorize(&role_like_request, registered(&empty)),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );

    let viewer_like_request = request("tenant:a", "content", "read");
    let no_roles = resolved(principal(PrincipalKind::Human, "viewer"), "tenant:a", &[]);
    assert_eq!(
        authorizer.authorize(&viewer_like_request, registered(&no_roles)),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );
}

#[tokio::test]
async fn live_path_keeps_audience_credential_and_server_checks() {
    let authorizer = authorizer_with(config()).await;
    let mut request = request("tenant:b", "content", "read");
    let facts = resolved(
        principal(PrincipalKind::Human, "42"),
        "tenant:b",
        &["viewer"],
    );

    request.audience = ServiceId::from("");
    assert_eq!(
        authorizer.authorize(&request, registered(&facts)),
        Decision::Deny(DenyReason::InvalidAudience)
    );

    request.audience = ServiceId::from("svc");
    request.resource.domain = domain("tenant:a");
    assert_eq!(
        authorizer.authorize(&request, registered(&facts)),
        Decision::Deny(DenyReason::CrossDomainResource)
    );

    request.resource.domain = domain("tenant:b");
    request.action = Action::from("delete");
    assert_eq!(
        authorizer.authorize(&request, registered(&facts)),
        Decision::Deny(DenyReason::UnknownAction)
    );

    request.action = Action::from("read");
    request.resource.id = Some(ResourceId::from("doc-1"));
    request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::from("svc"),
        grants: grants([grant("tenant:b", "content", Some("doc-1"), "read")]),
    });
    assert!(
        authorizer
            .authorize(&request, registered(&facts))
            .is_allowed()
    );

    request.resource.id = Some(ResourceId::from("doc-2"));
    assert_eq!(
        authorizer.authorize(&request, registered(&facts)),
        Decision::Deny(DenyReason::CredentialGrantMissing)
    );

    request.resource.id = None;
    request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::from("svc"),
        grants: Attenuation::unrestricted(),
    });
    request.server = Some(ServerContext {
        grants: Attenuation::deny_all(),
    });
    assert_eq!(
        authorizer.authorize(&request, registered(&facts)),
        Decision::Deny(DenyReason::ServerGrantMissing)
    );
}

#[tokio::test]
async fn live_path_keeps_empty_and_multi_domain_credential_restrictions() {
    let authorizer = authorizer_with(config()).await;
    let mut request = request("tenant:a", "content", "write");
    let facts = resolved(
        principal(PrincipalKind::Human, "43"),
        "tenant:a",
        &["maintainer"],
    );

    request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "43"),
        audience: ServiceId::from("svc"),
        grants: Attenuation::deny_all(),
    });
    assert_eq!(
        authorizer.authorize(&request, registered(&facts)),
        Decision::Deny(DenyReason::CredentialGrantMissing)
    );

    request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "43"),
        audience: ServiceId::from("svc"),
        grants: grants([
            grant("tenant:a", "content", None, "read"),
            grant("tenant:b", "content", None, "write"),
        ]),
    });
    assert_eq!(
        authorizer.authorize(&request, registered(&facts)),
        Decision::Deny(DenyReason::CredentialGrantMissing)
    );

    request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "44"),
        audience: ServiceId::from("svc"),
        grants: Attenuation::unrestricted(),
    });
    assert_eq!(
        authorizer.authorize(&request, registered(&facts)),
        Decision::Deny(DenyReason::CredentialPrincipalMismatch)
    );
}

#[tokio::test]
async fn resolved_domain_allows_current_group_domains_and_registered_apis_deny_unknown_domain() {
    let authorizer = authorizer_with(dynamic_config()).await;

    for group in ["group:alpha", "group:beta"] {
        let request = request(group, "content", "read");
        let facts = resolved(principal(PrincipalKind::Human, "42"), group, &["viewer"]);

        assert!(
            authorizer
                .authorize(&request, resolved_authority(&facts))
                .is_allowed()
        );
        assert_eq!(
            authorizer.authorize(&request, snapshot_human("42", group, 11)),
            Decision::Deny(DenyReason::UnknownDomain)
        );
        assert_eq!(
            authorizer.authorize(&request, registered(&facts)),
            Decision::Deny(DenyReason::UnknownDomain)
        );
    }
}

#[tokio::test]
async fn resolved_domain_binds_the_authority_principal_and_request_domain() {
    let authorizer = authorizer_with(dynamic_config()).await;
    let base_request = request("group:alpha", "content", "read");

    let malformed_principal = resolved(
        principal(PrincipalKind::Human, ""),
        "group:alpha",
        &["viewer"],
    );
    assert_eq!(
        authorizer.authorize(&base_request, resolved_authority(&malformed_principal)),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );

    let group_a_facts = resolved(
        principal(PrincipalKind::Human, "42"),
        "group:alpha",
        &["viewer"],
    );
    let group_b_request = request("group:beta", "content", "read");
    assert_eq!(
        authorizer.authorize(&group_b_request, resolved_authority(&group_a_facts)),
        Decision::Deny(DenyReason::CrossDomainResource)
    );
}

#[tokio::test]
async fn resolved_domain_rejects_malformed_domains_and_cross_domain_resources() {
    let authorizer = authorizer_with(dynamic_config()).await;
    let facts = resolved(
        principal(PrincipalKind::Human, "42"),
        "group:alpha",
        &["viewer"],
    );

    for malformed in ["", "group:\n", "*"] {
        let mut request = request("group:alpha", "content", "read");
        request.resource.domain = domain(malformed);
        assert_eq!(
            authorizer.authorize(&request, resolved_authority(&facts)),
            Decision::Deny(DenyReason::InvalidDomain)
        );
    }

    let request = request("group:alpha", "content", "read");
    let malformed_facts = resolved(principal(PrincipalKind::Human, "42"), "", &["viewer"]);
    assert_eq!(
        authorizer.authorize(&request, resolved_authority(&malformed_facts)),
        Decision::Deny(DenyReason::InvalidDomain)
    );

    let mut cross_domain = request;
    cross_domain.resource.domain = domain("group:beta");
    assert_eq!(
        authorizer.authorize(&cross_domain, resolved_authority(&facts)),
        Decision::Deny(DenyReason::CrossDomainResource)
    );
}

#[tokio::test]
async fn resolved_domain_rejects_empty_unknown_and_snapshot_only_authority() {
    let authorizer = authorizer_with(dynamic_config()).await;

    let live_request = request("group:alpha", "content", "read");
    let unknown = resolved(
        principal(PrincipalKind::Human, "42"),
        "group:alpha",
        &["viewer", "missing"],
    );
    assert_eq!(
        authorizer.authorize(&live_request, resolved_authority(&unknown)),
        Decision::Deny(DenyReason::UnknownRole)
    );

    let empty = resolved(principal(PrincipalKind::Human, "42"), "group:alpha", &[]);
    assert_eq!(
        authorizer.authorize(&live_request, resolved_authority(&empty)),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );

    let snapshot = authorizer_with(config()).await;
    let registered_request = request("tenant:a", "content", "write");
    assert!(
        snapshot
            .authorize(&registered_request, human("42", "tenant:a"))
            .is_allowed()
    );
    let no_live_roles = resolved(principal(PrincipalKind::Human, "42"), "tenant:a", &[]);
    assert_eq!(
        snapshot.authorize(&registered_request, resolved_authority(&no_live_roles)),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );
}

#[tokio::test]
async fn resolved_domain_exact_group_grants_do_not_expand_to_children_or_siblings() {
    let authorizer = authorizer_with(dynamic_config()).await;

    let mut alpha_request = request("group:alpha", "content", "read");
    alpha_request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::from("svc"),
        grants: grants([grant("group:alpha", "content", None, "read")]),
    });
    let alpha_facts = resolved(
        principal(PrincipalKind::Human, "42"),
        "group:alpha",
        &["viewer"],
    );
    assert!(
        authorizer
            .authorize(&alpha_request, resolved_authority(&alpha_facts))
            .is_allowed()
    );

    for other in ["group:alpha/child", "group:beta"] {
        let mut other_request = request(other, "content", "read");
        other_request.credential = alpha_request.credential.clone();
        let other_facts = resolved(principal(PrincipalKind::Human, "42"), other, &["viewer"]);
        assert_eq!(
            authorizer.authorize(&other_request, resolved_authority(&other_facts)),
            Decision::Deny(DenyReason::CredentialGrantMissing)
        );
    }
}

#[tokio::test]
async fn resolved_domain_preserves_empty_credential_and_server_ceilings() {
    let authorizer = authorizer_with(dynamic_config()).await;
    let request = request("group:alpha", "content", "read");
    let facts = resolved(
        principal(PrincipalKind::Human, "42"),
        "group:alpha",
        &["viewer"],
    );

    assert!(
        authorizer
            .authorize(&request, resolved_authority(&facts))
            .is_allowed()
    );

    let mut empty_credential = request.clone();
    empty_credential.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::from("svc"),
        grants: Attenuation::deny_all(),
    });
    assert_eq!(
        authorizer.authorize(&empty_credential, resolved_authority(&facts)),
        Decision::Deny(DenyReason::CredentialGrantMissing)
    );

    let mut empty_server = request.clone();
    empty_server.server = Some(ServerContext {
        grants: Attenuation::deny_all(),
    });
    assert_eq!(
        authorizer.authorize(&empty_server, resolved_authority(&facts)),
        Decision::Deny(DenyReason::ServerGrantMissing)
    );

    let mut wrong_credential_principal = request.clone();
    wrong_credential_principal.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "43"),
        audience: ServiceId::from("svc"),
        grants: Attenuation::unrestricted(),
    });
    assert_eq!(
        authorizer.authorize(&wrong_credential_principal, resolved_authority(&facts)),
        Decision::Deny(DenyReason::CredentialPrincipalMismatch)
    );

    let mut wrong_credential_audience = request;
    wrong_credential_audience.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::from("other"),
        grants: Attenuation::unrestricted(),
    });
    assert_eq!(
        authorizer.authorize(&wrong_credential_audience, resolved_authority(&facts)),
        Decision::Deny(DenyReason::CredentialAudienceMismatch)
    );
}

#[tokio::test]
async fn resolved_domain_preserves_scoped_tuple_and_exact_object_denials() {
    let authorizer = authorizer_with(dynamic_config()).await;
    let facts = resolved(
        principal(PrincipalKind::Human, "42"),
        "group:alpha",
        &["maintainer"],
    );

    let mut request = request("group:alpha", "content", "write");
    request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::from("svc"),
        grants: grants([
            grant("group:alpha", "content", None, "read"),
            grant("group:beta", "content", None, "write"),
        ]),
    });
    assert_eq!(
        authorizer.authorize(&request, resolved_authority(&facts)),
        Decision::Deny(DenyReason::CredentialGrantMissing)
    );

    request.action = Action::from("read");
    request.resource.id = Some(ResourceId::from("doc-2"));
    request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::from("svc"),
        grants: grants([grant("group:alpha", "content", Some("doc-1"), "read")]),
    });
    assert_eq!(
        authorizer.authorize(&request, resolved_authority(&facts)),
        Decision::Deny(DenyReason::CredentialGrantMissing)
    );

    request.resource.id = Some(ResourceId::from("doc-1"));
    assert!(
        authorizer
            .authorize(&request, resolved_authority(&facts))
            .is_allowed()
    );
}

#[tokio::test]
async fn resolved_domain_still_rejects_unknown_universe_and_malformed_audiences() {
    let authorizer = authorizer_with(dynamic_config()).await;
    let facts = resolved(
        principal(PrincipalKind::Human, "42"),
        "group:alpha",
        &["viewer"],
    );

    let mut invalid_audience = request("group:alpha", "content", "read");
    invalid_audience.audience = ServiceId::from("");
    assert_eq!(
        authorizer.authorize(&invalid_audience, resolved_authority(&facts)),
        Decision::Deny(DenyReason::InvalidAudience)
    );

    let mut invalid_credential_audience = request("group:alpha", "content", "read");
    invalid_credential_audience.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::from("*"),
        grants: Attenuation::unrestricted(),
    });
    assert_eq!(
        authorizer.authorize(&invalid_credential_audience, resolved_authority(&facts)),
        Decision::Deny(DenyReason::InvalidAudience)
    );

    assert_eq!(
        authorizer.authorize(
            &request("group:alpha", "unknown", "read"),
            resolved_authority(&facts)
        ),
        Decision::Deny(DenyReason::UnknownResource)
    );
    assert_eq!(
        authorizer.authorize(
            &request("group:alpha", "content", "delete"),
            resolved_authority(&facts)
        ),
        Decision::Deny(DenyReason::UnknownAction)
    );

    let mut invalid_resource_id = request("group:alpha", "content", "read");
    invalid_resource_id.resource.id = Some(ResourceId::from(""));
    assert_eq!(
        authorizer.authorize(&invalid_resource_id, resolved_authority(&facts)),
        Decision::Deny(DenyReason::UnknownResource)
    );
}

#[tokio::test]
async fn construction_rejects_invalid_references_and_cycles() {
    let mut duplicate_role = config();
    duplicate_role
        .roles
        .push(role("viewer", &[("content", "read")]));
    assert!(matches!(
        Authorizer::new(duplicate_role).await,
        Err(InitError::DuplicateRole(role)) if role == RoleId::from("viewer")
    ));

    let mut unknown_role = config();
    unknown_role.assignments.push(assignment(
        principal(PrincipalKind::Human, "9"),
        "missing",
        "tenant:a",
    ));
    assert!(matches!(
        Authorizer::new(unknown_role).await,
        Err(InitError::UnknownRole(role)) if role == RoleId::from("missing")
    ));

    let mut unknown_domain = config();
    unknown_domain.assignments.push(assignment(
        principal(PrincipalKind::Human, "9"),
        "viewer",
        "missing",
    ));
    assert!(matches!(
        Authorizer::new(unknown_domain).await,
        Err(InitError::UnknownDomain(domain)) if domain == DomainId::from("missing")
    ));

    let mut cycle = config();
    cycle
        .hierarchy
        .edges
        .push((domain("tenant:a"), domain("tenant:a/child")));
    assert!(matches!(
        Authorizer::new(cycle).await,
        Err(InitError::HierarchyCycle)
    ));

    let mut public_domain = config();
    public_domain.public_read = BTreeSet::from([public_grant("missing", "content", None, "read")]);
    assert!(matches!(
        Authorizer::new(public_domain).await,
        Err(InitError::InvalidPublicReadGrant)
    ));

    let mut empty_role = config();
    empty_role.roles.push(role("", &[("content", "read")]));
    assert!(matches!(
        Authorizer::new(empty_role).await,
        Err(InitError::InvalidIdentifier(_))
    ));

    let mut duplicate_domain = config();
    duplicate_domain.domains.push(domain("tenant:a"));
    assert!(matches!(
        Authorizer::new(duplicate_domain).await,
        Err(InitError::DuplicateDomain(domain)) if domain == DomainId::from("tenant:a")
    ));
}

#[tokio::test]
async fn global_assignment_applies_in_each_registered_domain() {
    let mut config = config();
    config.global_assignments.push(GlobalAssignment {
        principal: principal(PrincipalKind::Human, "88"),
        role: RoleId::from("viewer"),
    });
    let authorizer = authorizer_with(config).await;
    assert!(
        authorizer
            .authorize(
                &request("tenant:a", "content", "read"),
                human("88", "tenant:a")
            )
            .is_allowed()
    );
    assert!(
        authorizer
            .authorize(
                &request("tenant:b", "content", "read"),
                human("88", "tenant:b")
            )
            .is_allowed()
    );
}

#[tokio::test]
async fn role_capabilities_are_exposed_without_wildcards() {
    let authorizer = authorizer_with(config()).await;
    let capabilities = authorizer
        .role_capabilities(&RoleId::from("admin"))
        .expect("admin role exists");
    assert!(capabilities.contains(&Capability::new("admin", "read")));
    assert!(!capabilities.contains(&Capability::new("admin", "delete")));
}

#[tokio::test]
async fn exact_id_grant_helper_builds_the_exact_tuple() {
    let authorizer = authorizer_with(config()).await;
    let mut request = request("tenant:b", "content", "read");
    request.resource.id = Some(ResourceId::from("doc-1"));
    request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::from("svc"),
        grants: Attenuation::grants([
            Grant::new("tenant:b", "content", "read").with_resource_id("doc-1")
        ]),
    });
    assert!(
        authorizer
            .authorize(&request, human("42", "tenant:b"))
            .is_allowed()
    );

    request.resource.id = Some(ResourceId::from("doc-2"));
    assert_eq!(
        authorizer.authorize(&request, human("42", "tenant:b")),
        Decision::Deny(DenyReason::CredentialGrantMissing)
    );
}

#[tokio::test]
async fn config_constructor_starts_from_empty_optional_sections() {
    let config = AuthorizerConfig::new(
        FactsRevision(3),
        ["docs"],
        [role("viewer", &[("page", "read")])],
    );
    assert_eq!(config.facts_revision, FactsRevision(3));
    assert!(config.assignments.is_empty());
    assert!(config.global_assignments.is_empty());
    assert!(config.hierarchy.edges.is_empty());
    assert!(config.public_read.is_empty());

    let authorizer = authorizer_with(config).await;
    let request = request("docs", "page", "read");
    assert_eq!(
        authorizer.authorize(&request, snapshot_human("42", "docs", 3)),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );

    let facts = resolved(principal(PrincipalKind::Human, "42"), "docs", &["viewer"]);
    assert!(
        authorizer
            .authorize(&request, registered(&facts))
            .is_allowed()
    );
}

#[tokio::test]
async fn authorizer_debug_reports_counts_without_identity_or_policy() {
    let authorizer = authorizer_with(config()).await;
    let debug = format!("{authorizer:?}");
    assert!(debug.contains("Authorizer"));
    assert!(debug.contains("facts_revision"));
    assert!(debug.contains("domains: 4"));
    assert!(!debug.contains("tenant:a"));
    assert!(!debug.contains("viewer"));
}

#[test]
fn deny_reason_display_is_stable_and_non_sensitive() {
    assert_eq!(DenyReason::UnknownDomain.to_string(), "unknown domain");
    assert_eq!(
        DenyReason::CredentialPrincipalMismatch.to_string(),
        "credential principal mismatch"
    );
    assert_eq!(
        DenyReason::EngineError.to_string(),
        "authorization engine error"
    );
}

#[test]
fn authorizer_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Authorizer>();
}
