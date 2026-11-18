use std::collections::BTreeSet;

use cloudiful_authz::{
    Action, Attenuation, Authorizer, AuthorizerConfig, AuthzRequest, Capability, CredentialContext,
    Decision, DenyReason, DomainHierarchy, DomainId, FactsRevision, GlobalAssignment, Grant,
    InitError, PrincipalId, PrincipalKind, PrincipalRef, PublicReadGrant, ResourceId, ResourceKind,
    ResourceRef, RoleAssignment, RoleId, RoleSpec, ServerContext, ServiceId, Subject,
};

fn domain(value: &str) -> DomainId {
    DomainId::new(value)
}

fn role(id: &str, capabilities: &[(&str, &str)]) -> RoleSpec {
    RoleSpec {
        id: RoleId::new(id),
        capabilities: capabilities
            .iter()
            .map(|(resource, action)| Capability {
                resource: ResourceKind::new(*resource),
                action: Action::new(*action),
            })
            .collect(),
    }
}

fn principal(kind: PrincipalKind, id: &str) -> PrincipalRef {
    PrincipalRef {
        kind,
        id: PrincipalId::new(id),
    }
}

fn assignment(principal: PrincipalRef, role: &str, domain_value: &str) -> RoleAssignment {
    RoleAssignment {
        principal,
        role: RoleId::new(role),
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
        resource: ResourceKind::new(resource),
        resource_id: id.map(ResourceId::new),
        action: Action::new(action),
    }
}

fn config() -> AuthorizerConfig {
    AuthorizerConfig {
        facts_revision: FactsRevision(7),
        domains: vec![
            domain("tenant:a"),
            domain("tenant:a/child"),
            domain("tenant:b"),
            domain("admin"),
        ],
        roles: vec![
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
        assignments: vec![
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
        ],
        global_assignments: Vec::new(),
        hierarchy: DomainHierarchy {
            edges: vec![(domain("tenant:a/child"), domain("tenant:a"))],
        },
        public_read: BTreeSet::from([public_grant("tenant:a", "content", None, "read")]),
    }
}

fn make_request(
    subject: Subject,
    domain_value: &str,
    resource: &str,
    action: &str,
    revision: u64,
) -> AuthzRequest {
    AuthzRequest {
        subject,
        domain: domain(domain_value),
        resource: ResourceRef {
            kind: ResourceKind::new(resource),
            id: None,
            domain: domain(domain_value),
        },
        action: Action::new(action),
        audience: ServiceId::new("svc"),
        facts_revision: FactsRevision(revision),
        credential: None,
        server: None,
    }
}

fn human_request(id: &str, domain: &str, resource: &str, action: &str) -> AuthzRequest {
    make_request(
        Subject::Principal(principal(PrincipalKind::Human, id)),
        domain,
        resource,
        action,
        7,
    )
}

fn grant(domain_value: &str, resource: &str, id: Option<&str>, action: &str) -> Grant {
    Grant {
        domain: domain(domain_value),
        resource: ResourceKind::new(resource),
        resource_id: id.map(ResourceId::new),
        action: Action::new(action),
    }
}

fn grants(entries: impl IntoIterator<Item = Grant>) -> Attenuation {
    Attenuation::Grants(entries.into_iter().collect())
}

async fn authorizer_with(config: AuthorizerConfig) -> Authorizer {
    Authorizer::new(config).await.expect("authorizer builds")
}

#[tokio::test]
async fn domain_assignment_is_isolated_and_parent_role_inherits_downward() {
    let authorizer = authorizer_with(config()).await;

    assert!(
        authorizer
            .authorize(&human_request("42", "tenant:a", "content", "write"))
            .is_allowed()
    );
    assert!(
        authorizer
            .authorize(&human_request("42", "tenant:a/child", "content", "write"))
            .is_allowed()
    );
    assert_eq!(
        authorizer.authorize(&human_request("42", "tenant:b", "content", "write")),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );
}

#[tokio::test]
async fn rebuilt_snapshot_revokes_a_removed_assignment() {
    let first = authorizer_with(config()).await;
    assert!(
        first
            .authorize(&human_request("42", "tenant:a/child", "content", "write"))
            .is_allowed()
    );

    let mut next = config();
    next.facts_revision = FactsRevision(8);
    next.assignments
        .retain(|assignment| assignment.principal != principal(PrincipalKind::Human, "42"));
    let second = authorizer_with(next).await;

    let mut request = human_request("42", "tenant:a/child", "content", "write");
    request.facts_revision = FactsRevision(8);
    assert_eq!(
        second.authorize(&request),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );
}

#[tokio::test]
async fn exact_capability_and_unknown_universe_are_enforced() {
    let authorizer = authorizer_with(config()).await;

    assert!(
        authorizer
            .authorize(&human_request("42", "tenant:a", "content", "read"))
            .is_allowed()
    );
    assert_eq!(
        authorizer.authorize(&human_request("42", "tenant:a", "content", "delete")),
        Decision::Deny(DenyReason::UnknownAction)
    );
    assert_eq!(
        authorizer.authorize(&human_request("42", "tenant:a", "unknown", "read")),
        Decision::Deny(DenyReason::UnknownResource)
    );
}

#[tokio::test]
async fn principal_kind_and_role_name_collisions_do_not_grant_authority() {
    let authorizer = authorizer_with(config()).await;

    let service_with_human_id = make_request(
        Subject::Principal(principal(PrincipalKind::Service, "42")),
        "tenant:a",
        "content",
        "write",
        7,
    );
    assert_eq!(
        authorizer.authorize(&service_with_human_id),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );

    let principal_named_like_a_role = make_request(
        Subject::Principal(principal(PrincipalKind::Human, "maintainer")),
        "tenant:a",
        "content",
        "write",
        7,
    );
    assert_eq!(
        authorizer.authorize(&principal_named_like_a_role),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );
}

#[tokio::test]
async fn unrestricted_and_empty_credential_and_server_attenuation_differ() {
    let authorizer = authorizer_with(config()).await;
    let mut base = human_request("42", "tenant:b", "content", "read");

    base.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::new("svc"),
        grants: Attenuation::Unrestricted,
    });
    assert!(authorizer.authorize(&base).is_allowed());

    base.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::new("svc"),
        grants: grants([]),
    });
    assert_eq!(
        authorizer.authorize(&base),
        Decision::Deny(DenyReason::CredentialGrantMissing)
    );

    let mut server_base = human_request("42", "tenant:b", "content", "read");
    server_base.server = Some(ServerContext {
        grants: Attenuation::Unrestricted,
    });
    assert!(authorizer.authorize(&server_base).is_allowed());

    server_base.server = Some(ServerContext { grants: grants([]) });
    assert_eq!(
        authorizer.authorize(&server_base),
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

    let mut request = human_request("43", "tenant:a", "content", "write");
    request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "43"),
        audience: ServiceId::new("svc"),
        grants: grants([
            grant("tenant:a", "content", None, "read"),
            grant("tenant:b", "content", None, "write"),
        ]),
    });
    assert_eq!(
        authorizer.authorize(&request),
        Decision::Deny(DenyReason::CredentialGrantMissing)
    );

    request.domain = domain("tenant:b");
    request.resource.domain = domain("tenant:b");
    assert!(authorizer.authorize(&request).is_allowed());
}

#[tokio::test]
async fn exact_resource_grants_require_the_same_exact_id() {
    let authorizer = authorizer_with(config()).await;

    let mut request = human_request("42", "tenant:b", "content", "read");
    request.resource.id = Some(ResourceId::new("doc-1"));
    request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::new("svc"),
        grants: grants([grant("tenant:b", "content", Some("doc-1"), "read")]),
    });
    assert!(authorizer.authorize(&request).is_allowed());

    request.resource.id = Some(ResourceId::new("doc-2"));
    assert_eq!(
        authorizer.authorize(&request),
        Decision::Deny(DenyReason::CredentialGrantMissing)
    );

    request.resource.id = None;
    assert_eq!(
        authorizer.authorize(&request),
        Decision::Deny(DenyReason::CredentialGrantMissing)
    );

    request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::new("svc"),
        grants: grants([grant("tenant:b", "content", None, "read")]),
    });
    assert!(authorizer.authorize(&request).is_allowed());
}

#[tokio::test]
async fn credential_principal_and_audience_mismatches_deny() {
    let authorizer = authorizer_with(config()).await;
    let mut request = human_request("42", "tenant:b", "content", "read");
    request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "43"),
        audience: ServiceId::new("svc"),
        grants: Attenuation::Unrestricted,
    });
    assert_eq!(
        authorizer.authorize(&request),
        Decision::Deny(DenyReason::CredentialPrincipalMismatch)
    );

    request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Service, "42"),
        audience: ServiceId::new("svc"),
        grants: Attenuation::Unrestricted,
    });
    assert_eq!(
        authorizer.authorize(&request),
        Decision::Deny(DenyReason::CredentialPrincipalMismatch)
    );

    request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::new("other"),
        grants: Attenuation::Unrestricted,
    });
    assert_eq!(
        authorizer.authorize(&request),
        Decision::Deny(DenyReason::CredentialAudienceMismatch)
    );
}

#[tokio::test]
async fn public_read_is_limited_and_still_attenuated() {
    let authorizer = authorizer_with(config()).await;
    let mut request = make_request(Subject::PublicRead, "tenant:a", "content", "read", 7);
    assert!(authorizer.authorize(&request).is_allowed());

    request.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "unknown"),
        audience: ServiceId::new("svc"),
        grants: grants([]),
    });
    assert_eq!(
        authorizer.authorize(&request),
        Decision::Deny(DenyReason::CredentialGrantMissing)
    );

    request.credential = None;
    request.server = Some(ServerContext { grants: grants([]) });
    assert_eq!(
        authorizer.authorize(&request),
        Decision::Deny(DenyReason::ServerGrantMissing)
    );

    request.server = None;
    let write = make_request(Subject::PublicRead, "tenant:a", "content", "write", 7);
    assert_eq!(
        authorizer.authorize(&write),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );
}

#[tokio::test]
async fn unknown_domains_and_cross_domain_resources_deny() {
    let authorizer = authorizer_with(config()).await;

    let unknown = human_request("42", "tenant:missing", "content", "read");
    assert_eq!(
        authorizer.authorize(&unknown),
        Decision::Deny(DenyReason::UnknownDomain)
    );

    let mut cross_domain = human_request("42", "tenant:a", "content", "read");
    cross_domain.resource.domain = domain("tenant:b");
    assert_eq!(
        authorizer.authorize(&cross_domain),
        Decision::Deny(DenyReason::CrossDomainResource)
    );
}

#[tokio::test]
async fn public_read_exact_id_grants_require_the_same_id() {
    let mut config = config();
    config.public_read =
        BTreeSet::from([public_grant("tenant:a", "content", Some("doc-1"), "read")]);
    let authorizer = authorizer_with(config).await;

    let mut request = make_request(Subject::PublicRead, "tenant:a", "content", "read", 7);
    request.resource.id = Some(ResourceId::new("doc-1"));
    assert!(authorizer.authorize(&request).is_allowed());

    request.resource.id = Some(ResourceId::new("doc-2"));
    assert_eq!(
        authorizer.authorize(&request),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );

    request.resource.id = None;
    assert_eq!(
        authorizer.authorize(&request),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );
}

#[tokio::test]
async fn malformed_audiences_deny_in_principal_and_public_modes() {
    let authorizer = authorizer_with(config()).await;

    let mut principal_empty = human_request("42", "tenant:a", "content", "read");
    principal_empty.audience = ServiceId::new("");
    assert_eq!(
        authorizer.authorize(&principal_empty),
        Decision::Deny(DenyReason::InvalidAudience)
    );

    let mut principal_control = human_request("42", "tenant:a", "content", "read");
    principal_control.audience = ServiceId::new("svc\n");
    assert_eq!(
        authorizer.authorize(&principal_control),
        Decision::Deny(DenyReason::InvalidAudience)
    );

    let mut principal_wildcard = human_request("42", "tenant:a", "content", "read");
    principal_wildcard.audience = ServiceId::new("*");
    assert_eq!(
        authorizer.authorize(&principal_wildcard),
        Decision::Deny(DenyReason::InvalidAudience)
    );

    let mut credential_empty = human_request("42", "tenant:a", "content", "read");
    credential_empty.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::new(""),
        grants: Attenuation::Unrestricted,
    });
    assert_eq!(
        authorizer.authorize(&credential_empty),
        Decision::Deny(DenyReason::InvalidAudience)
    );

    let mut public_empty = make_request(Subject::PublicRead, "tenant:a", "content", "read", 7);
    public_empty.audience = ServiceId::new("");
    assert_eq!(
        authorizer.authorize(&public_empty),
        Decision::Deny(DenyReason::InvalidAudience)
    );

    let mut public_credential_wildcard =
        make_request(Subject::PublicRead, "tenant:a", "content", "read", 7);
    public_credential_wildcard.credential = Some(CredentialContext {
        principal: principal(PrincipalKind::Human, "42"),
        audience: ServiceId::new("*"),
        grants: Attenuation::Unrestricted,
    });
    assert_eq!(
        authorizer.authorize(&public_credential_wildcard),
        Decision::Deny(DenyReason::InvalidAudience)
    );
}

#[tokio::test]
async fn stale_facts_revision_denies_before_authority() {
    let authorizer = authorizer_with(config()).await;
    let mut request = human_request("42", "tenant:a", "content", "read");
    request.facts_revision = FactsRevision(6);
    assert_eq!(
        authorizer.authorize(&request),
        Decision::Deny(DenyReason::StaleFacts)
    );
    assert_eq!(authorizer.facts_revision(), FactsRevision(7));
}

#[tokio::test]
async fn admin_has_no_wildcard_and_application_has_no_implicit_role() {
    let authorizer = authorizer_with(config()).await;
    let admin = make_request(
        Subject::Principal(principal(PrincipalKind::Human, "1")),
        "admin",
        "admin",
        "read",
        7,
    );
    assert!(authorizer.authorize(&admin).is_allowed());

    let admin_delete = make_request(
        Subject::Principal(principal(PrincipalKind::Human, "1")),
        "admin",
        "admin",
        "delete",
        7,
    );
    assert_eq!(
        authorizer.authorize(&admin_delete),
        Decision::Deny(DenyReason::UnknownAction)
    );

    let application = make_request(
        Subject::Principal(principal(PrincipalKind::Application, "app")),
        "tenant:a",
        "job",
        "run",
        7,
    );
    assert_eq!(
        authorizer.authorize(&application),
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
            .authorize(&human_request("42", "tenant:a", "content", "write"))
            .is_allowed()
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
        Err(InitError::DuplicateRole(role)) if role == RoleId::new("viewer")
    ));

    let mut unknown_role = config();
    unknown_role.assignments.push(assignment(
        principal(PrincipalKind::Human, "9"),
        "missing",
        "tenant:a",
    ));
    assert!(matches!(
        Authorizer::new(unknown_role).await,
        Err(InitError::UnknownRole(role)) if role == RoleId::new("missing")
    ));

    let mut unknown_domain = config();
    unknown_domain.assignments.push(assignment(
        principal(PrincipalKind::Human, "9"),
        "viewer",
        "missing",
    ));
    assert!(matches!(
        Authorizer::new(unknown_domain).await,
        Err(InitError::UnknownDomain(domain)) if domain == DomainId::new("missing")
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
        Err(InitError::DuplicateDomain(domain)) if domain == DomainId::new("tenant:a")
    ));
}

#[tokio::test]
async fn global_assignment_applies_in_each_registered_domain() {
    let mut config = config();
    config.global_assignments.push(GlobalAssignment {
        principal: principal(PrincipalKind::Human, "88"),
        role: RoleId::new("viewer"),
    });
    let authorizer = authorizer_with(config).await;
    assert!(
        authorizer
            .authorize(&human_request("88", "tenant:a", "content", "read"))
            .is_allowed()
    );
    assert!(
        authorizer
            .authorize(&human_request("88", "tenant:b", "content", "read"))
            .is_allowed()
    );
}

#[tokio::test]
async fn role_capabilities_are_exposed_without_wildcards() {
    let authorizer = authorizer_with(config()).await;
    let capabilities = authorizer
        .role_capabilities(&RoleId::new("admin"))
        .expect("admin role exists");
    assert!(capabilities.contains(&Capability {
        resource: ResourceKind::new("admin"),
        action: Action::new("read"),
    }));
    assert!(!capabilities.contains(&Capability {
        resource: ResourceKind::new("admin"),
        action: Action::new("delete"),
    }));
}

#[test]
fn authorizer_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Authorizer>();
}
