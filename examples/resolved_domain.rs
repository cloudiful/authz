use cloudiful_authz::{
    Action, Authority, Authorizer, AuthorizerConfig, AuthzRequest, Capability, Decision,
    DenyReason, FactsRevision, PrincipalRef, ResolvedRoles, ResourceKind, ResourceRef, RoleId,
    RoleSpec, ServiceId,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let principal = PrincipalRef::human("42");
    let config = AuthorizerConfig::new(
        FactsRevision(1),
        ["service"],
        [RoleSpec {
            id: RoleId::from("viewer"),
            capabilities: [Capability::new("page", "read")].into(),
        }],
    );
    let authorizer = Authorizer::new(config).await?;

    let request = |domain: &str| AuthzRequest {
        resource: ResourceRef {
            kind: ResourceKind::from("page"),
            id: None,
            domain: domain.into(),
        },
        action: Action::from("read"),
        audience: ServiceId::from("docs-service"),
        credential: None,
        server: None,
    };
    let facts = |domain: &str, roles: &[&str]| {
        ResolvedRoles::new(principal.clone(), domain, roles.iter().copied())
    };

    assert!(matches!(
        authorizer.authorize(
            &request("group:alpha"),
            Authority::Resolved(&facts("group:alpha", &["viewer"]))
        ),
        Decision::Allow
    ));
    assert!(matches!(
        authorizer.authorize(
            &request("group:beta"),
            Authority::Resolved(&facts("group:beta", &["viewer"]))
        ),
        Decision::Allow
    ));
    assert_eq!(
        authorizer.authorize(
            &request("group:beta"),
            Authority::Resolved(&facts("group:beta", &[]))
        ),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );
    assert_eq!(
        authorizer.authorize(
            &request("group:alpha"),
            Authority::Snapshot {
                subject: cloudiful_authz::Subject::Principal(principal.clone()),
                domain: "group:alpha".into(),
                facts_revision: FactsRevision(1),
            }
        ),
        Decision::Deny(DenyReason::UnknownDomain)
    );

    println!(
        "fresh group domains authorize through one engine and membership removal denies without a rebuild"
    );
    Ok(())
}
