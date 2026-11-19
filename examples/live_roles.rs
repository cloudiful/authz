use cloudiful_authz::{
    Action, Authority, Authorizer, AuthorizerConfig, AuthzRequest, Capability, Decision,
    FactsRevision, PrincipalRef, ResolvedRoles, ResourceKind, ResourceRef, RoleId, RoleSpec,
    ServiceId,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let principal = PrincipalRef::human("42");
    let config = AuthorizerConfig::new(
        FactsRevision(1),
        ["docs"],
        [RoleSpec {
            id: RoleId::from("viewer"),
            capabilities: [Capability::new("page", "read")].into(),
        }],
    );
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
    let current = ResolvedRoles::new(principal.clone(), "docs", ["viewer"]);
    let removed = ResolvedRoles::new(principal, "docs", [] as [&str; 0]);

    assert!(matches!(
        authorizer.authorize(&request, Authority::Registered(&current)),
        Decision::Allow
    ));
    assert!(matches!(
        authorizer.authorize(&request, Authority::Registered(&removed)),
        Decision::Deny(_)
    ));
    println!("live roles authorize the current request and removal denies without a rebuild");
    Ok(())
}
