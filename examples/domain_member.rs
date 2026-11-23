use cloudiful_authz::{
    Action, Authority, Authorizer, AuthorizerConfig, AuthzRequest, Capability, Decision,
    DomainHierarchy, FactsRevision, PrincipalRef, ResourceKind, ResourceRef, RoleAssignment,
    RoleId, RoleSpec, ServiceId, Subject,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let member = PrincipalRef::human("42");
    let mut config = AuthorizerConfig::new(
        FactsRevision(1),
        ["team", "team/docs"],
        [
            RoleSpec {
                id: RoleId::from("viewer"),
                capabilities: [Capability::new("content", "read")].into(),
            },
            RoleSpec {
                id: RoleId::from("maintainer"),
                capabilities: [
                    Capability::new("content", "read"),
                    Capability::new("content", "write"),
                ]
                .into(),
            },
        ],
    );
    config.assignments.push(RoleAssignment {
        principal: member.clone(),
        role: RoleId::from("maintainer"),
        domain: "team".into(),
    });
    config.hierarchy = DomainHierarchy {
        edges: vec![("team/docs".into(), "team".into())],
    };
    let authorizer = Authorizer::new(config).await?;

    let request = AuthzRequest {
        resource: ResourceRef {
            kind: ResourceKind::from("content"),
            id: None,
            domain: "team/docs".into(),
        },
        action: Action::from("write"),
        audience: ServiceId::from("docs-service"),
        credential: None,
        server: None,
    };
    let authority = Authority::Snapshot {
        subject: Subject::Principal(member),
        domain: "team/docs".into(),
        facts_revision: FactsRevision(1),
    };

    assert!(matches!(
        authorizer.authorize(&request, authority),
        Decision::Allow
    ));
    println!("parent membership authorizes the child domain");
    Ok(())
}
