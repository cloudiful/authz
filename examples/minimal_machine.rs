use cloudiful_authz::{
    Action, Attenuation, Authority, Authorizer, AuthorizerConfig, AuthzRequest, Capability,
    CredentialContext, FactsRevision, PrincipalRef, ResourceKind, ResourceRef, RoleAssignment,
    RoleId, RoleSpec, ServiceId, Subject,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let machine = PrincipalRef::service("worker-1");
    let mut config = AuthorizerConfig::new(
        FactsRevision(1),
        ["jobs"],
        [RoleSpec {
            id: RoleId::from("worker"),
            capabilities: [Capability::new("job", "run")].into(),
        }],
    );
    config.assignments.push(RoleAssignment {
        principal: machine.clone(),
        role: RoleId::from("worker"),
        domain: "jobs".into(),
    });
    let authorizer = Authorizer::new(config).await?;

    let request = AuthzRequest {
        resource: ResourceRef {
            kind: ResourceKind::from("job"),
            id: Some("42".into()),
            domain: "jobs".into(),
        },
        action: Action::from("run"),
        audience: ServiceId::from("job-runner"),
        credential: Some(CredentialContext {
            principal: machine.clone(),
            audience: ServiceId::from("job-runner"),
            grants: Attenuation::unrestricted(),
        }),
        server: None,
    };
    let authority = Authority::Snapshot {
        subject: Subject::Principal(machine),
        domain: "jobs".into(),
        facts_revision: FactsRevision(1),
    };

    println!("{:?}", authorizer.authorize(&request, authority));
    Ok(())
}
