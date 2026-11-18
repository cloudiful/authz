use std::collections::BTreeSet;

use cloudiful_authz::{
    Action, Attenuation, Authorizer, AuthorizerConfig, AuthzRequest, Capability, CredentialContext,
    DomainHierarchy, DomainId, FactsRevision, PrincipalId, PrincipalKind, PrincipalRef,
    ResourceKind, ResourceRef, RoleAssignment, RoleId, RoleSpec, ServiceId, Subject,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let machine = PrincipalRef {
        kind: PrincipalKind::Service,
        id: PrincipalId::new("worker-1"),
    };
    let authorizer = Authorizer::new(AuthorizerConfig {
        facts_revision: FactsRevision(1),
        domains: vec![DomainId::new("jobs")],
        roles: vec![RoleSpec {
            id: RoleId::new("worker"),
            capabilities: BTreeSet::from([Capability {
                resource: ResourceKind::new("job"),
                action: Action::new("run"),
            }]),
        }],
        assignments: vec![RoleAssignment {
            principal: machine.clone(),
            role: RoleId::new("worker"),
            domain: DomainId::new("jobs"),
        }],
        global_assignments: vec![],
        hierarchy: DomainHierarchy::default(),
        public_read: BTreeSet::new(),
    })
    .await?;

    let request = AuthzRequest {
        subject: Subject::Principal(machine.clone()),
        domain: DomainId::new("jobs"),
        resource: ResourceRef {
            kind: ResourceKind::new("job"),
            id: Some(cloudiful_authz::ResourceId::new("42")),
            domain: DomainId::new("jobs"),
        },
        action: Action::new("run"),
        audience: ServiceId::new("job-runner"),
        facts_revision: FactsRevision(1),
        credential: Some(CredentialContext {
            principal: machine,
            audience: ServiceId::new("job-runner"),
            grants: Attenuation::Unrestricted,
        }),
        server: None,
    };

    println!("{:?}", authorizer.authorize(&request));
    Ok(())
}
