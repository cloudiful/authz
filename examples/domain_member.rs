use std::collections::BTreeSet;

use cloudiful_authz::{
    Action, Authorizer, AuthorizerConfig, AuthzRequest, Capability, Decision, DomainHierarchy,
    DomainId, FactsRevision, PrincipalId, PrincipalKind, PrincipalRef, ResourceKind, ResourceRef,
    RoleAssignment, RoleId, RoleSpec, ServiceId, Subject,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let member = PrincipalRef {
        kind: PrincipalKind::Human,
        id: PrincipalId::new("42"),
    };
    let authorizer = Authorizer::new(AuthorizerConfig {
        facts_revision: FactsRevision(1),
        domains: vec![DomainId::new("team"), DomainId::new("team/docs")],
        roles: vec![
            RoleSpec {
                id: RoleId::new("viewer"),
                capabilities: BTreeSet::from([Capability {
                    resource: ResourceKind::new("content"),
                    action: Action::new("read"),
                }]),
            },
            RoleSpec {
                id: RoleId::new("maintainer"),
                capabilities: BTreeSet::from([
                    Capability {
                        resource: ResourceKind::new("content"),
                        action: Action::new("read"),
                    },
                    Capability {
                        resource: ResourceKind::new("content"),
                        action: Action::new("write"),
                    },
                ]),
            },
        ],
        assignments: vec![RoleAssignment {
            principal: member.clone(),
            role: RoleId::new("maintainer"),
            domain: DomainId::new("team"),
        }],
        global_assignments: vec![],
        hierarchy: DomainHierarchy {
            edges: vec![(DomainId::new("team/docs"), DomainId::new("team"))],
        },
        public_read: BTreeSet::new(),
    })
    .await?;

    let request = AuthzRequest {
        subject: Subject::Principal(member),
        domain: DomainId::new("team/docs"),
        resource: ResourceRef {
            kind: ResourceKind::new("content"),
            id: None,
            domain: DomainId::new("team/docs"),
        },
        action: Action::new("write"),
        audience: ServiceId::new("docs-service"),
        facts_revision: FactsRevision(1),
        credential: None,
        server: None,
    };

    assert!(matches!(authorizer.authorize(&request), Decision::Allow));
    println!("parent membership authorizes the child domain");
    Ok(())
}
