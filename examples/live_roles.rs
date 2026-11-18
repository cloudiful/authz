use std::collections::BTreeSet;

use cloudiful_authz::{
    Action, Authorizer, AuthorizerConfig, AuthzRequest, Capability, Decision, DomainHierarchy,
    DomainId, FactsRevision, PrincipalId, PrincipalKind, PrincipalRef, ResolvedRoles, ResourceKind,
    ResourceRef, RoleId, RoleSpec, ServiceId, Subject,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let principal = PrincipalRef {
        kind: PrincipalKind::Human,
        id: PrincipalId::new("42"),
    };
    let authorizer = Authorizer::new(AuthorizerConfig {
        facts_revision: FactsRevision(1),
        domains: vec![DomainId::new("docs")],
        roles: vec![RoleSpec {
            id: RoleId::new("viewer"),
            capabilities: BTreeSet::from([Capability {
                resource: ResourceKind::new("page"),
                action: Action::new("read"),
            }]),
        }],
        assignments: vec![],
        global_assignments: vec![],
        hierarchy: DomainHierarchy::default(),
        public_read: BTreeSet::new(),
    })
    .await?;

    let request = AuthzRequest {
        subject: Subject::Principal(principal.clone()),
        domain: DomainId::new("docs"),
        resource: ResourceRef {
            kind: ResourceKind::new("page"),
            id: None,
            domain: DomainId::new("docs"),
        },
        action: Action::new("read"),
        audience: ServiceId::new("docs-service"),
        facts_revision: FactsRevision(999),
        credential: None,
        server: None,
    };
    let current = ResolvedRoles {
        principal: principal.clone(),
        domain: DomainId::new("docs"),
        roles: BTreeSet::from([RoleId::new("viewer")]),
    };
    let removed = ResolvedRoles {
        principal,
        domain: DomainId::new("docs"),
        roles: BTreeSet::new(),
    };

    assert!(matches!(
        authorizer.authorize_with_roles(&request, &current),
        Decision::Allow
    ));
    assert!(matches!(
        authorizer.authorize_with_roles(&request, &removed),
        Decision::Deny(_)
    ));
    println!("live roles authorize the current request and removal denies without a rebuild");
    Ok(())
}
