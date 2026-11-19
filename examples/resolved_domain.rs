use std::collections::BTreeSet;

use cloudiful_authz::{
    Action, Authorizer, AuthorizerConfig, AuthzRequest, Capability, Decision, DenyReason,
    DomainHierarchy, DomainId, FactsRevision, PrincipalId, PrincipalKind, PrincipalRef,
    ResolvedRoles, ResourceKind, ResourceRef, RoleId, RoleSpec, ServiceId, Subject,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let principal = PrincipalRef {
        kind: PrincipalKind::Human,
        id: PrincipalId::new("42"),
    };
    let authorizer = Authorizer::new(AuthorizerConfig {
        facts_revision: FactsRevision(1),
        domains: vec![DomainId::new("service")],
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

    let request = |domain: &str| AuthzRequest {
        subject: Subject::Principal(principal.clone()),
        domain: DomainId::new(domain),
        resource: ResourceRef {
            kind: ResourceKind::new("page"),
            id: None,
            domain: DomainId::new(domain),
        },
        action: Action::new("read"),
        audience: ServiceId::new("docs-service"),
        facts_revision: FactsRevision(1),
        credential: None,
        server: None,
    };
    let facts = |domain: &str, roles: &[&str]| ResolvedRoles {
        principal: principal.clone(),
        domain: DomainId::new(domain),
        roles: roles.iter().map(|role| RoleId::new(*role)).collect(),
    };

    assert!(matches!(
        authorizer.authorize_with_resolved_domain(
            &request("group:alpha"),
            &facts("group:alpha", &["viewer"])
        ),
        Decision::Allow
    ));
    assert!(matches!(
        authorizer.authorize_with_resolved_domain(
            &request("group:beta"),
            &facts("group:beta", &["viewer"])
        ),
        Decision::Allow
    ));
    assert_eq!(
        authorizer
            .authorize_with_resolved_domain(&request("group:beta"), &facts("group:beta", &[])),
        Decision::Deny(DenyReason::NoSubjectAuthority)
    );
    assert_eq!(
        authorizer.authorize(&request("group:alpha")),
        Decision::Deny(DenyReason::UnknownDomain)
    );

    println!(
        "fresh group domains authorize through one engine and membership removal denies without a rebuild"
    );
    Ok(())
}
