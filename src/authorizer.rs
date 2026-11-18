use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use casbin::{CoreApi, DefaultModel, Enforcer, MemoryAdapter, MgmtApi};

use crate::encoding::{encode_principal, encode_role, validate_identifier, validate_service_id};
use crate::error::InitError;
use crate::types::{
    Action, Attenuation, AuthorizerConfig, AuthzRequest, Capability, Decision, DenyReason,
    DomainHierarchy, DomainId, FactsRevision, PublicReadGrant, ResourceId, ResourceKind, RoleId,
    Subject,
};

const MODEL: &str = r#"
[request_definition]
r = sub, dom, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = g(r.sub, p.sub, r.dom) && r.obj == p.obj && r.act == p.act
"#;

#[derive(Clone)]
pub struct Authorizer {
    enforcer: Arc<Enforcer>,
    facts_revision: FactsRevision,
    roles: BTreeMap<RoleId, BTreeSet<Capability>>,
    domains: BTreeSet<DomainId>,
    resources: BTreeSet<ResourceKind>,
    actions: BTreeSet<Action>,
    public_read: BTreeSet<PublicReadGrant>,
}

impl Authorizer {
    pub async fn new(config: AuthorizerConfig) -> Result<Self, InitError> {
        let domains = validated_domains(&config.domains)?;
        let roles = validated_roles(&config.roles)?;
        let public_read = validated_public_read(&config.public_read, &domains)?;

        let children = build_children(&config.hierarchy, &domains)?;
        let descendants = build_descendants(&domains, &children)?;

        let mut policies = BTreeSet::<Vec<String>>::new();
        for (role, capabilities) in &roles {
            for capability in capabilities {
                policies.insert(vec![
                    encode_role(role),
                    capability.resource.0.clone(),
                    capability.action.0.clone(),
                ]);
            }
        }

        let mut groups = BTreeSet::<Vec<String>>::new();
        for assignment in &config.assignments {
            validate_identifier(&assignment.principal.id.0)
                .map_err(InitError::InvalidIdentifier)?;
            if !roles.contains_key(&assignment.role) {
                return Err(InitError::UnknownRole(assignment.role.clone()));
            }
            let Some(domains_for_assignment) = descendants.get(&assignment.domain) else {
                return Err(InitError::UnknownDomain(assignment.domain.clone()));
            };
            for domain in domains_for_assignment {
                groups.insert(vec![
                    encode_principal(&assignment.principal),
                    encode_role(&assignment.role),
                    domain.0.clone(),
                ]);
            }
        }

        for assignment in &config.global_assignments {
            validate_identifier(&assignment.principal.id.0)
                .map_err(InitError::InvalidIdentifier)?;
            if !roles.contains_key(&assignment.role) {
                return Err(InitError::UnknownRole(assignment.role.clone()));
            }
            for domain in &domains {
                groups.insert(vec![
                    encode_principal(&assignment.principal),
                    encode_role(&assignment.role),
                    domain.0.clone(),
                ]);
            }
        }

        let model = DefaultModel::from_str(MODEL)
            .await
            .map_err(|error| InitError::Engine(error.to_string()))?;
        let mut enforcer = Enforcer::new(model, MemoryAdapter::default())
            .await
            .map_err(|error| InitError::Engine(error.to_string()))?;

        if !policies.is_empty() {
            let inserted = enforcer
                .add_policies(policies.into_iter().collect())
                .await
                .map_err(|error| InitError::Engine(error.to_string()))?;
            if !inserted {
                return Err(InitError::Engine("policy insertion failed".to_owned()));
            }
        }
        if !groups.is_empty() {
            let inserted = enforcer
                .add_grouping_policies(groups.into_iter().collect())
                .await
                .map_err(|error| InitError::Engine(error.to_string()))?;
            if !inserted {
                return Err(InitError::Engine(
                    "role assignment insertion failed".to_owned(),
                ));
            }
        }
        enforcer
            .build_role_links()
            .map_err(|error| InitError::Engine(error.to_string()))?;

        let (resources, actions) = validated_universe(&config.roles, &public_read)?;

        Ok(Self {
            enforcer: Arc::new(enforcer),
            facts_revision: config.facts_revision,
            roles,
            domains,
            resources,
            actions,
            public_read,
        })
    }

    pub fn authorize(&self, request: &AuthzRequest) -> Decision {
        if request.facts_revision != self.facts_revision {
            return Decision::Deny(DenyReason::StaleFacts);
        }
        if validate_service_id(&request.audience.0).is_err() {
            return Decision::Deny(DenyReason::InvalidAudience);
        }
        if let Some(credential) = &request.credential
            && validate_service_id(&credential.audience.0).is_err()
        {
            return Decision::Deny(DenyReason::InvalidAudience);
        }
        if !self.domains.contains(&request.domain) {
            return Decision::Deny(DenyReason::UnknownDomain);
        }
        if !self.resources.contains(&request.resource.kind) {
            return Decision::Deny(DenyReason::UnknownResource);
        }
        if !self.actions.contains(&request.action) {
            return Decision::Deny(DenyReason::UnknownAction);
        }
        if let Some(resource_id) = &request.resource.id
            && validate_identifier(&resource_id.0).is_err()
        {
            return Decision::Deny(DenyReason::UnknownResource);
        }
        if request.resource.domain != request.domain {
            return Decision::Deny(DenyReason::CrossDomainResource);
        }

        let subject_allowed = match &request.subject {
            Subject::Principal(principal) => {
                if validate_identifier(&principal.id.0).is_err() {
                    return Decision::Deny(DenyReason::NoSubjectAuthority);
                }
                let encoded_principal = encode_principal(principal);
                match self.enforcer.enforce((
                    encoded_principal,
                    request.domain.0.clone(),
                    request.resource.kind.0.clone(),
                    request.action.0.clone(),
                )) {
                    Ok(allowed) => allowed,
                    Err(_) => return Decision::Deny(DenyReason::EngineError),
                }
            }
            Subject::PublicRead => self
                .public_read
                .iter()
                .any(|grant| public_read_matches(grant, request)),
        };
        if !subject_allowed {
            return Decision::Deny(DenyReason::NoSubjectAuthority);
        }

        if let Some(credential) = &request.credential {
            if let Subject::Principal(principal) = &request.subject
                && &credential.principal != principal
            {
                return Decision::Deny(DenyReason::CredentialPrincipalMismatch);
            }
            if credential.audience != request.audience {
                return Decision::Deny(DenyReason::CredentialAudienceMismatch);
            }
            if !attenuation_matches(&credential.grants, request) {
                return Decision::Deny(DenyReason::CredentialGrantMissing);
            }
        }

        if let Some(server) = &request.server
            && !attenuation_matches(&server.grants, request)
        {
            return Decision::Deny(DenyReason::ServerGrantMissing);
        }

        Decision::Allow
    }

    pub fn facts_revision(&self) -> FactsRevision {
        self.facts_revision
    }

    pub fn role_capabilities(&self, role: &RoleId) -> Option<&BTreeSet<Capability>> {
        self.roles.get(role)
    }
}

fn validated_domains(domains: &[DomainId]) -> Result<BTreeSet<DomainId>, InitError> {
    let mut validated = BTreeSet::new();
    for domain in domains {
        validate_identifier(&domain.0).map_err(InitError::InvalidIdentifier)?;
        if !validated.insert(domain.clone()) {
            return Err(InitError::DuplicateDomain(domain.clone()));
        }
    }
    Ok(validated)
}

fn validated_roles(
    roles: &[crate::types::RoleSpec],
) -> Result<BTreeMap<RoleId, BTreeSet<Capability>>, InitError> {
    let mut validated = BTreeMap::new();
    for role in roles {
        validate_identifier(&role.id.0).map_err(InitError::InvalidIdentifier)?;
        if validated.contains_key(&role.id) {
            return Err(InitError::DuplicateRole(role.id.clone()));
        }
        for capability in &role.capabilities {
            validate_identifier(&capability.resource.0).map_err(InitError::InvalidIdentifier)?;
            validate_identifier(&capability.action.0).map_err(InitError::InvalidIdentifier)?;
        }
        validated.insert(role.id.clone(), role.capabilities.clone());
    }
    Ok(validated)
}

fn validated_public_read(
    grants: &BTreeSet<PublicReadGrant>,
    domains: &BTreeSet<DomainId>,
) -> Result<BTreeSet<PublicReadGrant>, InitError> {
    let mut validated = BTreeSet::new();
    for grant in grants {
        if !domains.contains(&grant.domain) {
            return Err(InitError::InvalidPublicReadGrant);
        }
        validate_identifier(&grant.resource.0).map_err(InitError::InvalidIdentifier)?;
        validate_identifier(&grant.action.0).map_err(InitError::InvalidIdentifier)?;
        if let Some(resource_id) = &grant.resource_id {
            validate_identifier(&resource_id.0).map_err(InitError::InvalidIdentifier)?;
        }
        validated.insert(grant.clone());
    }
    Ok(validated)
}

fn validated_universe(
    roles: &[crate::types::RoleSpec],
    public_read: &BTreeSet<PublicReadGrant>,
) -> Result<(BTreeSet<ResourceKind>, BTreeSet<Action>), InitError> {
    let mut resources = BTreeSet::new();
    let mut actions = BTreeSet::new();
    for role in roles {
        for capability in &role.capabilities {
            resources.insert(capability.resource.clone());
            actions.insert(capability.action.clone());
        }
    }
    for grant in public_read {
        resources.insert(grant.resource.clone());
        actions.insert(grant.action.clone());
    }
    Ok((resources, actions))
}

fn build_children(
    hierarchy: &DomainHierarchy,
    domains: &BTreeSet<DomainId>,
) -> Result<BTreeMap<DomainId, BTreeSet<DomainId>>, InitError> {
    let mut children = domains
        .iter()
        .cloned()
        .map(|domain| (domain, BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    for (child, parent) in &hierarchy.edges {
        validate_identifier(&child.0).map_err(InitError::InvalidIdentifier)?;
        validate_identifier(&parent.0).map_err(InitError::InvalidIdentifier)?;
        if !domains.contains(child) {
            return Err(InitError::UnknownDomain(child.clone()));
        }
        if !domains.contains(parent) {
            return Err(InitError::UnknownDomain(parent.clone()));
        }
        let Some(parent_children) = children.get_mut(parent) else {
            return Err(InitError::UnknownDomain(parent.clone()));
        };
        parent_children.insert(child.clone());
    }

    let mut state = BTreeMap::<DomainId, u8>::new();
    for domain in domains {
        visit_domain(domain, &children, &mut state)?;
    }
    Ok(children)
}

fn visit_domain(
    domain: &DomainId,
    children: &BTreeMap<DomainId, BTreeSet<DomainId>>,
    state: &mut BTreeMap<DomainId, u8>,
) -> Result<(), InitError> {
    match state.get(domain).copied().unwrap_or(0) {
        2 => Ok(()),
        1 => Err(InitError::HierarchyCycle),
        _ => {
            state.insert(domain.clone(), 1);
            if let Some(descendants) = children.get(domain) {
                for descendant in descendants {
                    visit_domain(descendant, children, state)?;
                }
            }
            state.insert(domain.clone(), 2);
            Ok(())
        }
    }
}

fn build_descendants(
    domains: &BTreeSet<DomainId>,
    children: &BTreeMap<DomainId, BTreeSet<DomainId>>,
) -> Result<BTreeMap<DomainId, BTreeSet<DomainId>>, InitError> {
    let mut descendants = BTreeMap::new();
    for domain in domains {
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(domain.clone());
        while let Some(current) = queue.pop_front() {
            if !visited.insert(current.clone()) {
                continue;
            }
            if let Some(next) = children.get(&current) {
                queue.extend(next.iter().cloned());
            }
        }
        descendants.insert(domain.clone(), visited);
    }
    Ok(descendants)
}

fn attenuation_matches(attenuation: &Attenuation, request: &AuthzRequest) -> bool {
    match attenuation {
        Attenuation::Unrestricted => true,
        Attenuation::Grants(grants) => grants.iter().any(|grant| {
            grant.domain == request.domain
                && grant.resource == request.resource.kind
                && grant.action == request.action
                && resource_id_matches(grant.resource_id.as_ref(), request.resource.id.as_ref())
        }),
    }
}

fn public_read_matches(grant: &PublicReadGrant, request: &AuthzRequest) -> bool {
    grant.domain == request.domain
        && grant.resource == request.resource.kind
        && grant.action == request.action
        && resource_id_matches(grant.resource_id.as_ref(), request.resource.id.as_ref())
}

fn resource_id_matches(grant: Option<&ResourceId>, requested: Option<&ResourceId>) -> bool {
    match (grant, requested) {
        (None, _) => true,
        (Some(grant), Some(requested)) => grant == requested,
        (Some(_), None) => false,
    }
}
