use std::collections::BTreeSet;
use std::fmt;

macro_rules! string_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

string_id!(PrincipalId);
string_id!(DomainId);
string_id!(RoleId);
string_id!(ResourceKind);
string_id!(ResourceId);
string_id!(Action);
string_id!(ServiceId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FactsRevision(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrincipalKind {
    Human,
    Service,
    Application,
}

impl PrincipalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Service => "service",
            Self::Application => "application",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrincipalRef {
    pub kind: PrincipalKind,
    pub id: PrincipalId,
}

impl PrincipalRef {
    pub fn new(kind: PrincipalKind, id: impl Into<PrincipalId>) -> Self {
        Self {
            kind,
            id: id.into(),
        }
    }

    pub fn human(id: impl Into<PrincipalId>) -> Self {
        Self::new(PrincipalKind::Human, id)
    }

    pub fn service(id: impl Into<PrincipalId>) -> Self {
        Self::new(PrincipalKind::Service, id)
    }

    pub fn application(id: impl Into<PrincipalId>) -> Self {
        Self::new(PrincipalKind::Application, id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    Principal(PrincipalRef),
    PublicRead,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Capability {
    pub resource: ResourceKind,
    pub action: Action,
}

impl Capability {
    pub fn new(resource: impl Into<ResourceKind>, action: impl Into<Action>) -> Self {
        Self {
            resource: resource.into(),
            action: action.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Grant {
    pub domain: DomainId,
    pub resource: ResourceKind,
    pub resource_id: Option<ResourceId>,
    pub action: Action,
}

impl Grant {
    pub fn new(
        domain: impl Into<DomainId>,
        resource: impl Into<ResourceKind>,
        action: impl Into<Action>,
    ) -> Self {
        Self {
            domain: domain.into(),
            resource: resource.into(),
            resource_id: None,
            action: action.into(),
        }
    }

    pub fn with_resource_id(mut self, id: impl Into<ResourceId>) -> Self {
        self.resource_id = Some(id.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attenuation {
    Unrestricted,
    Grants(BTreeSet<Grant>),
}

impl Attenuation {
    pub fn grants(entries: impl IntoIterator<Item = Grant>) -> Self {
        Self::Grants(entries.into_iter().collect())
    }

    pub fn deny_all() -> Self {
        Self::Grants(BTreeSet::new())
    }

    pub fn unrestricted() -> Self {
        Self::Unrestricted
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleSpec {
    pub id: RoleId,
    pub capabilities: BTreeSet<Capability>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleAssignment {
    pub principal: PrincipalRef,
    pub role: RoleId,
    pub domain: DomainId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalAssignment {
    pub principal: PrincipalRef,
    pub role: RoleId,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DomainHierarchy {
    pub edges: Vec<(DomainId, DomainId)>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicReadGrant {
    pub domain: DomainId,
    pub resource: ResourceKind,
    pub resource_id: Option<ResourceId>,
    pub action: Action,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizerConfig {
    pub facts_revision: FactsRevision,
    pub domains: Vec<DomainId>,
    pub roles: Vec<RoleSpec>,
    pub assignments: Vec<RoleAssignment>,
    pub global_assignments: Vec<GlobalAssignment>,
    pub hierarchy: DomainHierarchy,
    pub public_read: BTreeSet<PublicReadGrant>,
}

impl AuthorizerConfig {
    pub fn new(
        facts_revision: FactsRevision,
        domains: impl IntoIterator<Item = impl Into<DomainId>>,
        roles: impl IntoIterator<Item = RoleSpec>,
    ) -> Self {
        Self {
            facts_revision,
            domains: domains.into_iter().map(Into::into).collect(),
            roles: roles.into_iter().collect(),
            assignments: Vec::new(),
            global_assignments: Vec::new(),
            hierarchy: DomainHierarchy::default(),
            public_read: BTreeSet::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialContext {
    pub principal: PrincipalRef,
    pub audience: ServiceId,
    pub grants: Attenuation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerContext {
    pub grants: Attenuation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRef {
    pub kind: ResourceKind,
    pub id: Option<ResourceId>,
    pub domain: DomainId,
}

/// Trusted current subject facts supplied by the caller for one request.
///
/// The caller is responsible for the provenance of every field: `principal`
/// and `domain` are the exact target of the current lookup, and the domain
/// existence plus the effective (including inherited) role set must come from
/// authoritative current data, never from client claims or an old snapshot.
/// `Authority::Resolved` trusts that provenance to admit a syntactically valid
/// domain that is not registered in the authorizer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRoles {
    pub principal: PrincipalRef,
    pub domain: DomainId,
    pub roles: BTreeSet<RoleId>,
}

impl ResolvedRoles {
    pub fn new(
        principal: PrincipalRef,
        domain: impl Into<DomainId>,
        roles: impl IntoIterator<Item = impl Into<RoleId>>,
    ) -> Self {
        Self {
            principal,
            domain: domain.into(),
            roles: roles.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthzRequest {
    pub resource: ResourceRef,
    pub action: Action,
    pub audience: ServiceId,
    pub credential: Option<CredentialContext>,
    pub server: Option<ServerContext>,
}

/// Where the subject identity, domain, and current roles come from.
///
/// `Snapshot` carries the request identity and the revision observed from the
/// trusted assignment source. `Registered` and `Resolved` use principal-bound
/// current roles; `Registered` requires a registered domain, while `Resolved`
/// validates the domain syntactically and trusts the caller's proof that it
/// currently exists. Neither live variant has an assignment revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authority<'a> {
    Snapshot {
        subject: Subject,
        domain: DomainId,
        facts_revision: FactsRevision,
    },
    Registered(&'a ResolvedRoles),
    Resolved(&'a ResolvedRoles),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    UnknownDomain,
    UnknownResource,
    UnknownAction,
    CrossDomainResource,
    NoSubjectAuthority,
    StaleFacts,
    InvalidAudience,
    InvalidDomain,
    UnknownRole,
    CredentialPrincipalMismatch,
    CredentialAudienceMismatch,
    CredentialGrantMissing,
    ServerGrantMissing,
    EngineError,
}

impl fmt::Display for DenyReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self {
            Self::UnknownDomain => "unknown domain",
            Self::UnknownResource => "unknown resource",
            Self::UnknownAction => "unknown action",
            Self::CrossDomainResource => "resource belongs to a different domain",
            Self::NoSubjectAuthority => "subject has no authority",
            Self::StaleFacts => "stale facts revision",
            Self::InvalidAudience => "invalid audience",
            Self::InvalidDomain => "invalid domain",
            Self::UnknownRole => "unknown role",
            Self::CredentialPrincipalMismatch => "credential principal mismatch",
            Self::CredentialAudienceMismatch => "credential audience mismatch",
            Self::CredentialGrantMissing => "credential grant missing",
            Self::ServerGrantMissing => "server grant missing",
            Self::EngineError => "authorization engine error",
        };
        formatter.write_str(description)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(DenyReason),
}

impl Decision {
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }
}
