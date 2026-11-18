use std::collections::BTreeSet;

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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Grant {
    pub domain: DomainId,
    pub resource: ResourceKind,
    pub resource_id: Option<ResourceId>,
    pub action: Action,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attenuation {
    Unrestricted,
    Grants(BTreeSet<Grant>),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRoles {
    pub principal: PrincipalRef,
    pub domain: DomainId,
    pub roles: BTreeSet<RoleId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthzRequest {
    pub subject: Subject,
    pub domain: DomainId,
    pub resource: ResourceRef,
    pub action: Action,
    pub audience: ServiceId,
    pub facts_revision: FactsRevision,
    pub credential: Option<CredentialContext>,
    pub server: Option<ServerContext>,
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
    PublicReadNotAllowed,
    LivePrincipalMismatch,
    LiveDomainMismatch,
    UnknownRole,
    CredentialPrincipalMismatch,
    CredentialAudienceMismatch,
    CredentialGrantMissing,
    ServerGrantMissing,
    EngineError,
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
