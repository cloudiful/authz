use std::fmt;

use crate::{DomainId, RoleId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitError {
    DuplicateRole(RoleId),
    DuplicateDomain(DomainId),
    UnknownRole(RoleId),
    UnknownDomain(DomainId),
    InvalidPublicReadGrant,
    HierarchyCycle,
    InvalidIdentifier(String),
    Engine(String),
}

impl fmt::Display for InitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateRole(role) => write!(formatter, "duplicate role: {}", role.0),
            Self::DuplicateDomain(domain) => write!(formatter, "duplicate domain: {}", domain.0),
            Self::UnknownRole(role) => write!(formatter, "unknown role: {}", role.0),
            Self::UnknownDomain(domain) => write!(formatter, "unknown domain: {}", domain.0),
            Self::InvalidPublicReadGrant => {
                formatter.write_str("public-read grant references an unknown domain")
            }
            Self::HierarchyCycle => formatter.write_str("domain hierarchy contains a cycle"),
            Self::InvalidIdentifier(value) => write!(formatter, "invalid identifier: {value}"),
            Self::Engine(message) => write!(formatter, "authorization engine error: {message}"),
        }
    }
}

impl std::error::Error for InitError {}
