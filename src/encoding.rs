use crate::{PrincipalRef, RoleId};

pub(crate) fn validate_identifier(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("identifier must not be empty".to_owned());
    }
    if value.chars().any(char::is_control) {
        return Err("identifier must not contain control characters".to_owned());
    }
    Ok(())
}

pub(crate) fn validate_service_id(value: &str) -> Result<(), String> {
    validate_identifier(value)?;
    if value == "*" {
        return Err("service audience must not be a wildcard".to_owned());
    }
    Ok(())
}

pub(crate) fn encode_principal(principal: &PrincipalRef) -> String {
    let kind = principal.kind.as_str();
    format!(
        "p/{}:{}/{}:{}",
        kind.len(),
        kind,
        principal.id.0.len(),
        principal.id.0
    )
}

pub(crate) fn encode_role(role: &RoleId) -> String {
    format!("r/{}:{}", role.0.len(), role.0)
}

#[cfg(test)]
mod tests {
    use super::{encode_principal, encode_role};
    use crate::{PrincipalId, PrincipalKind, PrincipalRef, RoleId};

    fn principal(kind: PrincipalKind, id: &str) -> PrincipalRef {
        PrincipalRef {
            kind,
            id: PrincipalId::new(id),
        }
    }

    #[test]
    fn principal_and_role_namespaces_never_collide() {
        let principal = encode_principal(&principal(PrincipalKind::Human, "viewer"));
        let role = encode_role(&RoleId::new("viewer"));
        assert_ne!(principal, role);
        assert!(principal.starts_with("p/"));
        assert!(role.starts_with("r/"));
    }

    #[test]
    fn length_prefixes_distinguish_ambiguous_components() {
        assert_ne!(
            encode_principal(&principal(PrincipalKind::Human, "a/b")),
            encode_principal(&principal(PrincipalKind::Human, "a"))
        );
        assert_ne!(
            encode_principal(&principal(PrincipalKind::Service, "42")),
            encode_principal(&principal(PrincipalKind::Human, "42"))
        );
        assert_ne!(
            encode_role(&RoleId::new("a:b")),
            encode_role(&RoleId::new("a"))
        );
    }
}
