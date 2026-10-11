//! Tenant isolation and role-based access control.
//!
//! Every request into the platform carries a [`TenantContext`]: who is asking, for which
//! tenant, in what role. Two rules follow from it:
//!
//! * **RBAC** ([`authorize`]): the role must grant the [`Permission`] for the action.
//! * **Tenant isolation** ([`TenantContext::guard`]): a context may only touch data in its
//!   own tenant; a cross-tenant access is refused before any query runs.
//!
//! These are defence in depth alongside database row-level security — the same philosophy
//! the AuthZ Fuzzer tests other services for.

use lattivant_event::TenantId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A role within a tenant, ordered by privilege.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Read-only within the tenant.
    Viewer,
    /// Read and investigate.
    Analyst,
    /// Full read/write within the tenant, including running scans.
    Appsec,
    /// Tenant administrator.
    Admin,
}

impl Role {
    /// Numeric privilege level; higher is more privileged.
    pub fn level(self) -> u8 {
        match self {
            Role::Viewer => 0,
            Role::Analyst => 1,
            Role::Appsec => 2,
            Role::Admin => 3,
        }
    }

    /// Whether this role is at least as privileged as `other`.
    pub fn dominates(self, other: Role) -> bool {
        self.level() >= other.level()
    }
}

/// A sensitive action that requires a minimum role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Read events, findings and incidents.
    ReadEvents,
    /// Create and manage incidents and investigations.
    ManageIncidents,
    /// Start authorization scans.
    RunScan,
    /// Accept or clear findings (manage suppressions).
    ManageSuppressions,
    /// Manage tenant settings, members and credentials.
    AdministerTenant,
}

impl Permission {
    /// The least-privileged role that holds this permission.
    pub fn minimum_role(self) -> Role {
        match self {
            Permission::ReadEvents => Role::Viewer,
            Permission::ManageIncidents => Role::Analyst,
            Permission::RunScan => Role::Appsec,
            Permission::ManageSuppressions => Role::Appsec,
            Permission::AdministerTenant => Role::Admin,
        }
    }
}

/// Why an authorization or tenant check failed.
#[derive(Debug, Error, PartialEq)]
pub enum AccessError {
    /// The role does not hold the required permission.
    #[error("role {role:?} lacks permission {permission:?} (needs {needed:?})")]
    Forbidden {
        /// The caller's role.
        role: Role,
        /// The permission required.
        permission: Permission,
        /// The minimum role that would satisfy it.
        needed: Role,
    },
    /// The context tried to touch another tenant's data.
    #[error("tenant {actor:?} may not access data owned by {owner:?}")]
    CrossTenant {
        /// The requesting tenant.
        actor: String,
        /// The owning tenant.
        owner: String,
    },
}

/// The authenticated context for a request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantContext {
    /// The tenant this request acts for.
    pub tenant_id: TenantId,
    /// The id of the acting principal (non-secret).
    pub principal_id: String,
    /// The principal's role.
    pub role: Role,
}

impl TenantContext {
    /// Construct a context.
    pub fn new(tenant_id: impl Into<String>, principal_id: impl Into<String>, role: Role) -> Self {
        TenantContext {
            tenant_id: TenantId::new(tenant_id),
            principal_id: principal_id.into(),
            role,
        }
    }

    /// Check the role grants `permission`.
    pub fn require(&self, permission: Permission) -> Result<(), AccessError> {
        authorize(self.role, permission)
    }

    /// Check the context may touch data owned by `owner_tenant`.
    pub fn guard(&self, owner_tenant: &TenantId) -> Result<(), AccessError> {
        if &self.tenant_id == owner_tenant {
            Ok(())
        } else {
            Err(AccessError::CrossTenant {
                actor: self.tenant_id.to_string(),
                owner: owner_tenant.to_string(),
            })
        }
    }

    /// Require both a permission and tenant ownership in one call.
    pub fn require_on(
        &self,
        permission: Permission,
        owner_tenant: &TenantId,
    ) -> Result<(), AccessError> {
        self.require(permission)?;
        self.guard(owner_tenant)
    }
}

/// Whether a role holds a permission.
pub fn authorize(role: Role, permission: Permission) -> Result<(), AccessError> {
    let needed = permission.minimum_role();
    if role.dominates(needed) {
        Ok(())
    } else {
        Err(AccessError::Forbidden {
            role,
            permission,
            needed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_ordering() {
        assert!(Role::Admin.dominates(Role::Viewer));
        assert!(!Role::Viewer.dominates(Role::Appsec));
    }

    #[test]
    fn permission_matrix() {
        assert!(authorize(Role::Viewer, Permission::ReadEvents).is_ok());
        assert!(authorize(Role::Viewer, Permission::RunScan).is_err());
        assert!(authorize(Role::Appsec, Permission::RunScan).is_ok());
        assert!(authorize(Role::Appsec, Permission::AdministerTenant).is_err());
        assert!(authorize(Role::Admin, Permission::AdministerTenant).is_ok());
    }

    #[test]
    fn tenant_guard_blocks_cross_tenant() {
        let ctx = TenantContext::new("alpha", "alpha-admin", Role::Admin);
        assert!(ctx.guard(&TenantId::new("alpha")).is_ok());
        assert_eq!(
            ctx.guard(&TenantId::new("bravo")),
            Err(AccessError::CrossTenant {
                actor: "alpha".into(),
                owner: "bravo".into()
            })
        );
    }

    #[test]
    fn require_on_checks_permission_then_tenant() {
        let viewer = TenantContext::new("alpha", "v", Role::Viewer);
        // permission fails first
        assert!(matches!(
            viewer.require_on(Permission::RunScan, &TenantId::new("alpha")),
            Err(AccessError::Forbidden { .. })
        ));
        let appsec = TenantContext::new("alpha", "s", Role::Appsec);
        assert!(appsec.require_on(Permission::RunScan, &TenantId::new("alpha")).is_ok());
        assert!(matches!(
            appsec.require_on(Permission::RunScan, &TenantId::new("bravo")),
            Err(AccessError::CrossTenant { .. })
        ));
    }
}
