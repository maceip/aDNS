use crate::{
    Action, ActionParameters, AuthError, MAX_SAFE_INTEGER, Operation, OperatorRecordType,
    RegisterParameters, decode_p256_spki, invalid, name_in_zone, sha256_hex, validate_hex_digest,
    validate_identifier, validate_lease, validate_name, validate_ports,
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Install or revoke only through CCF governance. Exact name lists are used;
/// suffix matching is NOT an authorization grant. Separate grants should be
/// issued for service owners, certificate issuers and zone operators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerGrant {
    pub grant_id: String,
    pub subject_spki_sha256: String,
    pub zones: Vec<String>,
    pub mailbox_domains: Vec<String>,
    pub service_hosts: Vec<String>,
    pub roles: Vec<String>,
    pub address_cidrs: Vec<String>,
    pub ports: Vec<u16>,
    pub allowed_operations: Vec<Operation>,
    pub acme_names: Vec<String>,
    pub operator_names: Vec<String>,
    pub operator_record_types: Vec<OperatorRecordType>,
    pub max_lease_seconds: u64,
    pub max_challenge_lifetime_seconds: u64,
    pub valid_from: u64,
    pub valid_until: u64,
    pub revoked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cidr {
    V4 { network: Ipv4Addr, prefix: u8 },
    V6 { network: Ipv6Addr, prefix: u8 },
}

impl Cidr {
    /// Reject host bits, leading zeroes and alternate
    /// spellings so governance review sees the precise network being granted.
    pub fn parse(text: &str) -> Result<Self, AuthError> {
        let (network, prefix) = text.split_once('/').ok_or_else(|| invalid("CIDR"))?;
        let prefix: u8 = prefix.parse().map_err(|_| invalid("CIDR prefix"))?;
        let address: IpAddr = network.parse().map_err(|_| invalid("CIDR address"))?;
        if format!("{address}/{prefix}") != text {
            return Err(invalid("canonical CIDR"));
        }
        match address {
            IpAddr::V4(network) if prefix <= 32 => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                if u32::from(network) & mask != u32::from(network) {
                    return Err(invalid("CIDR host bits"));
                }
                Ok(Self::V4 { network, prefix })
            }
            IpAddr::V6(network) if prefix <= 128 => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                if u128::from(network) & mask != u128::from(network) {
                    return Err(invalid("CIDR host bits"));
                }
                Ok(Self::V6 { network, prefix })
            }
            _ => Err(invalid("CIDR prefix")),
        }
    }
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self, address) {
            (Self::V4 { network, prefix }, IpAddr::V4(address)) => {
                let mask = if *prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                u32::from(address) & mask == u32::from(*network)
            }
            (Self::V6 { network, prefix }, IpAddr::V6(address)) => {
                let mask = if *prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                u128::from(address) & mask == u128::from(*network)
            }
            _ => false,
        }
    }
}

fn unique<T: Ord>(items: &[T]) -> bool {
    items.len() <= 512
        && items
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == items.len()
}

impl OwnerGrant {
    pub fn validate(&self) -> Result<(), AuthError> {
        validate_identifier(&self.grant_id)?;
        validate_hex_digest(&self.subject_spki_sha256)?;
        if self.zones.is_empty()
            || !unique(&self.zones)
            || self.allowed_operations.is_empty()
            || !unique(&self.allowed_operations)
            || !unique(&self.mailbox_domains)
            || !unique(&self.service_hosts)
            || !unique(&self.roles)
            || !unique(&self.address_cidrs)
            || !unique(&self.acme_names)
            || !unique(&self.operator_names)
            || !unique(&self.operator_record_types)
        {
            return Err(invalid("grant list"));
        }
        for zone in &self.zones {
            validate_name(zone, false)?;
        }
        for name in self
            .mailbox_domains
            .iter()
            .chain(&self.service_hosts)
            .chain(&self.acme_names)
        {
            validate_name(name, false)?;
            if !self.zones.iter().any(|zone| name_in_zone(name, zone)) {
                return Err(invalid("grant name outside granted zones"));
            }
        }
        for name in &self.operator_names {
            validate_name(name, true)?;
            if !self.zones.iter().any(|zone| name_in_zone(name, zone)) {
                return Err(invalid("operator name outside granted zones"));
            }
        }
        for role in &self.roles {
            validate_identifier(role)?;
        }
        for cidr in &self.address_cidrs {
            Cidr::parse(cidr)?;
        }
        validate_ports(&self.ports, true)?;
        validate_lease(self.max_lease_seconds)?;
        validate_lease(self.max_challenge_lifetime_seconds)?;
        if self.valid_from >= self.valid_until || self.valid_until > MAX_SAFE_INTEGER {
            return Err(invalid("grant validity"));
        }
        Ok(())
    }
}

fn denied(reason: &str) -> AuthError {
    AuthError::GrantDenied(reason.into())
}

/// Stateless checks for nonce issuance and mutation admission. For operations
/// referencing an existing registration/challenge, also validate that stored
/// target with the functions below INSIDE the mutation transaction.
pub fn authorize_action(
    action: &Action,
    grant: &OwnerGrant,
    audience: &str,
    now: u64,
) -> Result<(), AuthError> {
    action.validate()?;
    grant.validate()?;
    if action.audience != audience {
        return Err(AuthError::AudienceMismatch);
    }
    if action.grant_id != grant.grant_id {
        return Err(denied("grant ID"));
    }
    if grant.revoked || now < grant.valid_from || now >= grant.valid_until {
        return Err(denied("expired, future or revoked grant"));
    }
    if sha256_hex(&decode_p256_spki(&action.signer_spki_der)?) != grant.subject_spki_sha256 {
        return Err(denied("signer key"));
    }
    if !grant.zones.contains(&action.zone)
        || !grant.allowed_operations.contains(&action.operation())
    {
        return Err(denied("zone or operation"));
    }
    match &action.parameters {
        ActionParameters::Register(p) => {
            authorize_registration_scope(p, grant)?;
            if p.lease_seconds > grant.max_lease_seconds {
                return Err(denied("maximum lease"));
            }
        }
        ActionParameters::Renew(p) => {
            if p.requested_lease_seconds > grant.max_lease_seconds {
                return Err(denied("maximum lease"));
            }
        }
        ActionParameters::Deregister(p) => {
            if p.selected_ports
                .iter()
                .any(|port| !grant.ports.contains(port))
            {
                return Err(denied("port"));
            }
        }
        ActionParameters::AcmeChallengeCreate(p) => {
            if !grant.acme_names.contains(&p.name) {
                return Err(denied("exact ACME name"));
            }
            if p.lifetime_seconds > grant.max_challenge_lifetime_seconds {
                return Err(denied("maximum challenge lifetime"));
            }
        }
        ActionParameters::AcmeChallengeDelete(_) => {}
        ActionParameters::OperatorRecords(p) => {
            if p.mutations.iter().any(|m| {
                !grant.operator_names.contains(&m.name)
                    || !grant.operator_record_types.contains(&m.record_type)
            }) {
                return Err(denied("operator owner or type"));
            }
        }
    }
    Ok(())
}

/// The referenced registration must have been admitted under this grant and
/// key. Do not use caller-supplied metadata for any of these target arguments.
pub fn authorize_registration_target(
    action: &Action,
    registration_grant_id: &str,
    registration_spki_sha256: &str,
    registration_zone: &str,
) -> Result<(), AuthError> {
    if !matches!(
        action.parameters,
        ActionParameters::Renew(_) | ActionParameters::Deregister(_)
    ) {
        return Err(denied("wrong registration operation"));
    }
    if action.grant_id != registration_grant_id
        || action.zone != registration_zone
        || sha256_hex(&decode_p256_spki(&action.signer_spki_der)?) != registration_spki_sha256
    {
        return Err(denied("registration ownership"));
    }
    Ok(())
}

/// An issuer may challenge a registration owned by a separate service grant,
/// but only its stored active service hostname and zone. authorize_action has
/// already checked this issuer's exact acme_names delegation.
pub fn authorize_acme_registration_target(
    action: &Action,
    registration_zone: &str,
    registration_service_host: &str,
    registration_active: bool,
) -> Result<(), AuthError> {
    let ActionParameters::AcmeChallengeCreate(p) = &action.parameters else {
        return Err(denied("wrong ACME operation"));
    };
    if !registration_active
        || action.zone != registration_zone
        || p.name != registration_service_host
    {
        return Err(denied("ACME registration target"));
    }
    Ok(())
}

pub fn authorize_challenge_target(
    action: &Action,
    challenge_grant_id: &str,
    challenge_zone: &str,
) -> Result<(), AuthError> {
    if !matches!(action.parameters, ActionParameters::AcmeChallengeDelete(_)) {
        return Err(denied("wrong challenge operation"));
    }
    if action.grant_id != challenge_grant_id || action.zone != challenge_zone {
        return Err(denied("challenge ownership"));
    }
    Ok(())
}

/// Every admitted/renewed lease is capped by all independent validity bounds.
/// The caller must demand new evidence once its appraisal deadline has passed.
pub fn bounded_lease_expiration(
    admission: u64,
    requested_seconds: u64,
    grant_valid_until: u64,
    policy_valid_until: u64,
    reappraisal_deadline: u64,
) -> Result<u64, AuthError> {
    validate_lease(requested_seconds)?;
    let requested = admission
        .checked_add(requested_seconds)
        .filter(|v| *v <= MAX_SAFE_INTEGER)
        .ok_or_else(|| invalid("lease overflow"))?;
    if [grant_valid_until, policy_valid_until, reappraisal_deadline]
        .iter()
        .any(|v| *v > MAX_SAFE_INTEGER)
    {
        return Err(invalid("validity timestamp"));
    }
    let expires_at = requested
        .min(grant_valid_until)
        .min(policy_valid_until)
        .min(reappraisal_deadline);
    if expires_at <= admission {
        return Err(denied("validity requires reappraisal"));
    }
    Ok(expires_at)
}

/// Recheck stored service scope on renewal without requiring Register permission.
/// Call authorize_action first for current key, operation and validity checks.
/// The requested renewal duration is checked by authorize_action separately.
pub fn authorize_registration_scope(
    parameters: &RegisterParameters,
    grant: &OwnerGrant,
) -> Result<(), AuthError> {
    grant.validate()?;
    validate_name(&parameters.mailbox_domain, false)?;
    validate_name(&parameters.service_host, false)?;
    parameters.addresses.validate()?;
    validate_ports(&parameters.ports, false)?;
    if !grant.mailbox_domains.contains(&parameters.mailbox_domain)
        || !grant.service_hosts.contains(&parameters.service_host)
        || !grant.roles.contains(&parameters.role)
    {
        return Err(denied("exact names or role"));
    }
    if parameters
        .ports
        .iter()
        .any(|port| !grant.ports.contains(port))
    {
        return Err(denied("port"));
    }
    let cidrs = grant
        .address_cidrs
        .iter()
        .map(|c| Cidr::parse(c))
        .collect::<Result<Vec<_>, _>>()?;
    for address in parameters
        .addresses
        .ipv4
        .iter()
        .chain(&parameters.addresses.ipv6)
    {
        let address = address.parse().map_err(|_| invalid("IP address"))?;
        if !cidrs.iter().any(|cidr| cidr.contains(address)) {
            return Err(denied("address CIDR"));
        }
    }
    Ok(())
}
