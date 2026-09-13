use crate::{AuthError, MAX_SAFE_INTEGER, decode_base64url, decode_p256_spki, invalid};
use serde::{Deserialize, Deserializer, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Register,
    Renew,
    Deregister,
    AcmeChallengeCreate,
    AcmeChallengeDelete,
    OperatorRecords,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Action {
    pub request_id: String,
    pub audience: String,
    pub grant_id: String,
    pub zone: String,
    pub signer_spki_der: String,
    #[serde(flatten)]
    pub parameters: ActionParameters,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "parameters", rename_all = "snake_case")]
pub enum ActionParameters {
    Register(RegisterParameters),
    Renew(RenewParameters),
    Deregister(DeregisterParameters),
    AcmeChallengeCreate(AcmeChallengeCreateParameters),
    AcmeChallengeDelete(AcmeChallengeDeleteParameters),
    OperatorRecords(OperatorParameters),
}

// Flatten + deny_unknown_fields is not a safe deserialization boundary. Parse
// the outer object explicitly, then deserialize the exact operation schema.
impl<'de> Deserialize<'de> for Action {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawAction {
            request_id: String,
            audience: String,
            grant_id: String,
            zone: String,
            signer_spki_der: String,
            operation: Operation,
            parameters: serde_json::Value,
        }
        let raw = RawAction::deserialize(deserializer)?;
        fn parameters<T: serde::de::DeserializeOwned, E: serde::de::Error>(
            value: serde_json::Value,
        ) -> Result<T, E> {
            serde_json::from_value(value).map_err(E::custom)
        }
        let p = match raw.operation {
            Operation::Register => {
                ActionParameters::Register(parameters::<_, D::Error>(raw.parameters)?)
            }
            Operation::Renew => ActionParameters::Renew(parameters::<_, D::Error>(raw.parameters)?),
            Operation::Deregister => {
                ActionParameters::Deregister(parameters::<_, D::Error>(raw.parameters)?)
            }
            Operation::AcmeChallengeCreate => {
                ActionParameters::AcmeChallengeCreate(parameters::<_, D::Error>(raw.parameters)?)
            }
            Operation::AcmeChallengeDelete => {
                ActionParameters::AcmeChallengeDelete(parameters::<_, D::Error>(raw.parameters)?)
            }
            Operation::OperatorRecords => {
                ActionParameters::OperatorRecords(parameters::<_, D::Error>(raw.parameters)?)
            }
        };
        Ok(Self {
            request_id: raw.request_id,
            audience: raw.audience,
            grant_id: raw.grant_id,
            zone: raw.zone,
            signer_spki_der: raw.signer_spki_der,
            parameters: p,
        })
    }
}

impl ActionParameters {
    pub fn operation(&self) -> Operation {
        match self {
            Self::Register(_) => Operation::Register,
            Self::Renew(_) => Operation::Renew,
            Self::Deregister(_) => Operation::Deregister,
            Self::AcmeChallengeCreate(_) => Operation::AcmeChallengeCreate,
            Self::AcmeChallengeDelete(_) => Operation::AcmeChallengeDelete,
            Self::OperatorRecords(_) => Operation::OperatorRecords,
        }
    }
    pub fn evidence_digest(&self) -> Option<&str> {
        match self {
            Self::Register(p) => Some(&p.evidence_digest),
            Self::Renew(p) => p.evidence_digest.as_deref(),
            _ => None,
        }
    }
    pub fn evidence_profile(&self) -> Option<&str> {
        match self {
            Self::Register(p) => Some(&p.evidence_profile),
            Self::Renew(p) => p.evidence_profile.as_deref(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Addresses {
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterParameters {
    pub role: String,
    pub mailbox_domain: String,
    pub service_host: String,
    pub addresses: Addresses,
    pub ports: Vec<u16>,
    pub lease_seconds: u64,
    pub evidence_profile: String,
    pub evidence_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenewParameters {
    pub registration_id: String,
    pub requested_lease_seconds: u64,
    /// Optional paired fields permit a signed fresh appraisal at renewal.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "optional_string"
    )]
    pub evidence_profile: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "optional_string"
    )]
    pub evidence_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeregisterParameters {
    pub registration_id: String,
    pub selected_ports: Vec<u16>,
    pub withdraw_all: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeChallengeCreateParameters {
    pub registration_id: String,
    pub order_id: String,
    pub name: String,
    pub txt_value: String,
    pub ttl: u32,
    pub lifetime_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeChallengeDeleteParameters {
    pub challenge_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum OperatorRecordType {
    A,
    Aaaa,
    Ns,
    Cname,
    Mx,
    Txt,
    Caa,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationAction {
    Replace,
    Add,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordMutation {
    pub action: MutationAction,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: OperatorRecordType,
    pub ttl: u32,
    pub rdata_strings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorParameters {
    pub expected_serial: u32,
    pub mutations: Vec<RecordMutation>,
}

pub fn validate_hex_digest(text: &str) -> Result<(), AuthError> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("lowercase hex SHA-256"));
    }
    Ok(())
}

pub fn validate_identifier(text: &str) -> Result<(), AuthError> {
    if text.is_empty()
        || text.len() > 128
        || !text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:.".contains(&b))
    {
        return Err(invalid("identifier"));
    }
    Ok(())
}

/// Canonical absolute lowercase ASCII DNS names. Underscores are accepted only
/// for operator record owner labels; host and zone names use hostname labels.
pub fn validate_name(name: &str, allow_underscore: bool) -> Result<(), AuthError> {
    if name.is_empty() || name.len() > 254 || !name.ends_with('.') || !name.is_ascii() {
        return Err(invalid("canonical DNS name"));
    }
    if name == "." {
        return Err(invalid("root zone is outside service scope"));
    }
    for label in name[..name.len() - 1].split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'-'
                    || (allow_underscore && b == b'_')
            })
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return Err(invalid("canonical DNS label"));
        }
    }
    Ok(())
}

pub fn name_in_zone(name: &str, zone: &str) -> bool {
    name == zone
        || (name.len() > zone.len()
            && name.ends_with(zone)
            && name.as_bytes()[name.len() - zone.len() - 1] == b'.')
}

pub fn validate_ports(ports: &[u16], allow_empty: bool) -> Result<(), AuthError> {
    if (!allow_empty && ports.is_empty())
        || ports.len() > 128
        || ports.contains(&0)
        || ports.windows(2).any(|p| p[0] >= p[1])
    {
        return Err(invalid("ports must be sorted, distinct and nonzero"));
    }
    Ok(())
}

pub fn validate_lease(value: u64) -> Result<(), AuthError> {
    if value == 0 || value > MAX_SAFE_INTEGER {
        return Err(invalid("lease seconds"));
    }
    Ok(())
}

impl Addresses {
    pub fn validate(&self) -> Result<(), AuthError> {
        if self.ipv4.len() + self.ipv6.len() == 0 || self.ipv4.len() + self.ipv6.len() > 128 {
            return Err(invalid("address count"));
        }
        let mut last4 = None;
        for address in &self.ipv4 {
            let ip = address.parse::<Ipv4Addr>().map_err(|_| invalid("IPv4"))?;
            if ip.to_string() != *address || last4.is_some_and(|last| last >= ip) {
                return Err(invalid(
                    "IPv4 must be canonical, numerically sorted and distinct",
                ));
            }
            last4 = Some(ip);
        }
        let mut last6 = None;
        for address in &self.ipv6 {
            let ip = address.parse::<Ipv6Addr>().map_err(|_| invalid("IPv6"))?;
            if ip.to_string() != *address || last6.is_some_and(|last| last >= ip) {
                return Err(invalid(
                    "IPv6 must be RFC 5952, numerically sorted and distinct",
                ));
            }
            last6 = Some(ip);
        }
        Ok(())
    }
}

impl Action {
    pub fn operation(&self) -> Operation {
        self.parameters.operation()
    }
    pub fn validate(&self) -> Result<(), AuthError> {
        validate_identifier(&self.request_id)?;
        validate_identifier(&self.grant_id)?;
        if self.audience.is_empty()
            || self.audience.len() > 512
            || !self.audience.is_ascii()
            || self
                .audience
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err(invalid("audience"));
        }
        validate_name(&self.zone, false)?;
        decode_p256_spki(&self.signer_spki_der)?;
        match &self.parameters {
            ActionParameters::Register(p) => {
                validate_identifier(&p.role)?;
                validate_name(&p.mailbox_domain, false)?;
                validate_name(&p.service_host, false)?;
                if !name_in_zone(&p.mailbox_domain, &self.zone)
                    || !name_in_zone(&p.service_host, &self.zone)
                {
                    return Err(invalid("registration names outside zone"));
                }
                // Reserve room for the longest TLSA owner prefix (_65535._tcp.).
                if p.service_host.len() + 12 > 254 {
                    return Err(invalid("service host exceeds TLSA owner limit"));
                }
                p.addresses.validate()?;
                validate_ports(&p.ports, false)?;
                validate_lease(p.lease_seconds)?;
                validate_identifier(&p.evidence_profile)?;
                validate_hex_digest(&p.evidence_digest)?;
            }
            ActionParameters::Renew(p) => {
                validate_identifier(&p.registration_id)?;
                validate_lease(p.requested_lease_seconds)?;
                match (&p.evidence_profile, &p.evidence_digest) {
                    (Some(profile), Some(digest)) => {
                        validate_identifier(profile)?;
                        validate_hex_digest(digest)?;
                    }
                    (None, None) => {}
                    _ => return Err(invalid("renew evidence profile and digest must be paired")),
                }
            }
            ActionParameters::Deregister(p) => {
                validate_identifier(&p.registration_id)?;
                validate_ports(&p.selected_ports, p.withdraw_all)?;
                if p.withdraw_all && !p.selected_ports.is_empty() {
                    return Err(invalid("withdraw_all requires empty selected_ports"));
                }
                if p.reason.is_empty()
                    || p.reason.len() > 256
                    || p.reason.chars().any(char::is_control)
                {
                    return Err(invalid("reason"));
                }
            }
            ActionParameters::AcmeChallengeCreate(p) => {
                validate_identifier(&p.registration_id)?;
                validate_identifier(&p.order_id)?;
                validate_name(&p.name, false)?;
                if !name_in_zone(&p.name, &self.zone) || p.name.len() + 16 > 254 {
                    return Err(invalid("challenge name"));
                }
                if decode_base64url(&p.txt_value, 32)?.len() != 32 {
                    return Err(invalid("ACME txt_value must encode SHA-256"));
                }
                validate_lease(p.lifetime_seconds)?;
                if p.ttl == 0 || u64::from(p.ttl) > p.lifetime_seconds {
                    return Err(invalid("challenge TTL"));
                }
            }
            ActionParameters::AcmeChallengeDelete(p) => validate_identifier(&p.challenge_id)?,
            ActionParameters::OperatorRecords(p) => {
                if p.mutations.is_empty() || p.mutations.len() > 128 {
                    return Err(invalid("mutation count"));
                }
                let mut owners = std::collections::BTreeSet::new();
                for mutation in &p.mutations {
                    validate_name(&mutation.name, true)?;
                    if !name_in_zone(&mutation.name, &self.zone) {
                        return Err(invalid("mutation outside zone"));
                    }
                    if !owners.insert((&mutation.name, mutation.record_type)) {
                        return Err(invalid("duplicate RRset mutation"));
                    }
                    if mutation.ttl == 0
                        || mutation.rdata_strings.len() > 128
                        || (mutation.rdata_strings.is_empty()
                            && mutation.action != MutationAction::Delete)
                        || mutation.rdata_strings.iter().any(|s| {
                            s.is_empty()
                                || s.len() > 65535
                                || s.chars().any(|c| c == '\0' || c == '\r' || c == '\n')
                        })
                    {
                        return Err(invalid("record mutation"));
                    }
                    let unique: std::collections::BTreeSet<_> =
                        mutation.rdata_strings.iter().collect();
                    if unique.len() != mutation.rdata_strings.len() {
                        return Err(invalid("duplicate RDATA"));
                    }
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn optional_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}
