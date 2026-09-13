use adns_wire::*;
use std::collections::{BTreeMap, BTreeSet};
/// Contributions are keyed by registration and owner. Withdrawal cannot erase
/// another registration's concurrent key, including when both use one digest.
#[derive(Default)]
pub struct TlsaOverlap {
    contributions: BTreeMap<WireName, BTreeMap<String, BTreeSet<[u8; 32]>>>,
}
impl TlsaOverlap {
    pub fn add(
        &mut self,
        registration: &str,
        host: &WireName,
        ports: &[u16],
        digest: [u8; 32],
    ) -> Result<(), DnsError> {
        let names: Vec<_> = ports
            .iter()
            .map(|p| {
                host.prepend_label(b"_tcp")?
                    .prepend_label(format!("_{p}").as_bytes())
            })
            .collect::<Result<_, _>>()?;
        for name in names {
            self.contributions
                .entry(name)
                .or_default()
                .entry(registration.to_owned())
                .or_default()
                .insert(digest);
        }
        Ok(())
    }
    pub fn withdraw(&mut self, registration: &str, owners: Option<&[WireName]>) {
        self.contributions.retain(|name, contributions| {
            if owners.is_none_or(|o| o.contains(name)) {
                contributions.remove(registration);
            }
            !contributions.is_empty()
        });
    }
    pub fn records(&self, ttl: u32) -> Vec<ResourceRecord> {
        let mut out = Vec::new();
        for (name, contributions) in &self.contributions {
            let digests: BTreeSet<_> = contributions.values().flat_map(|s| s.iter()).collect();
            for digest in digests {
                out.push(ResourceRecord {
                    name: *name,
                    rtype: RecordType::Tlsa,
                    rclass: RecordClass::In,
                    ttl,
                    rdata: RData::Tlsa(TlsaData {
                        usage: 3,
                        selector: 1,
                        matching_type: 1,
                        certificate_association_data: digest.to_vec(),
                    }),
                });
            }
        }
        out
    }
}
