use crate::*;
use adns_wire::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
};

pub struct SignedZone {
    pub origin: WireName,
    pub records: Vec<ResourceRecord>,
    pub serial: u32,
    pub inception: u32,
    pub expiration: u32,
    mode: DenialMode,
    names: BTreeSet<WireName>,
    cuts: BTreeSet<WireName>,
    rrsets: BTreeMap<(WireName, RecordType), Vec<ResourceRecord>>,
    denial: BTreeMap<WireName, ResourceRecord>,
    hashes: BTreeMap<[u8; 20], WireName>,
}
#[derive(Debug, Clone)]
pub struct Resolution<'a> {
    pub rcode: u8,
    pub authoritative: bool,
    pub answers: Cow<'a, [ResourceRecord]>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}
impl Default for Resolution<'_> {
    fn default() -> Self {
        Self {
            rcode: 0,
            authoritative: true,
            answers: Cow::Borrowed(&[]),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }
}
impl SignedZone {
    pub fn sign(
        origin: WireName,
        records: Vec<ResourceRecord>,
        key: &SigningKey,
        now: u32,
        validity: u32,
        mode: DenialMode,
    ) -> Result<Self, DnssecError> {
        Self::sign_with_keys(origin, records, key, key, now, validity, mode)
    }
    pub fn sign_with_keys(
        origin: WireName,
        mut records: Vec<ResourceRecord>,
        ksk: &SigningKey,
        zsk: &SigningKey,
        now: u32,
        validity: u32,
        mode: DenialMode,
    ) -> Result<Self, DnssecError> {
        // Existing generated records are replaced as one snapshot.
        records.retain(|r| {
            !matches!(
                r.rtype,
                RecordType::Dnskey
                    | RecordType::Rrsig
                    | RecordType::Nsec
                    | RecordType::Nsec3
                    | RecordType::Nsec3Param
            )
        });
        if records.iter().any(|r| {
            r.rclass != RecordClass::In
                || !r.name.is_subdomain_of(&origin)
                || r.rdata.record_type() != Some(r.rtype)
                || matches!(
                    r.rtype,
                    RecordType::Opt
                        | RecordType::Tsig
                        | RecordType::Axfr
                        | RecordType::Ixfr
                        | RecordType::Any
                )
        }) {
            return Err(DnssecError::InvalidZone);
        }
        let soas: Vec<_> = records
            .iter()
            .filter(|r| r.rtype == RecordType::Soa)
            .collect();
        if soas.len() != 1
            || soas[0].name != origin
            || !records
                .iter()
                .any(|r| r.name == origin && r.rtype == RecordType::Ns)
        {
            return Err(DnssecError::InvalidZone);
        }
        let RData::Soa(soa) = &soas[0].rdata else {
            return Err(DnssecError::InvalidZone);
        };
        let serial = soa.serial;
        let ttl = soas[0].ttl.min(soa.minimum);
        let key_ttl = soas[0].ttl;
        let cuts: BTreeSet<_> = records
            .iter()
            .filter(|r| r.rtype == RecordType::Ns && r.name != origin)
            .map(|r| r.name)
            .collect();
        // No nested zone cuts or authoritative data beneath a delegation. Only
        // address glue for that delegation's NS targets is valid below cuts.
        for cut in &cuts {
            if cuts.iter().any(|p| p != cut && cut.is_subdomain_of(p)) {
                return Err(DnssecError::InvalidZone);
            }
            let targets: BTreeSet<_> = records
                .iter()
                .filter(|r| r.name == *cut && r.rtype == RecordType::Ns)
                .filter_map(|r| {
                    if let RData::Ns(n) = r.rdata {
                        Some(n)
                    } else {
                        None
                    }
                })
                .collect();
            if records.iter().any(|r| {
                r.name != *cut
                    && r.name.is_subdomain_of(cut)
                    && (!matches!(r.rtype, RecordType::A | RecordType::Aaaa)
                        || !targets.contains(&r.name))
            }) {
                return Err(DnssecError::InvalidZone);
            }
        }
        let same_key = ksk.dnskey(257) == zsk.dnskey(257);
        records.push(ResourceRecord::new(
            origin,
            key_ttl,
            RData::Dnskey(ksk.dnskey(257)),
        )?);
        if !same_key {
            records.push(ResourceRecord::new(
                origin,
                key_ttl,
                RData::Dnskey(zsk.dnskey(256)),
            )?);
        }
        if let DenialMode::Nsec3 { iterations, salt } = &mode {
            nsec3_hash(&origin, *iterations, salt)?;
            records.push(ResourceRecord::new(
                origin,
                0,
                RData::Nsec3Param(Nsec3ParamData {
                    hash_algorithm: 1,
                    flags: 0,
                    iterations: *iterations,
                    salt: salt.clone(),
                }),
            )?);
        }
        let mut names = BTreeSet::new();
        let mut types = BTreeMap::<WireName, BTreeSet<RecordType>>::new();
        for rr in &records {
            if cuts
                .iter()
                .any(|c| rr.name != *c && rr.name.is_subdomain_of(c))
            {
                continue;
            }
            types.entry(rr.name).or_default().insert(rr.rtype);
            let mut name = rr.name;
            loop {
                names.insert(name);
                if name == origin {
                    break;
                }
                name = name.parent().ok_or(DnssecError::InvalidZone)?;
            }
        }
        for (name, t) in &types {
            if t.contains(&RecordType::Cname) && (t.len() != 1 || *name == origin) {
                return Err(DnssecError::InvalidZone);
            }
        }
        let mut denial = BTreeMap::new();
        let mut hashes = BTreeMap::new();
        match &mode {
            DenialMode::Nsec => {
                let ordered: Vec<_> = names.iter().copied().collect();
                for (i, &name) in ordered.iter().enumerate() {
                    let mut bitmap = types.get(&name).cloned().unwrap_or_default();
                    bitmap.extend([RecordType::Nsec, RecordType::Rrsig]);
                    let rr = ResourceRecord::new(
                        name,
                        ttl,
                        RData::Nsec(NsecData {
                            next_domain_name: ordered[(i + 1) % ordered.len()],
                            types: bitmap.into_iter().collect(),
                        }),
                    )?;
                    denial.insert(name, rr.clone());
                    records.push(rr);
                }
            }
            DenialMode::Nsec3 { iterations, salt } => {
                for name in &names {
                    if hashes
                        .insert(nsec3_hash(name, *iterations, salt)?, *name)
                        .is_some()
                    {
                        return Err(DnssecError::HashCollision);
                    }
                }
                let ordered: Vec<_> = hashes.keys().copied().collect();
                for (i, hash) in ordered.iter().enumerate() {
                    let original = hashes[hash];
                    let mut bitmap = types.get(&original).cloned().unwrap_or_default();
                    if !bitmap.is_empty()
                        && (!cuts.contains(&original) || bitmap.contains(&RecordType::Ds))
                    {
                        bitmap.insert(RecordType::Rrsig);
                    }
                    let owner = origin.prepend_label(base32hex_encode(hash).as_bytes())?;
                    let rr = ResourceRecord::new(
                        owner,
                        ttl,
                        RData::Nsec3(Nsec3Data {
                            hash_algorithm: 1,
                            flags: 0,
                            iterations: *iterations,
                            salt: salt.clone(),
                            next_hashed_owner: ordered[(i + 1) % ordered.len()].to_vec(),
                            types: bitmap.into_iter().collect(),
                        }),
                    )?;
                    denial.insert(original, rr.clone());
                    records.push(rr);
                }
            }
        }
        let mut rrsets = BTreeMap::<(WireName, RecordType), Vec<ResourceRecord>>::new();
        for rr in records {
            rrsets.entry((rr.name, rr.rtype)).or_default().push(rr);
        }
        for ((name, t), rrset) in &mut rrsets {
            let first = &rrset[0];
            if rrset.iter().any(|r| r.ttl != first.ttl) {
                return Err(DnssecError::InvalidZone);
            }
            let mut sorted: Vec<_> = rrset
                .iter()
                .map(|r| Ok((r.rdata.to_wire()?, r.clone())))
                .collect::<Result<_, DnsError>>()?;
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            sorted.dedup_by(|a, b| a.0 == b.0);
            *rrset = sorted.into_iter().map(|(_, r)| r).collect();
            if *t == RecordType::Cname && rrset.len() != 1 {
                return Err(DnssecError::InvalidZone);
            }
            if cuts.iter().any(|c| name != c && name.is_subdomain_of(c))
                || (*t == RecordType::Ns && cuts.contains(name))
            {
                continue;
            }
            let signer = if *t == RecordType::Dnskey { ksk } else { zsk };
            let flags = if *t == RecordType::Dnskey || same_key {
                257
            } else {
                256
            };
            let sig = signer.sign_rrset(rrset, origin, flags, now, validity)?;
            rrset.push(sig);
        }
        let records = rrsets.values().flatten().cloned().collect();
        Ok(Self {
            origin,
            records,
            serial,
            inception: now.wrapping_sub(300),
            expiration: now.wrapping_add(validity),
            mode,
            names,
            cuts,
            rrsets,
            denial,
            hashes,
        })
    }
    /// Zero-allocation exact lookup; includes the applicable RRSIG as last RR.
    pub fn exact_rrset(&self, name: &WireName, rtype: RecordType) -> Option<&[ResourceRecord]> {
        self.rrsets.get(&(*name, rtype)).map(Vec::as_slice)
    }
    pub fn name_exists(&self, name: &WireName) -> bool {
        self.names.contains(name)
    }
    pub fn find_closest_encloser(
        &self,
        name: &WireName,
    ) -> Result<(WireName, WireName), DnssecError> {
        if !name.is_subdomain_of(&self.origin) || self.name_exists(name) {
            return Err(DnssecError::NoProof);
        }
        let mut child = *name;
        let mut parent = name.parent().ok_or(DnssecError::NoProof)?;
        loop {
            if self.name_exists(&parent) {
                return Ok((parent, child));
            }
            child = parent;
            parent = parent.parent().ok_or(DnssecError::NoProof)?;
        }
    }
    fn sig_for(&self, rr: &ResourceRecord) -> Result<ResourceRecord, DnssecError> {
        self.exact_rrset(&rr.name, rr.rtype)
            .and_then(|s| s.iter().find(|r| matches!(r.rdata, RData::Rrsig(_))))
            .cloned()
            .ok_or(DnssecError::NoProof)
    }
    fn pair(&self, rr: &ResourceRecord) -> Result<(ResourceRecord, ResourceRecord), DnssecError> {
        Ok((rr.clone(), self.sig_for(rr)?))
    }
    fn soa_pair(&self) -> Result<(ResourceRecord, ResourceRecord), DnssecError> {
        let rr = self
            .exact_rrset(&self.origin, RecordType::Soa)
            .and_then(|s| s.first())
            .ok_or(DnssecError::NoProof)?;
        let (mut soa, mut sig) = self.pair(rr)?;
        if let RData::Soa(s) = &soa.rdata {
            soa.ttl = soa.ttl.min(s.minimum);
            sig.ttl = soa.ttl;
        }
        Ok((soa, sig))
    }
    fn covering(&self, name: &WireName) -> Result<&ResourceRecord, DnssecError> {
        match &self.mode{
        DenialMode::Nsec=>self.denial.values().find(|rr|matches!(&rr.rdata,RData::Nsec(n)if covers(&rr.name,&n.next_domain_name,name))).ok_or(DnssecError::NoProof),
        DenialMode::Nsec3{iterations,salt}=>{let hash=nsec3_hash(name,*iterations,salt)?;if self.hashes.contains_key(&hash){return Err(DnssecError::NoProof);}let original=self.hashes.range(..hash).next_back().or_else(||self.hashes.last_key_value()).ok_or(DnssecError::NoProof)?.1;self.denial.get(original).ok_or(DnssecError::NoProof)}
    }
    }
    pub fn synthesize_nxdomain_proof(
        &self,
        qname: &WireName,
    ) -> Result<NegativeProof, DnssecError> {
        if !matches!(self.mode, DenialMode::Nsec3 { .. }) {
            return Err(DnssecError::NoProof);
        }
        let (ce, nc) = self.find_closest_encloser(qname)?;
        let wc = ce.prepend_wildcard()?;
        if self.name_exists(&wc) || self.cuts.iter().any(|c| qname.is_subdomain_of(c)) {
            return Err(DnssecError::NoProof);
        }
        let (soa, soa_rrsig) = self.soa_pair()?;
        let (closest_encloser_nsec3, closest_encloser_rrsig) =
            self.pair(self.denial.get(&ce).ok_or(DnssecError::NoProof)?)?;
        let (next_closer_nsec3, next_closer_rrsig) = self.pair(self.covering(&nc)?)?;
        let wildcard_nsec3 = Some(self.pair(self.covering(&wc)?)?);
        Ok(NegativeProof {
            soa,
            soa_rrsig,
            closest_encloser_nsec3,
            closest_encloser_rrsig,
            next_closer_nsec3,
            next_closer_rrsig,
            wildcard_nsec3,
        })
    }
    fn append_pair(
        &self,
        out: &mut Vec<ResourceRecord>,
        rr: &ResourceRecord,
    ) -> Result<(), DnssecError> {
        let (a, b) = self.pair(rr)?;
        for rr in [a, b] {
            if !out.contains(&rr) {
                out.push(rr);
            }
        }
        Ok(())
    }
    fn denial_records(
        &self,
        qname: &WireName,
        nodata: bool,
        wildcard: Option<WireName>,
        include_soa: bool,
    ) -> Result<Vec<ResourceRecord>, DnssecError> {
        let mut out = Vec::new();
        if include_soa {
            let (a, b) = self.soa_pair()?;
            out.extend([a, b]);
        }
        if nodata && wildcard.is_none() {
            self.append_pair(
                &mut out,
                self.denial.get(qname).ok_or(DnssecError::NoProof)?,
            )?;
            return Ok(out);
        }
        let (ce, nc) = self.find_closest_encloser(qname)?;
        let wc = ce.prepend_wildcard()?;
        match &self.mode {
            DenialMode::Nsec => {
                self.append_pair(&mut out, self.covering(qname)?)?;
                if nodata {
                    self.append_pair(&mut out, self.denial.get(&wc).ok_or(DnssecError::NoProof)?)?;
                } else if wildcard.is_none() {
                    self.append_pair(&mut out, self.covering(&wc)?)?;
                }
            }
            DenialMode::Nsec3 { .. } => {
                self.append_pair(&mut out, self.denial.get(&ce).ok_or(DnssecError::NoProof)?)?;
                self.append_pair(&mut out, self.covering(&nc)?)?;
                if nodata {
                    self.append_pair(&mut out, self.denial.get(&wc).ok_or(DnssecError::NoProof)?)?;
                } else if wildcard.is_none() {
                    self.append_pair(&mut out, self.covering(&wc)?)?;
                }
            }
        }
        Ok(out)
    }
    fn negative(
        &self,
        qname: &WireName,
        nodata: bool,
        wildcard: Option<WireName>,
        dnssec: bool,
    ) -> Resolution<'_> {
        let mut result = Resolution {
            rcode: if nodata { 0 } else { 3 },
            ..Resolution::default()
        };
        let records = if dnssec {
            self.denial_records(qname, nodata, wildcard, true)
        } else {
            self.soa_pair().map(|(s, _)| vec![s])
        };
        match records {
            Ok(r) => result.authorities = r,
            Err(_) => result.rcode = 2,
        }
        result
    }
    pub fn resolve(&self, qname: &WireName, qtype: RecordType, dnssec: bool) -> Resolution<'_> {
        if !qname.is_subdomain_of(&self.origin) {
            return Resolution {
                rcode: 5,
                authoritative: false,
                ..Resolution::default()
            };
        }
        // Parent-side DS queries at a cut are authoritative; everything else is a referral.
        if let Some(cut) = self
            .cuts
            .iter()
            .find(|c| qname.is_subdomain_of(c) && !(qname == *c && qtype == RecordType::Ds))
        {
            let mut result = Resolution {
                authoritative: false,
                ..Resolution::default()
            };
            if let Some(ns) = self.exact_rrset(cut, RecordType::Ns) {
                result.authorities.extend_from_slice(ns);
                for rr in ns {
                    if let RData::Ns(target) = &rr.rdata {
                        if target.is_subdomain_of(cut) {
                            for t in [RecordType::A, RecordType::Aaaa] {
                                if let Some(glue) = self.exact_rrset(target, t) {
                                    result.additionals.extend(
                                        glue.iter()
                                            .filter(|r| r.rtype != RecordType::Rrsig)
                                            .cloned(),
                                    );
                                }
                            }
                        }
                    }
                }
            }
            if dnssec {
                if let Some(ds) = self.exact_rrset(cut, RecordType::Ds) {
                    result.authorities.extend_from_slice(ds);
                } else if let Some(denial) = self.denial.get(cut) {
                    if self.append_pair(&mut result.authorities, denial).is_err() {
                        result.rcode = 2;
                    }
                }
            }
            return result;
        }
        // RFC 8482: a minimal ANY response returns one real RRset.
        let actual_type = if qtype == RecordType::Any {
            self.rrsets
                .range((*qname, RecordType::A)..=(*qname, RecordType::Unknown(u16::MAX)))
                .find(|((_, t), _)| {
                    !matches!(
                        t,
                        RecordType::Nsec | RecordType::Nsec3 | RecordType::Nsec3Param
                    )
                })
                .map_or(qtype, |((_, t), _)| *t)
        } else {
            qtype
        };
        if let Some(rrset) = self.exact_rrset(qname, actual_type) {
            let end = if dnssec {
                rrset.len()
            } else {
                rrset
                    .iter()
                    .position(|r| r.rtype == RecordType::Rrsig)
                    .unwrap_or(rrset.len())
            };
            return Resolution {
                answers: Cow::Borrowed(&rrset[..end]),
                ..Resolution::default()
            };
        }
        if qtype == RecordType::Rrsig {
            let sigs: Vec<_> = self
                .rrsets
                .range((*qname, RecordType::A)..=(*qname, RecordType::Unknown(u16::MAX)))
                .flat_map(|(_, r)| r.iter())
                .filter(|r| r.rtype == RecordType::Rrsig)
                .cloned()
                .collect();
            if !sigs.is_empty() {
                return Resolution {
                    answers: Cow::Owned(sigs),
                    ..Resolution::default()
                };
            }
        }
        if qtype != RecordType::Cname {
            if let Some(rrset) = self.exact_rrset(qname, RecordType::Cname) {
                let end = if dnssec {
                    rrset.len()
                } else {
                    rrset
                        .iter()
                        .position(|r| r.rtype == RecordType::Rrsig)
                        .unwrap_or(rrset.len())
                };
                return Resolution {
                    answers: Cow::Borrowed(&rrset[..end]),
                    ..Resolution::default()
                };
            }
        }
        if self.name_exists(qname) {
            return self.negative(qname, true, None, dnssec);
        }
        let Ok((ce, _)) = self.find_closest_encloser(qname) else {
            return Resolution {
                rcode: 2,
                ..Resolution::default()
            };
        };
        let Ok(wildcard) = ce.prepend_wildcard() else {
            return Resolution {
                rcode: 2,
                ..Resolution::default()
            };
        };
        if self.name_exists(&wildcard) {
            let wildcard_type = if qtype == RecordType::Any {
                self.rrsets
                    .range((wildcard, RecordType::A)..=(wildcard, RecordType::Unknown(u16::MAX)))
                    .find(|((_, t), _)| {
                        !matches!(
                            t,
                            RecordType::Nsec | RecordType::Nsec3 | RecordType::Nsec3Param
                        )
                    })
                    .map_or(qtype, |((_, t), _)| *t)
            } else {
                qtype
            };
            if let Some(rrset) = self
                .exact_rrset(&wildcard, wildcard_type)
                .or_else(|| self.exact_rrset(&wildcard, RecordType::Cname))
            {
                let answers = rrset
                    .iter()
                    .filter(|r| dnssec || r.rtype != RecordType::Rrsig)
                    .cloned()
                    .map(|mut rr| {
                        rr.name = *qname;
                        rr
                    })
                    .collect();
                let mut result = Resolution {
                    answers: Cow::Owned(answers),
                    ..Resolution::default()
                };
                if dnssec {
                    match self.denial_records(qname, false, Some(wildcard), false) {
                        Ok(r) => result.authorities = r,
                        Err(_) => {
                            result.answers = Cow::Borrowed(&[]);
                            result.rcode = 2;
                        }
                    }
                }
                return result;
            }
            return self.negative(qname, true, Some(wildcard), dnssec);
        }
        self.negative(qname, false, None, dnssec)
    }
    pub fn to_zone_file(&self) -> Result<String, DnssecError> {
        let mut text = String::new();
        writeln!(text, "; agentdns signed snapshot serial {}", self.serial)
            .map_err(|_| DnssecError::InvalidZone)?;
        for rr in &self.records {
            writeln!(
                text,
                "{} {} IN {} {}",
                rr.name,
                rr.ttl,
                rr.rtype,
                rdata_text(&rr.rdata)?
            )
            .map_err(|_| DnssecError::InvalidZone)?;
        }
        Ok(text)
    }
}
fn quoted(bytes: &[u8]) -> String {
    let mut s = String::from("\"");
    for &b in bytes {
        match b {
            b'"' | b'\\' => {
                s.push('\\');
                s.push(char::from(b));
            }
            32..=126 => s.push(char::from(b)),
            _ => {
                let _ = write!(s, "\\{b:03}");
            }
        }
    }
    s.push('"');
    s
}
pub fn rdata_text(rdata: &RData) -> Result<String, DnssecError> {
    let types = |t: &[RecordType]| {
        t.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ")
    };
    let salt = |s: &[u8]| {
        if s.is_empty() {
            "-".to_owned()
        } else {
            hex_encode(s)
        }
    };
    Ok(match rdata {
        RData::A(a) => a.to_string(),
        RData::Aaaa(a) => a.to_string(),
        RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) => n.to_string(),
        RData::Soa(s) => format!(
            "{} {} {} {} {} {} {}",
            s.mname, s.rname, s.serial, s.refresh, s.retry, s.expire, s.minimum
        ),
        RData::Mx(m) => format!("{} {}", m.preference, m.exchange),
        RData::Txt(v) => v.iter().map(|b| quoted(b)).collect::<Vec<_>>().join(" "),
        RData::Tlsa(t) => format!(
            "{} {} {} {}",
            t.usage,
            t.selector,
            t.matching_type,
            hex_encode(&t.certificate_association_data)
        ),
        RData::Dnskey(k) => format!(
            "{} {} {} {}",
            k.flags,
            k.protocol,
            k.algorithm,
            STANDARD.encode(&k.public_key)
        ),
        RData::Ds(d) => format!(
            "{} {} {} {}",
            d.key_tag,
            d.algorithm,
            d.digest_type,
            hex_encode(&d.digest)
        ),
        RData::Rrsig(s) => format!(
            "{} {} {} {} {} {} {} {} {}",
            s.type_covered,
            s.algorithm,
            s.labels,
            s.original_ttl,
            s.expiration,
            s.inception,
            s.key_tag,
            s.signer_name,
            STANDARD.encode(&s.signature)
        ),
        RData::Nsec(n) => format!("{} {}", n.next_domain_name, types(&n.types)),
        RData::Nsec3(n) => format!(
            "{} {} {} {} {} {}",
            n.hash_algorithm,
            n.flags,
            n.iterations,
            salt(&n.salt),
            base32hex_encode(&n.next_hashed_owner),
            types(&n.types)
        ),
        RData::Nsec3Param(n) => format!(
            "{} {} {} {}",
            n.hash_algorithm,
            n.flags,
            n.iterations,
            salt(&n.salt)
        ),
        RData::Caa(c) => format!(
            "{} {} {}",
            c.flags,
            String::from_utf8_lossy(&c.tag),
            quoted(&c.value)
        ),
        _ => {
            let b = rdata.to_wire()?;
            format!("\\# {} {}", b.len(), hex_encode(&b))
        }
    })
}

impl SignedZone {
    /// Rehydrate a committed, presigned snapshot. This never uses private keys
    /// and never changes serials, timestamps, or signatures. The CCF storage
    /// adapter remains responsible for authenticity/commit provenance.
    pub fn from_signed_records(
        origin: WireName,
        records: Vec<ResourceRecord>,
    ) -> Result<Self, DnssecError> {
        if records.is_empty()
            || records.iter().any(|r| {
                r.rclass != RecordClass::In
                    || !r.name.is_subdomain_of(&origin)
                    || r.rdata.record_type() != Some(r.rtype)
            })
        {
            return Err(DnssecError::InvalidZone);
        }
        let soas: Vec<_> = records
            .iter()
            .filter(|r| r.rtype == RecordType::Soa)
            .collect();
        if soas.len() != 1
            || soas[0].name != origin
            || !records
                .iter()
                .any(|r| r.name == origin && r.rtype == RecordType::Ns)
        {
            return Err(DnssecError::InvalidZone);
        }
        let serial = if let RData::Soa(s) = &soas[0].rdata {
            s.serial
        } else {
            return Err(DnssecError::InvalidZone);
        };
        let params: Vec<_> = records
            .iter()
            .filter_map(|r| {
                if let RData::Nsec3Param(p) = &r.rdata {
                    Some((r.name, p))
                } else {
                    None
                }
            })
            .collect();
        let mode = if params.is_empty() {
            DenialMode::Nsec
        } else {
            if params.len() != 1
                || params[0].0 != origin
                || params[0].1.hash_algorithm != 1
                || params[0].1.flags != 0
            {
                return Err(DnssecError::InvalidZone);
            }
            let p = params[0].1;
            nsec3_hash(&origin, p.iterations, &p.salt)?;
            DenialMode::Nsec3 {
                iterations: p.iterations,
                salt: p.salt.clone(),
            }
        };
        let cuts: BTreeSet<_> = records
            .iter()
            .filter(|r| r.rtype == RecordType::Ns && r.name != origin)
            .map(|r| r.name)
            .collect();
        let mut rrsets = BTreeMap::<(WireName, RecordType), Vec<ResourceRecord>>::new();
        let mut signatures = Vec::new();
        let mut names = BTreeSet::new();
        for rr in &records {
            if let RData::Rrsig(sig) = &rr.rdata {
                if sig.algorithm != 14
                    || sig.signature.len() != 96
                    || sig.signer_name != origin
                    || sig.labels > rr.name.label_count()
                {
                    return Err(DnssecError::InvalidZone);
                }
                signatures.push(rr.clone());
                continue;
            }
            rrsets
                .entry((rr.name, rr.rtype))
                .or_default()
                .push(rr.clone());
            if rr.rtype == RecordType::Nsec3
                || cuts
                    .iter()
                    .any(|c| rr.name != *c && rr.name.is_subdomain_of(c))
            {
                continue;
            }
            let mut name = rr.name;
            loop {
                names.insert(name);
                if name == origin {
                    break;
                }
                name = name.parent().ok_or(DnssecError::InvalidZone)?;
            }
        }
        let mut inception = None;
        let mut expiration = None;
        for rr in signatures {
            let RData::Rrsig(sig) = &rr.rdata else {
                unreachable!()
            };
            inception = Some(inception.map_or(sig.inception, |n: u32| {
                if sig.inception.wrapping_sub(n) < 0x8000_0000 {
                    sig.inception
                } else {
                    n
                }
            }));
            expiration = Some(expiration.map_or(sig.expiration, |n: u32| {
                if sig.expiration.wrapping_sub(n) < 0x8000_0000 {
                    n
                } else {
                    sig.expiration
                }
            }));
            let set = rrsets
                .get_mut(&(rr.name, sig.type_covered))
                .ok_or(DnssecError::InvalidZone)?;
            if set.iter().any(|r| r.ttl != rr.ttl) {
                return Err(DnssecError::InvalidZone);
            }
            set.push(rr);
        }
        for ((name, t), set) in &rrsets {
            let data: Vec<_> = set
                .iter()
                .filter(|r| r.rtype != RecordType::Rrsig)
                .collect();
            if data.is_empty()
                || data.iter().any(|r| r.ttl != data[0].ttl)
                || (*t == RecordType::Cname
                    && (data.len() != 1
                        || rrsets.keys().any(|(n, t)| {
                            n == name && !matches!(t, RecordType::Cname | RecordType::Nsec)
                        })))
            {
                return Err(DnssecError::InvalidZone);
            }
            if !(cuts.iter().any(|c| name != c && name.is_subdomain_of(c))
                || (*t == RecordType::Ns && cuts.contains(name))
                || set.iter().any(|r| r.rtype == RecordType::Rrsig))
            {
                return Err(DnssecError::InvalidZone);
            }
        }
        let mut denial = BTreeMap::new();
        let mut hashes = BTreeMap::new();
        match &mode {
            DenialMode::Nsec => {
                if records.iter().any(|r| r.rtype == RecordType::Nsec3) {
                    return Err(DnssecError::InvalidZone);
                }
                let ordered: Vec<_> = names.iter().copied().collect();
                for (i, name) in ordered.iter().enumerate() {
                    let set = rrsets
                        .get(&(*name, RecordType::Nsec))
                        .ok_or(DnssecError::InvalidZone)?;
                    if set.iter().filter(|r| r.rtype == RecordType::Nsec).count() != 1 {
                        return Err(DnssecError::InvalidZone);
                    }
                    let rr = &set[0];
                    let RData::Nsec(n) = &rr.rdata else {
                        return Err(DnssecError::InvalidZone);
                    };
                    if n.next_domain_name != ordered[(i + 1) % ordered.len()] {
                        return Err(DnssecError::InvalidZone);
                    }
                    denial.insert(*name, rr.clone());
                }
            }
            DenialMode::Nsec3 { iterations, salt } => {
                if records.iter().any(|r| r.rtype == RecordType::Nsec) {
                    return Err(DnssecError::InvalidZone);
                }
                for name in &names {
                    if hashes
                        .insert(nsec3_hash(name, *iterations, salt)?, *name)
                        .is_some()
                    {
                        return Err(DnssecError::HashCollision);
                    }
                }
                let ordered: Vec<_> = hashes.keys().copied().collect();
                for (i, hash) in ordered.iter().enumerate() {
                    let owner = origin.prepend_label(base32hex_encode(hash).as_bytes())?;
                    let set = rrsets
                        .get(&(owner, RecordType::Nsec3))
                        .ok_or(DnssecError::InvalidZone)?;
                    if set.iter().filter(|r| r.rtype == RecordType::Nsec3).count() != 1 {
                        return Err(DnssecError::InvalidZone);
                    }
                    let rr = &set[0];
                    let RData::Nsec3(n) = &rr.rdata else {
                        return Err(DnssecError::InvalidZone);
                    };
                    if n.hash_algorithm != 1
                        || n.flags != 0
                        || n.iterations != *iterations
                        || n.salt != *salt
                        || n.next_hashed_owner != ordered[(i + 1) % ordered.len()]
                    {
                        return Err(DnssecError::InvalidZone);
                    }
                    denial.insert(hashes[hash], rr.clone());
                }
            }
        }
        Ok(Self {
            origin,
            records,
            serial,
            inception: inception.ok_or(DnssecError::InvalidZone)?,
            expiration: expiration.ok_or(DnssecError::InvalidZone)?,
            mode,
            names,
            cuts,
            rrsets,
            denial,
            hashes,
        })
    }
}
