use crate::AttestationError;
use openssl::{
    bn::BigNum, ecdsa::EcdsaSig, hash::MessageDigest, nid::Nid, sign::Verifier, x509::X509,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const REPORT_SIZE: usize = 1184;
const SIGNED_SIZE: usize = 672;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcbVersion {
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}
impl TcbVersion {
    fn parse(bytes: &[u8]) -> Result<Self, AttestationError> {
        if bytes[2..6] != [0; 4] {
            return Err(AttestationError::Malformed("reserved TCB bits"));
        }
        Ok(Self {
            bootloader: bytes[0],
            tee: bytes[1],
            snp: bytes[6],
            microcode: bytes[7],
        })
    }
    pub fn meets(&self, min: &Self) -> bool {
        self.bootloader >= min.bootloader
            && self.tee >= min.tee
            && self.snp >= min.snp
            && self.microcode >= min.microcode
    }
}

/// Parsed values are untrusted until both report and endorsement verification.
#[derive(Clone, Debug)]
pub struct SnpAttestationReport {
    pub version: u32,
    pub guest_svn: u32,
    pub policy: u64,
    pub vmpl: u32,
    pub signature_algo: u32,
    pub flags: u32,
    pub current_tcb: TcbVersion,
    pub reported_tcb: TcbVersion,
    pub committed_tcb: TcbVersion,
    pub launch_tcb: TcbVersion,
    pub report_data: [u8; 64],
    pub measurement: [u8; 48],
    pub host_data: [u8; 32],
    pub chip_id: [u8; 64],
    pub cpuid_family: u8,
    pub cpuid_model: u8,
    /// ABI 1.58 report version 5: authenticated mitigation state at launch.
    /// Absent on versions 2/3; no policy floor is inferred from this value.
    pub launch_mitigation_vector: Option<u64>,
    /// ABI 1.58 report version 5: authenticated current mitigation state.
    pub current_mitigation_vector: Option<u64>,
}
impl SnpAttestationReport {
    pub fn parse(bytes: &[u8]) -> Result<Self, AttestationError> {
        if bytes.len() != REPORT_SIZE {
            return Err(AttestationError::Malformed("SNP report must be 1184 bytes"));
        }
        // Fixed offsets from AMD ABI; copy into arrays rather than casting memory.
        let u32_at =
            |p| u32::from_le_bytes(bytes[p..p + 4].try_into().expect("bounded fixed offset"));
        let version = u32_at(0);
        if !matches!(version, 2 | 3 | 5) {
            return Err(AttestationError::Malformed(
                "unsupported SNP report version",
            ));
        }
        // AMD 56860 rev. 1.58, Table 23: v5 assigns two u64 mitigation
        // vectors at 0x1f8 and 0x200. The signed region still ends at 0x29f.
        // Unknown versions remain rejected rather than borrowing a layout.
        let reserved_start = if version == 5 { 520 } else { 504 };
        for range in [76..80, 395..416, reserved_start..672, 720..744, 792..1184] {
            if bytes[range].iter().any(|b| *b != 0) {
                return Err(AttestationError::Malformed("nonzero reserved report bytes"));
            }
        }
        if bytes[491] != 0 || bytes[495] != 0 || (version == 2 && bytes[392..395] != [0; 3]) {
            return Err(AttestationError::Malformed(
                "nonzero reserved version bytes",
            ));
        }
        Ok(Self {
            version,
            guest_svn: u32_at(4),
            policy: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            vmpl: u32_at(48),
            signature_algo: u32_at(52),
            flags: u32_at(72),
            current_tcb: TcbVersion::parse(&bytes[56..64])?,
            reported_tcb: TcbVersion::parse(&bytes[384..392])?,
            committed_tcb: TcbVersion::parse(&bytes[480..488])?,
            launch_tcb: TcbVersion::parse(&bytes[496..504])?,
            report_data: bytes[80..144].try_into().unwrap(),
            measurement: bytes[144..192].try_into().unwrap(),
            host_data: bytes[192..224].try_into().unwrap(),
            chip_id: bytes[416..480].try_into().unwrap(),
            cpuid_family: bytes[392],
            cpuid_model: bytes[393],
            launch_mitigation_vector: (version == 5)
                .then(|| u64::from_le_bytes(bytes[504..512].try_into().unwrap())),
            current_mitigation_vector: (version == 5)
                .then(|| u64::from_le_bytes(bytes[512..520].try_into().unwrap())),
        })
    }
    pub fn verify_security_policy(&self) -> Result<(), AttestationError> {
        if self.vmpl != 0 {
            return Err(AttestationError::ReportPolicyRejected("VMPL must be zero"));
        }
        if self.policy & (1 << 19) != 0 {
            return Err(AttestationError::ReportPolicyRejected("debug enabled"));
        }
        if self.policy & (1 << 18) != 0 {
            return Err(AttestationError::ReportPolicyRejected(
                "migration agent enabled",
            ));
        }
        if self.policy & (1 << 17) == 0 || self.policy >> 26 != 0 {
            return Err(AttestationError::ReportPolicyRejected(
                "invalid guest policy reserved bits",
            ));
        }
        // Report signing key 0 = VCEK; reject masked chip ID and VLEK/none.
        if self.flags & !1 != 0 {
            return Err(AttestationError::ReportPolicyRejected(
                "VCEK required, unmasked chip ID",
            ));
        }
        if self.signature_algo != 1 {
            return Err(AttestationError::UnsupportedAlgorithm);
        }
        Ok(())
    }
    pub fn verify_key_binding(&self, spki_der: &[u8]) -> Result<(), AttestationError> {
        if self.report_data[32..] != [0; 32] {
            return Err(AttestationError::ReportDataNotZeroed);
        }
        if self.report_data[..32] != Sha256::digest(spki_der)[..] {
            return Err(AttestationError::KeyBindingMismatch);
        }
        Ok(())
    }
    pub(crate) fn verify_signature(&self, raw: &[u8], vcek: &X509) -> Result<(), AttestationError> {
        if raw.len() != REPORT_SIZE {
            return Err(AttestationError::Malformed("report length"));
        }
        let key = vcek.public_key()?;
        if key.ec_key()?.group().curve_name() != Some(Nid::SECP384R1) {
            return Err(AttestationError::UnsupportedAlgorithm);
        }
        let mut r = raw[672..720].to_vec();
        r.reverse();
        let mut s = raw[744..792].to_vec();
        s.reverse();
        let sig =
            EcdsaSig::from_private_components(BigNum::from_slice(&r)?, BigNum::from_slice(&s)?)?
                .to_der()?;
        let mut verifier = Verifier::new(MessageDigest::sha384(), &key)?;
        verifier.update(&raw[..SIGNED_SIZE])?;
        if !verifier.verify(&sig)? {
            return Err(AttestationError::SignatureInvalid);
        }
        Ok(())
    }
}
