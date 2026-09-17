use crate::AttestationError;
use openssl::{
    bn::BigNum, ecdsa::EcdsaSig, hash::MessageDigest, nid::Nid, sign::Verifier, x509::X509,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const REPORT_SIZE: usize = 1184;
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
        let b: [u8; 8] = bytes
            .try_into()
            .map_err(|_| AttestationError::Malformed("TCB version"))?;
        if b[2..6] != [0; 4] {
            return Err(AttestationError::Malformed("reserved TCB bits"));
        }
        Ok(Self {
            bootloader: b[0],
            tee: b[1],
            snp: b[6],
            microcode: b[7],
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
        // All slicing is fallible so malformed/truncated input returns an
        // error instead of panicking on an attacker-controlled report.
        let u32_at = |p: usize| -> Result<u32, AttestationError> {
            bytes
                .get(p..p + 4)
                .and_then(|s| s.try_into().ok())
                .map(u32::from_le_bytes)
                .ok_or(AttestationError::Malformed("SNP report offset"))
        };
        let u64_at = |p: usize| -> Result<u64, AttestationError> {
            bytes
                .get(p..p + 8)
                .and_then(|s| s.try_into().ok())
                .map(u64::from_le_bytes)
                .ok_or(AttestationError::Malformed("SNP report offset"))
        };
        let version = u32_at(0)?;
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
        let array_64: [u8; 64] = bytes
            .get(80..144)
            .and_then(|s| s.try_into().ok())
            .ok_or(AttestationError::Malformed("SNP report_data"))?;
        let array_48: [u8; 48] = bytes
            .get(144..192)
            .and_then(|s| s.try_into().ok())
            .ok_or(AttestationError::Malformed("SNP measurement"))?;
        let array_32: [u8; 32] = bytes
            .get(192..224)
            .and_then(|s| s.try_into().ok())
            .ok_or(AttestationError::Malformed("SNP host_data"))?;
        let array_chip: [u8; 64] = bytes
            .get(416..480)
            .and_then(|s| s.try_into().ok())
            .ok_or(AttestationError::Malformed("SNP chip_id"))?;
        let launch_mitigation_vector = if version == 5 {
            Some(u64_at(504)?)
        } else {
            None
        };
        let current_mitigation_vector = if version == 5 {
            Some(u64_at(512)?)
        } else {
            None
        };
        Ok(Self {
            version,
            guest_svn: u32_at(4)?,
            policy: u64_at(8)?,
            vmpl: u32_at(48)?,
            signature_algo: u32_at(52)?,
            flags: u32_at(72)?,
            current_tcb: TcbVersion::parse(
                bytes
                    .get(56..64)
                    .ok_or(AttestationError::Malformed("SNP current TCB"))?,
            )?,
            reported_tcb: TcbVersion::parse(
                bytes
                    .get(384..392)
                    .ok_or(AttestationError::Malformed("SNP reported TCB"))?,
            )?,
            committed_tcb: TcbVersion::parse(
                bytes
                    .get(480..488)
                    .ok_or(AttestationError::Malformed("SNP committed TCB"))?,
            )?,
            launch_tcb: TcbVersion::parse(
                bytes
                    .get(496..504)
                    .ok_or(AttestationError::Malformed("SNP launch TCB"))?,
            )?,
            report_data: array_64,
            measurement: array_48,
            host_data: array_32,
            chip_id: array_chip,
            cpuid_family: *bytes
                .get(392)
                .ok_or(AttestationError::Malformed("SNP cpuid"))?,
            cpuid_model: *bytes
                .get(393)
                .ok_or(AttestationError::Malformed("SNP cpuid"))?,
            launch_mitigation_vector,
            current_mitigation_vector,
        })
    }
    pub fn verify_security_policy(&self) -> Result<(), AttestationError> {
        self.verify_security_policy_at_vmpl(0)
    }
    pub(crate) fn verify_security_policy_at_vmpl(&self, vmpl: u32) -> Result<(), AttestationError> {
        if vmpl > 3 || self.vmpl != vmpl {
            return Err(AttestationError::ReportPolicyRejected("VMPL rejected"));
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
