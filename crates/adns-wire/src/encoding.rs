//! Pure Rust encodings. Alphabet selection scans fixed tables; there are no
//! input-indexed lookups or early returns on individual invalid digits.
use crate::DnsError;
fn choose(table: &[u8], value: u8) -> u8 {
    table.iter().enumerate().fold(0, |a, (i, &b)| {
        a | (b & 0u8.wrapping_sub((i as u8 == value) as u8))
    })
}
fn decode_digit(table: &[u8], value: u8) -> (u8, bool) {
    let mut out = 0;
    let mut valid = false;
    for (i, &b) in table.iter().enumerate() {
        let same = b == value;
        out |= (i as u8) & 0u8.wrapping_sub(same as u8);
        valid |= same;
    }
    (out, valid)
}
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        result.push(char::from(choose(b"0123456789abcdef", b >> 4)));
        result.push(char::from(choose(b"0123456789abcdef", b & 15)));
    }
    result
}
pub fn hex_decode(s: &str) -> Result<Vec<u8>, DnsError> {
    let mut result = Vec::with_capacity(s.len() / 2);
    let mut valid = s.len() & 1 == 0;
    for pair in s.as_bytes().chunks_exact(2) {
        let (a, av) = decode_digit(b"0123456789abcdef", pair[0].to_ascii_lowercase());
        let (b, bv) = decode_digit(b"0123456789abcdef", pair[1].to_ascii_lowercase());
        valid &= av & bv;
        result.push((a << 4) | b);
    }
    if valid {
        Ok(result)
    } else {
        Err(DnsError::InvalidRdata)
    }
}
pub fn base32hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut bits = 0;
    let mut acc = 0u32;
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(choose(
                b"0123456789ABCDEFGHIJKLMNOPQRSTUV",
                ((acc >> bits) & 31) as u8,
            )));
        }
    }
    if bits > 0 {
        out.push(char::from(choose(
            b"0123456789ABCDEFGHIJKLMNOPQRSTUV",
            ((acc << (5 - bits)) & 31) as u8,
        )));
    }
    out
}
pub fn base32hex_decode(s: &str) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut bits = 0;
    let mut acc = 0u32;
    let mut valid = !matches!(s.len() % 8, 1 | 3 | 6);
    for &b in s.as_bytes() {
        let (v, ok) = decode_digit(b"0123456789ABCDEFGHIJKLMNOPQRSTUV", b.to_ascii_uppercase());
        valid &= ok;
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    valid &= acc & ((1 << bits) - 1) == 0;
    if valid {
        Ok(out)
    } else {
        Err(DnsError::InvalidRdata)
    }
}
