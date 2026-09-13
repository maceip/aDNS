//! Cross-implementation fixture generator. The transfer key is deliberately
//! public test material, never generated or used by a deployed authority.
use adns_transfer::{TsigKey, axfr_messages, verify_request};
use adns_wire::{RData, ResourceRecord, SoaData};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let directory = PathBuf::from(std::env::args().nth(1).ok_or("output directory required")?);
    let key = TsigKey::new("test-transfer.".parse()?, vec![7; 32])?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let request = verify_request(&fs::read(directory.join("query.bin"))?, &key, now)?;
    let origin = "example.test.".parse()?;
    let mut records = vec![ResourceRecord::new(
        origin,
        300,
        RData::Soa(SoaData {
            mname: "ns.example.test.".parse()?,
            rname: "hostmaster.example.test.".parse()?,
            serial: 7,
            refresh: 5,
            retry: 2,
            expire: 3600,
            minimum: 60,
        }),
    )?];
    for i in 0..1000 {
        records.push(ResourceRecord::new(
            format!("record{i}.example.test.").parse()?,
            300,
            RData::Txt(vec![vec![b'x'; 200], vec![b'y'; 200]]),
        )?);
    }
    let messages = axfr_messages(&request, &origin, &records, &key, now, 4096)?;
    let mut output = Vec::new();
    for message in &messages {
        output.extend((message.len() as u16).to_be_bytes());
        output.extend(message);
    }
    fs::write(directory.join("stream.bin"), output)?;
    println!(
        "Rust verified dnspython query and emitted {} authenticated packets for 1001-record snapshot",
        messages.len()
    );
    Ok(())
}
