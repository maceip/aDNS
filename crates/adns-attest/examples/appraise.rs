//! Offline native appraisal CLI. Policy and time must be trusted inputs.
#![forbid(unsafe_code)]
use std::{env, fs, process::ExitCode};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 6 {
        return Err("usage: appraise PROFILE EVIDENCE_COSE SPKI_DER POLICY_JSON UNIX_TIME".into());
    }
    let evidence = fs::read(&args[2])?;
    let spki = fs::read(&args[3])?;
    let policy: adns_attest::AppraisalPolicy = serde_json::from_slice(&fs::read(&args[4])?)?;
    let verified = adns_attest::appraise(&args[1], &evidence, &spki, &policy, args[5].parse()?)?;
    println!("{}", serde_json::to_string_pretty(&verified)?);
    Ok(())
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
