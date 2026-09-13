fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        return Err(
            "usage: audit_ccf_node QUOTE_JSON ACTUAL_TLS_PEER_DER POLICY_JSON UNIX_TIME".into(),
        );
    }
    let quote = std::fs::read(&args[0])?;
    let peer = std::fs::read(&args[1])?;
    let policy = serde_json::from_slice(&std::fs::read(&args[2])?)?;
    let result = adns_attest::node_audit::audit(&quote, &peer, &policy, args[3].parse()?)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
