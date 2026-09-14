//! Differential-testing oracle: parse one wire message file, print one JSON line.
//! Used by tools/differential_wire.py to compare our parser against dnspython.
//! Not a service entrypoint; output schema is `{"ok":bool, ...}`.
use adns_wire::Message;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args().nth(1).ok_or("usage: parse_wire <file>")?;
    let bytes = std::fs::read(path)?;
    match Message::parse(&bytes) {
        Ok(m) => {
            let (qname, qtype) = m
                .questions
                .first()
                .map(|q| (q.name.to_string(), q.qtype.code()))
                .unwrap_or_default();
            println!(
                "{}",
                serde_json::json!({
                    "ok": true,
                    "rcode": m.header.rcode(),
                    "qd": m.questions.len(),
                    "an": m.answers.len(),
                    "ns": m.authorities.len(),
                    "ar": m.additionals.len(),
                    "qname": qname,
                    "qtype": qtype,
                })
            );
        }
        Err(e) => println!("{}", serde_json::json!({"ok": false, "err": e.to_string()})),
    }
    Ok(())
}
