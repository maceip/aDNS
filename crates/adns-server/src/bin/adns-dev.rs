//! Development-only runtime. Production execution belongs to the CCF adapter.
use adns_dnssec::SignedZone;
use adns_server::*;
use adns_storage::*;
use adns_transfer::*;
use adns_wire::*;
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, RawQuery, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::{Mutex, RwLock},
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    http_listen: String,
    transfer_listen: String,
    zone: String,
    signature_validity: u32,
    refresh_before: u32,
    state_file: PathBuf,
    seal_key_file: PathBuf,
    tsig_name: String,
    tsig_secret_file: PathBuf,
    secondaries: Vec<String>,
    initial_records: Vec<ResourceRecord>,
    #[serde(default)]
    initial_grants: Vec<adns_auth::OwnerGrant>,
    #[serde(default)]
    initial_policy: Option<adns_attest::AppraisalPolicy>,
}
struct Runtime {
    config: Config,
    db: MemoryStorage,
    seal_key: [u8; 32],
    tsig: TsigKey,
    snapshot: RwLock<Arc<SignedZone>>,
    mutation: Mutex<()>,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn save_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut suffix = [0; 12];
    SystemRandom::new()
        .fill(&mut suffix)
        .map_err(|_| std::io::Error::other("random generator failed"))?;
    let temp = path.with_extension(format!("tmp-{}", hex::encode(suffix)));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    let result = (|| {
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&temp, path)?;
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}
fn snapshot(
    db: &MemoryStorage,
    zone: &str,
) -> std::result::Result<SignedZone, Box<dyn std::error::Error>> {
    let meta = zone_metadata(&db.read()?, &zone.parse()?)?;
    Ok(SignedZone::from_signed_records(
        meta.origin,
        meta.signed_records,
    )?)
}
impl Runtime {
    async fn persist(&self) -> std::result::Result<(), Box<dyn std::error::Error>> {
        save_private(&self.config.state_file, &self.db.seal(&self.seal_key)?)?;
        let signed = snapshot(&self.db, &self.config.zone)?;
        *self.snapshot.write().await = Arc::new(signed);
        Ok(())
    }
    async fn notify_and_observe(&self, notify: bool) {
        for endpoint in &self.config.secondaries {
            let zone = self.snapshot.read().await.clone();
            let mut state = SecondaryState {
                endpoint: endpoint.clone(),
                ..Default::default()
            };
            let key = composite_key(&[zone.origin.as_slice(), endpoint.as_bytes()]);
            if let Ok(Some(old)) =
                get_json(&self.db.read().unwrap(), Collection::SecondaryStatus, &key)
            {
                state = old;
            }
            if notify && self.exchange(endpoint, &zone.origin, 0x2400).await.is_ok() {
                state.notified(zone.serial);
            }
            if let Ok(response) = self.exchange(endpoint, &zone.origin, 0).await {
                if response.header.flags & 0x840f == 0x8400 {
                    if let Some(serial) = response.answers.iter().find_map(|r| {
                        if r.name == zone.origin {
                            if let RData::Soa(s) = &r.rdata {
                                Some(s.serial)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }) {
                        state.observed(serial, now());
                    }
                }
            }
            let _lock = self.mutation.lock().await;
            if let Ok(mut tx) = self.db.write() {
                if put_json(&mut tx, Collection::SecondaryStatus, key, &state).is_ok() {
                    let _ = tx.commit();
                }
            }
        }
    }
    async fn exchange(
        &self,
        endpoint: &str,
        origin: &WireName,
        flags: u16,
    ) -> std::result::Result<Message, Box<dyn std::error::Error>> {
        use ring::rand::{SecureRandom, SystemRandom};
        let mut id = [0; 2];
        SystemRandom::new().fill(&mut id).map_err(|_| "rng")?;
        let message = Message {
            header: Header {
                id: u16::from_be_bytes(id),
                flags,
            },
            questions: vec![Question {
                name: *origin,
                qtype: RecordType::Soa,
                qclass: RecordClass::In,
            }],
            ..Default::default()
        };
        let (packet, mac) = sign_message(&message.to_wire()?, &self.tsig, now(), None, false)?;
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(endpoint).await?;
        sock.send(&packet).await?;
        let mut buffer = vec![0; 65535];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), sock.recv(&mut buffer))
            .await??;
        let answer = verify_message(&buffer[..n], &self.tsig, now(), Some(&mac), false)?.message;
        if answer.header.id != message.header.id
            || !answer.header.is_response()
            || answer.header.opcode() != message.header.opcode()
            || answer.questions != message.questions
        {
            return Err("secondary response mismatch".into());
        }
        Ok(answer)
    }
}
fn response(status: u16, body: serde_json::Value) -> Response {
    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        axum::Json(body),
    )
        .into_response()
}
async fn http(
    State(runtime): State<Arc<Runtime>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
    body: Bytes,
) -> Response {
    let query = form_urlencoded::parse(raw.as_deref().unwrap_or("").as_bytes())
        .into_owned()
        .collect::<Vec<_>>();
    if uri.path() == "/dns-query" {
        let packet = if method == Method::POST {
            if headers.get("content-type").and_then(|v| v.to_str().ok())
                != Some("application/dns-message")
            {
                return response(415, json!({"error":"application/dns-message required"}));
            }
            body.to_vec()
        } else if method == Method::GET {
            let dns: Vec<_> = query.iter().filter(|(k, _)| k == "dns").collect();
            if dns.len() != 1 {
                return response(400, json!({"error":"one dns parameter required"}));
            }
            match URL_SAFE_NO_PAD.decode(&dns[0].1) {
                Ok(b) => b,
                Err(_) => return response(400, json!({"error":"invalid base64url DNS message"})),
            }
        } else {
            return response(405, json!({"error":"method not allowed"}));
        };
        let zone = runtime.snapshot.read().await.clone();
        if now() >= u64::from(zone.expiration) {
            return response(503, json!({"error":"signature maintenance expired"}));
        }
        return match answer_query(&zone, &packet) {
            Ok(wire) => (
                [
                    ("content-type", "application/dns-message"),
                    ("cache-control", "no-store"),
                ],
                wire,
            )
                .into_response(),
            Err(e) => response(400, json!({"error":e.to_string()})),
        };
    }
    if method == Method::GET {
        let snapshot = runtime.db.read().unwrap();
        return match read_json(&snapshot, uri.path(), &query, now()) {
            Ok(mut result) => {
                result.body["backend"] = json!("development-memory");
                if let Some(v) = result.original_version {
                    result.body["tx_id"] = json!(format!("local.{v}"));
                    result.body["status"] = json!("local_committed");
                }
                if result.body.get("execution_state").is_some() {
                    result.body["observation_status"] = json!("local_committed");
                    result.body["observation_tx_id"] =
                        json!(format!("local.{}", snapshot.revision()));
                    result.body["tx_id"] = result.body["observation_tx_id"].clone();
                }
                response(result.http_status, result.body)
            }
            Err(e) => response(e.http_status(), json!({"error":e.to_string()})),
        };
    }
    if headers.get("content-type").and_then(|v| v.to_str().ok()) != Some("application/json") {
        return response(415, json!({"error":"application/json required"}));
    }
    let guard = runtime.mutation.lock().await;
    let mut tx = match runtime.db.write() {
        Ok(tx) => tx,
        Err(e) => return response(503, json!({"error":e.to_string()})),
    };
    match mutate_observed(&mut tx, method.as_str(), uri.path(), &body, now()) {
        Ok(mut result) => match tx.commit() {
            Ok(v) => {
                if let Err(e) = runtime.persist().await {
                    return response(503, json!({"error":e.to_string()}));
                }
                result.body["backend"] = json!("development-memory");
                result.body["tx_id"] =
                    json!(format!("local.{}", result.original_version.unwrap_or(v)));
                if result.promote_status_on_commit && result.body.get("status").is_some() {
                    result.body["status"] = json!("local_committed");
                }
                if result.body.get("execution_state").is_some() {
                    result.body["observation_status"] = json!("local_committed");
                    result.body["observation_tx_id"] = json!(format!("local.{v}"));
                }
                let notify = !result.changed_zones.is_empty();
                drop(guard);
                if notify {
                    runtime.notify_and_observe(true).await;
                }
                response(result.http_status, result.body)
            }
            Err(e) => response(503, json!({"error":e.to_string()})),
        },
        Err(e) => response(e.http_status(), json!({"error":e.to_string()})),
    }
}
async fn transfer(
    runtime: Arc<Runtime>,
    mut stream: tokio::net::TcpStream,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    loop {
        let len = match tokio::time::timeout(std::time::Duration::from_secs(10), stream.read_u16())
            .await
        {
            Ok(Ok(n)) => usize::from(n),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            _ => return Err("transfer read timeout".into()),
        };
        if len < 12 {
            return Err("short query".into());
        }
        let mut packet = vec![0; len];
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            stream.read_exact(&mut packet),
        )
        .await??;
        let query = verify_request(&packet, &runtime.tsig, now())?;
        let zone = runtime.snapshot.read().await.clone();
        if now() >= u64::from(zone.expiration) {
            return Err("signed snapshot expired".into());
        }
        let messages = if matches!(
            query.message.questions[0].qtype,
            RecordType::Axfr | RecordType::Ixfr
        ) {
            axfr_messages(
                &query,
                &zone.origin,
                &zone.records,
                &runtime.tsig,
                now(),
                16000,
            )?
        } else {
            let unsigned = query.message.to_wire()?;
            let answer = answer_query(&zone, &unsigned)?;
            vec![
                sign_message(
                    &answer,
                    &runtime.tsig,
                    now(),
                    Some(&query.request_mac),
                    false,
                )?
                .0,
            ]
        };
        for msg in messages {
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                stream.write_u16(msg.len() as u16).await?;
                stream.write_all(&msg).await
            })
            .await??;
        }
    }
}
fn initialize(dir: &Path, zone: &str) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use ring::rand::{SecureRandom, SystemRandom};
    std::fs::create_dir_all(dir)?;
    let dir = std::fs::canonicalize(dir)?;
    if dir.join("config.json").exists() {
        return Err("configuration already exists".into());
    }
    let mut seal = [0; 32];
    let mut secret = [0; 32];
    SystemRandom::new().fill(&mut seal).map_err(|_| "rng")?;
    SystemRandom::new().fill(&mut secret).map_err(|_| "rng")?;
    save_private(&dir.join("seal.key"), &seal)?;
    save_private(&dir.join("tsig.key"), &secret)?;
    let origin: WireName = zone.parse()?;
    let ns = format!("ns.{zone}").parse()?;
    let config = Config {
        http_listen: "127.0.0.1:8080".into(),
        transfer_listen: "0.0.0.0:5353".into(),
        zone: zone.into(),
        signature_validity: 900,
        refresh_before: 300,
        state_file: dir.join("state.sealed"),
        seal_key_file: dir.join("seal.key"),
        tsig_name: "agentdns-transfer.".into(),
        tsig_secret_file: dir.join("tsig.key"),
        secondaries: vec![],
        initial_grants: vec![],
        initial_policy: None,
        initial_records: vec![
            ResourceRecord::new(
                origin,
                300,
                RData::Soa(SoaData {
                    mname: ns,
                    rname: format!("hostmaster.{zone}").parse()?,
                    serial: 1,
                    refresh: 5,
                    retry: 2,
                    expire: 3600,
                    minimum: 60,
                }),
            )?,
            ResourceRecord::new(origin, 300, RData::Ns(ns))?,
            ResourceRecord::new(ns, 300, RData::A("192.0.2.53".parse()?))?,
        ],
    };
    save_private(
        &dir.join("config.json"),
        &serde_json::to_vec_pretty(&config)?,
    )?;
    save_private(
        &dir.join("bind-key.conf"),
        format!(
            "key \"{}\" {{ algorithm hmac-sha256; secret \"{}\"; }};\n",
            config.tsig_name,
            STANDARD.encode(secret)
        )
        .as_bytes(),
    )?;
    println!(
        "Development configuration: {}",
        dir.join("config.json").display()
    );
    Ok(())
}
#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("init") {
        return initialize(
            Path::new(args.get(2).ok_or("init DIRECTORY ZONE")?),
            args.get(3).ok_or("init DIRECTORY ZONE")?,
        );
    }
    let path = args
        .get(1)
        .ok_or("usage: adns-dev init DIRECTORY ZONE | adns-dev CONFIG.json")?;
    let config: Config = serde_json::from_slice(&std::fs::read(path)?)?;
    let seal_key: [u8; 32] = std::fs::read(&config.seal_key_file)?
        .try_into()
        .map_err(|_| "invalid seal key")?;
    let secret = std::fs::read(&config.tsig_secret_file)?;
    let tsig = TsigKey::new(config.tsig_name.parse()?, secret)?;
    let db = if config.state_file.exists() {
        MemoryStorage::restore(&std::fs::read(&config.state_file)?, &seal_key)?
    } else {
        let db = MemoryStorage::default();
        let mut tx = db.write()?;
        put_json(
            &mut tx,
            Collection::Lifecycle,
            b"configuration".to_vec(),
            &ServiceConfiguration {
                audience: "ccf://agentdns.development".into(),
                epoch: 1,
                last_time: now(),
            },
        )?;
        for grant in &config.initial_grants {
            grant.validate()?;
            put_json(
                &mut tx,
                Collection::Grants,
                grant.grant_id.as_bytes().to_vec(),
                grant,
            )?;
        }
        if let Some(policy) = &config.initial_policy {
            put_json(
                &mut tx,
                Collection::Policies,
                config.zone.parse::<WireName>()?.as_slice().to_vec(),
                policy,
            )?;
        }
        initialize_zone(
            &mut tx,
            ZoneMetadata {
                id: ZoneId(1),
                origin: config.zone.parse()?,
                serial: 1,
                base_records: config.initial_records.clone(),
                signed_records: vec![],
                signature_validity: config.signature_validity,
                refresh_before: config.refresh_before,
                last_signed_at: 0,
                earliest_signature_expiration: 0,
                maintenance_health: "starting".into(),
                ksk_dnskey_rdata: vec![],
                ksk_rollover: None,
            },
            now(),
        )?;
        tx.commit()?;
        db
    };
    validate_lifecycle_format(&db.read()?)?;
    let signed = snapshot(&db, &config.zone)?;
    let runtime = Arc::new(Runtime {
        config,
        db,
        seal_key,
        tsig,
        snapshot: RwLock::new(Arc::new(signed)),
        mutation: Mutex::new(()),
    });
    runtime.persist().await?;
    let udp = Arc::new(UdpSocket::bind(&runtime.config.transfer_listen).await?);
    let udp_runtime = runtime.clone();
    tokio::spawn(async move {
        let mut buffer = vec![0; 65535];
        loop {
            let Ok((len, peer)) = udp.recv_from(&mut buffer).await else {
                break;
            };
            let Ok(query) = verify_request(&buffer[..len], &udp_runtime.tsig, now()) else {
                continue;
            };
            if query.message.questions[0].qtype != RecordType::Soa {
                continue;
            }
            let zone = udp_runtime.snapshot.read().await.clone();
            if now() >= u64::from(zone.expiration) {
                continue;
            }
            let Ok(unsigned) = query.message.to_wire() else {
                continue;
            };
            let Ok(answer) = answer_query(&zone, &unsigned) else {
                continue;
            };
            let Ok((signed, _)) = sign_message(
                &answer,
                &udp_runtime.tsig,
                now(),
                Some(&query.request_mac),
                false,
            ) else {
                continue;
            };
            if signed.len() <= 1232 {
                let _ = udp.send_to(&signed, peer).await;
            }
        }
    });
    let tcp = TcpListener::bind(&runtime.config.transfer_listen).await?;
    let http_listener = TcpListener::bind(&runtime.config.http_listen).await?;
    let accept = runtime.clone();
    let permits = Arc::new(tokio::sync::Semaphore::new(64));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = tcp.accept().await else {
                break;
            };
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                continue;
            };
            let r = accept.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = transfer(r, stream).await {
                    eprintln!("transfer rejected: {e}");
                }
            });
        }
    });
    let timer = runtime.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            let lock = timer.mutation.lock().await;
            let mut tx = match timer.db.write() {
                Ok(tx) => tx,
                Err(e) => {
                    eprintln!("maintenance storage: {e}");
                    continue;
                }
            };
            let changed = match maintenance(&mut tx, now()) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("maintenance failed: {e}");
                    continue;
                }
            };
            if tx.commit().is_ok() {
                if let Err(e) = timer.persist().await {
                    eprintln!("maintenance persistence: {e}");
                }
            }
            drop(lock);
            timer.notify_and_observe(!changed.is_empty()).await;
        }
    });
    eprintln!(
        "DEVELOPMENT MEMORY BACKEND: HTTP {}, TSIG transfer {}",
        runtime.config.http_listen, runtime.config.transfer_listen
    );
    let app = Router::new()
        .fallback(http)
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .with_state(runtime);
    axum::serve(http_listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
