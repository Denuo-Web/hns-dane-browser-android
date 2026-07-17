use hns_browser_runtime::{
    BrowserRuntime, GatewayHttpRequest, ResolutionMode, RuntimeConfiguration, RuntimePolicy,
    SyncOptions,
};
use hns_core::dns::{
    DnsEncodeConfig, DnsFlags, DnsHeader, DnsMessage, DnsName, DnsQuestion, RecordType,
    ResourceRecord,
};
use hns_core::network::NetworkKind;
use hns_p2p::{DnsRelayClient, PeerManager, SqlitePeerStore};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

const DNS_CLASS_IN: u16 = 1;
const DNS_OPT_TYPE: u16 = 41;
const DNSSEC_DO_FLAG: u32 = 0x8000;

fn main() {
    if let Err(error) = run() {
        eprintln!("full-tier browser acceptance failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let data_dir = required_env("DATA_DIR")?;
    let artifact_dir = PathBuf::from(required_env("ARTIFACT_DIR")?);
    let network = required_env("HNS_NETWORK")?
        .parse::<NetworkKind>()
        .map_err(|_| "HNS_NETWORK must be regtest".to_owned())?;
    if network != NetworkKind::Regtest {
        return Err("the full-tier acceptance binary is deliberately regtest-only".to_owned());
    }

    let name = required_env("HNS_NAME")?;
    let url = required_env("HNS_URL")?;
    let legacy_doh_sentinel = required_env("HNS_DOH_RESOLVER")?;
    let peers = socket_list(&required_env("HNS_STATIC_PEERS")?)?;
    if peers.len() != 4 {
        return Err(format!(
            "HNS_STATIC_PEERS must contain exactly four nodes, got {}",
            peers.len()
        ));
    }
    if peers.iter().copied().collect::<HashSet<_>>().len() != 4 {
        return Err("HNS_STATIC_PEERS must contain four distinct node sockets".to_owned());
    }
    let bad_relay = env_socket("HNS_BAD_RELAY")?;
    let good_relay = env_socket("HNS_GOOD_RELAY")?;
    if bad_relay == good_relay || !peers.contains(&bad_relay) || !peers.contains(&good_relay) {
        return Err(
            "good and bad relay addresses must be distinct members of HNS_STATIC_PEERS".to_owned(),
        );
    }

    let target_height_path = PathBuf::from(required_env("HNS_TARGET_HEIGHT_FILE")?);
    let target_height = read_target_height(&target_height_path)?;
    fs::create_dir_all(&artifact_dir)
        .map_err(|error| format!("create artifact directory: {error}"))?;
    fs::create_dir_all(&data_dir).map_err(|error| format!("create data directory: {error}"))?;

    let relay_exchange = verify_real_relay_failover(network, &name, bad_relay, good_relay)?;
    if relay_exchange.retries == 0 || relay_exchange.peer != good_relay {
        return Err(format!(
            "real relay failover did not use the alternate: peer={}, retries={}",
            relay_exchange.peer, relay_exchange.retries
        ));
    }
    validate_failover_response(&relay_exchange.response, &name)?;

    let peer_store_path = Path::new(&data_dir).join("hns-regtest/peers.sqlite");
    seed_peer_store(&peer_store_path, &peers, bad_relay, good_relay)?;

    let policy = RuntimePolicy {
        resolution_mode: ResolutionMode::Strict,
        // Keep a reachable sentinel configured while the independent compatibility control is
        // disabled. The harness requires that sentinel to observe zero connections.
        hns_doh_resolver: Some(legacy_doh_sentinel),
        experimental_p2p_dns_relay: true,
        legacy_hns_doh_compatibility: false,
        stateless_dane_certificates: false,
    };
    let runtime = BrowserRuntime::open(
        RuntimeConfiguration::new(&data_dir, network)
            .with_sync_options(SyncOptions {
                seed_peers: false,
                timeout: Duration::from_secs(5),
                ..SyncOptions::default()
            })
            .with_initial_policy(policy),
    )
    .map_err(|error| format!("open browser runtime: {error}"))?;

    let mut sync = runtime
        .sync_status()
        .map_err(|error| format!("read initial sync status: {error}"))?;
    for _ in 0..20 {
        sync = runtime
            .sync_once()
            .map_err(|error| format!("synchronize regtest headers: {error}"))?;
        eprintln!("{}", sync.to_json());
        if sync
            .best_height
            .is_some_and(|height| height >= target_height)
        {
            break;
        }
        thread::sleep(Duration::from_millis(250));
    }
    let best_height = sync
        .best_height
        .ok_or_else(|| "runtime did not establish a regtest header tip".to_owned())?;
    if best_height < target_height {
        return Err(format!(
            "runtime header tip {best_height} is below controller target {target_height}"
        ));
    }

    // Header synchronization rewards peers. Restore deterministic relay ordering so the
    // unreachable relay is exercised first and the working relay is the successful alternate.
    seed_peer_store(&peer_store_path, &peers, bad_relay, good_relay)?;

    let (host, port, path) = parse_https_url(&url)?;
    if !host.eq_ignore_ascii_case(name.trim_end_matches('.')) {
        return Err(format!(
            "HNS_URL host {host} does not match HNS_NAME {name}"
        ));
    }
    let registered_name = name
        .trim_end_matches('.')
        .rsplit('.')
        .next()
        .ok_or_else(|| "HNS_NAME has no registered root label".to_owned())?;
    let response = runtime
        .gateway_request(GatewayHttpRequest {
            method: "GET".to_owned(),
            scheme: "https".to_owned(),
            host: host.clone(),
            port,
            path_and_query: path,
            headers: vec![("Accept".to_owned(), "text/plain".to_owned())],
            body: Vec::new(),
        })
        .map_err(|error| format!("execute browser gateway request: {error}"))?
        .into_bytes();
    let response_text = String::from_utf8(response)
        .map_err(|_| "gateway response was not UTF-8 test content".to_owned())?;

    assert_contains(&response_text, "HTTP/1.1 200 ", "HTTPS status")?;
    assert_header(&response_text, "X-HNS-TLS-Policy", "dane")?;
    assert_header(&response_text, "X-HNS-Security-Path", "dane-p2p-dns-relay")?;
    assert_header(&response_text, "X-HNS-Resolver-Mode", "strict")?;
    assert_header(&response_text, "X-HNS-DoH-Fallback", "no")?;
    if header_value(&response_text, "X-HNS-Resolver-Policy").is_some() {
        return Err("legacy resolver policy appeared in a strict relay response".to_owned());
    }

    let trace = header_value(&response_text, "X-HNS-Resolution-Trace")
        .ok_or_else(|| "gateway response omitted its internal resolution trace".to_owned())?;
    for (needle, label) in [
        (r#""network":"regtest""#, "regtest network"),
        (r#""hnsProof":"verified""#, "Urkel proof"),
        (r#""localChainStale":false"#, "current local chain"),
        (r#""delegation":true"#, "delegation"),
        (
            r#""resolutionSource":"p2p_dns_relay""#,
            "P2P DNS-relay source",
        ),
        (r#""p2pDnsRelay":{"attempted":true"#, "relay attempt"),
        (r#""dnssec":"secure""#, "DNSSEC"),
        (r#""tlsaEvaluated":true"#, "TLSA evaluation"),
        (r#""tlsaFound":true"#, "TLSA record"),
        (r#""dnssecSecure":true"#, "TLSA DNSSEC status"),
        (r#""decision":"verified""#, "DANE decision"),
        (r#""certificateMatch":"pass""#, "certificate match"),
        (r#""webPkiFallback":false"#, "no WebPKI fallback"),
        (r#""fallback":{"used":false"#, "no legacy DoH fallback"),
    ] {
        assert_contains(&trace, needle, label)?;
    }

    let proof = runtime
        .proof_details(&host)
        .map_err(|error| format!("read verified proof details: {error}"))?;
    for (needle, label) in [
        (r#""network":"regtest""#, "proof network"),
        (r#""hnsProof":"verified""#, "proof verification"),
        (r#""secure":true"#, "proof security"),
        (r#""exists":true"#, "registered name existence"),
        (
            r#""cacheStatus":"anchored_to_current_tip""#,
            "proof chain anchor",
        ),
    ] {
        assert_contains(&proof, needle, label)?;
    }
    if proof.contains(r#""treeRoot":null"#) || proof.contains(r#""resourceValueHex":null"#) {
        return Err("verified proof omitted its Urkel tree root or resource value".to_owned());
    }

    let artifact = format!(
        concat!(
            "{{\n",
            "  \"status\": \"pass\",\n",
            "  \"network\": \"regtest\",\n",
            "  \"nodeCount\": 4,\n",
            "  \"targetHeight\": {},\n",
            "  \"bestHeight\": {},\n",
            "  \"registeredName\": {},\n",
            "  \"navigationName\": {},\n",
            "  \"urkelProof\": \"verified\",\n",
            "  \"dnssec\": \"secure\",\n",
            "  \"dane\": \"verified\",\n",
            "  \"httpsStatus\": 200,\n",
            "  \"resolutionSource\": \"p2p_dns_relay\",\n",
            "  \"legacyDohContact\": false,\n",
            "  \"relayFailover\": {{\"verified\": true, \"retryCount\": {}, \"peer\": {}}}\n",
            "}}\n"
        ),
        target_height,
        best_height,
        json_string(registered_name),
        json_string(&name),
        relay_exchange.retries,
        json_string(&relay_exchange.peer.to_string()),
    );
    atomic_write(&artifact_dir.join("full-tier-result.json"), &artifact)?;
    atomic_write(&artifact_dir.join("full-tier-proof.json"), &(proof + "\n"))?;
    println!("real four-node regtest Urkel/DNSSEC/DANE acceptance passed");
    Ok(())
}

fn verify_real_relay_failover(
    network: NetworkKind,
    name: &str,
    bad_relay: SocketAddr,
    good_relay: SocketAddr,
) -> Result<hns_p2p::DnsRelayExchange, String> {
    let mut peers = PeerManager::default();
    peers.upsert(bad_relay).score = 0;
    peers.upsert(good_relay).score = 100;
    let mut relay = DnsRelayClient::new(network.network(), peers);
    let query = dnssec_a_query(name)?;
    relay
        .resolve(&query)
        .map_err(|error| format!("real relay failover query: {error}"))
}

fn dnssec_a_query(name: &str) -> Result<Vec<u8>, String> {
    let question_name =
        DnsName::from_ascii(name).map_err(|error| format!("invalid relay query name: {error}"))?;
    let message = DnsMessage {
        header: DnsHeader {
            id: 0x6f31,
            flags: DnsFlags::new(0),
            question_count: 1,
            answer_count: 0,
            authority_count: 0,
            additional_count: 1,
        },
        questions: vec![DnsQuestion {
            name: question_name,
            record_type: RecordType::A,
            class: DNS_CLASS_IN,
        }],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: vec![ResourceRecord {
            name: DnsName::root(),
            record_type: RecordType::Unknown(DNS_OPT_TYPE),
            class: 1232,
            ttl: DNSSEC_DO_FLAG,
            rdata: Vec::new(),
        }],
    };
    message
        .encode(&DnsEncodeConfig::default())
        .map_err(|error| format!("encode relay DNS query: {error}"))
}

fn validate_failover_response(response: &[u8], name: &str) -> Result<(), String> {
    let expected_name =
        DnsName::from_ascii(name).map_err(|error| format!("invalid expected DNS name: {error}"))?;
    let message = DnsMessage::parse(response)
        .map_err(|error| format!("parse successful alternate relay response: {error}"))?;
    if message.header.flags.rcode() != 0 || message.header.flags.truncated() {
        return Err(format!(
            "alternate relay returned rcode {} or a truncated response",
            message.header.flags.rcode()
        ));
    }
    let has_address = message.answers.iter().any(|record| {
        record.name == expected_name
            && record.record_type == RecordType::A
            && record.rdata.as_slice() == [127, 0, 0, 1]
    });
    let has_address_signature = message.answers.iter().any(|record| {
        record.name == expected_name
            && record.record_type == RecordType::Rrsig
            && record.rdata.len() >= 2
            && u16::from_be_bytes([record.rdata[0], record.rdata[1]]) == RecordType::A.code()
    });
    if !has_address || !has_address_signature {
        return Err(
            "alternate relay response omitted the expected A RRset or its DNSSEC signature"
                .to_owned(),
        );
    }
    Ok(())
}

fn seed_peer_store(
    path: &Path,
    peers: &[SocketAddr],
    bad_relay: SocketAddr,
    good_relay: SocketAddr,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("create peer store parent: {error}"))?;
    }
    let store = SqlitePeerStore::open(path).map_err(|error| format!("open peer store: {error}"))?;
    let mut manager = store
        .load_manager()
        .map_err(|error| format!("load peer store: {error}"))?;
    manager.retain(|state| peers.contains(&state.address));
    for peer in peers {
        let state = manager.upsert(*peer);
        state.banned_until = None;
        state.score = if *peer == bad_relay {
            0
        } else if *peer == good_relay {
            100
        } else {
            200
        };
    }
    store
        .save_manager(&manager)
        .map_err(|error| format!("save peer store: {error}"))?;
    Ok(())
}

fn read_target_height(path: &Path) -> Result<u32, String> {
    for _ in 0..120 {
        match fs::read_to_string(path) {
            Ok(value) => {
                return value
                    .trim()
                    .parse::<u32>()
                    .map_err(|error| format!("parse {}: {error}", path.display()));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                thread::sleep(Duration::from_millis(250));
            }
            Err(error) => return Err(format!("read {}: {error}", path.display())),
        }
    }
    Err(format!("timed out waiting for {}", path.display()))
}

fn required_env(name: &str) -> Result<String, String> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("missing required environment variable {name}"))
}

fn socket_list(value: &str) -> Result<Vec<SocketAddr>, String> {
    value
        .split(',')
        .map(|item| {
            item.trim()
                .parse::<SocketAddr>()
                .map_err(|error| format!("invalid peer address {item}: {error}"))
        })
        .collect()
}

fn env_socket(name: &str) -> Result<SocketAddr, String> {
    required_env(name)?
        .parse()
        .map_err(|error| format!("invalid {name}: {error}"))
}

fn parse_https_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| "HNS_URL must use https://".to_owned())?;
    let (authority, path) = rest
        .split_once('/')
        .map(|(authority, path)| (authority, format!("/{path}")))
        .unwrap_or((rest, "/".to_owned()));
    let (host, port) = authority
        .rsplit_once(':')
        .map(|(host, port)| {
            port.parse::<u16>()
                .map(|port| (host.to_owned(), port))
                .map_err(|error| format!("invalid HNS_URL port: {error}"))
        })
        .transpose()?
        .unwrap_or_else(|| (authority.to_owned(), 443));
    if host.is_empty() {
        return Err("HNS_URL host is empty".to_owned());
    }
    Ok((host, port, path))
}

fn assert_header(response: &str, name: &str, expected: &str) -> Result<(), String> {
    let actual =
        header_value(response, name).ok_or_else(|| format!("gateway response omitted {name}"))?;
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(format!("{name} was {actual:?}, expected {expected:?}"))
    }
}

fn header_value(response: &str, wanted: &str) -> Option<String> {
    let head = response
        .split_once("\r\n\r\n")
        .map_or(response, |(head, _)| head);
    head.lines().skip(1).find_map(|line| {
        let (name, value) = line.trim_end_matches('\r').split_once(':')?;
        name.eq_ignore_ascii_case(wanted)
            .then(|| value.trim().to_owned())
    })
}

fn assert_contains(haystack: &str, needle: &str, label: &str) -> Result<(), String> {
    if haystack.contains(needle) {
        Ok(())
    } else {
        Err(format!("{label} evidence is missing: {needle}"))
    }
}

fn json_string(value: &str) -> String {
    let mut encoded = String::from("\"");
    for character in value.chars() {
        match character {
            '\"' => encoded.push_str("\\\""),
            '\\' => encoded.push_str("\\\\"),
            '\n' => encoded.push_str("\\n"),
            '\r' => encoded.push_str("\\r"),
            '\t' => encoded.push_str("\\t"),
            character if character.is_control() => {
                encoded.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => encoded.push(character),
        }
    }
    encoded.push('\"');
    encoded
}

fn atomic_write(path: &Path, value: &str) -> Result<(), String> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, value)
        .map_err(|error| format!("write {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path).map_err(|error| format!("publish {}: {error}", path.display()))
}
