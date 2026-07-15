//! Platform-neutral browser runtime shared by native application shells.

#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use hns_chain::{DifficultyPolicy, HeaderChain, SqliteHeaderStore, mainnet_sync_checkpoints};
use hns_core::dns::{
    DnsEncodeConfig, DnsFlags, DnsHeader, DnsMessage, DnsName, DnsQuestion, RecordType,
    ResourceRecord,
};
pub use hns_core::network::NetworkKind;
use hns_core::{BlockHeader, HEADER_SIZE, Height, NameHash};
use hns_dane::{
    DaneDecision, MAX_STATELESS_DANE_ROOTS, StatelessDaneConfig, TlsaMatching, TlsaRecord,
    TlsaSelector, TlsaUsage,
};
use hns_gateway::{Gateway, GatewayConfig, GatewayError, GatewayRequest, HnsHttpsMode};
use hns_loopback_proxy::{
    BackendError as ProxyBackendError, CancellationToken as ProxyCancellationToken, ProxyBackend,
    ProxyHeader, ProxyRequest as LoopbackProxyRequest, ProxyRequestBody, ProxyResponse,
    ProxyResponseBody, ProxyResponseHead, ProxyTunnel, ProxyTunnelOpen,
};
use hns_p2p::{
    DnsSeedPeerSource, HeaderSyncSession, PeerConnection, PeerSource, SqlitePeerStore,
    StaticPeerSource, VersionPacket, is_allowed_peer_endpoint,
};
use hns_resolver::{
    AuthoritativeDnssecResolver, AuthoritativeDohEndpoint, AuthoritativeDohTlsAuthentication,
    CompositeResolver, DelegatedResolver, DelegatingResolver, DnsEndpointPolicy,
    DnsInterceptionStatus, DnsTransport, HnsDelegation, HnsProofProvider, HnsResourceValueProvider,
    NameClass, ProvenNameRecords, ResolutionAnswer, ResolutionRequest, Resolver, ResolverError,
    ResourceValueAnchor, SqliteResourceValueProvider, SystemDnssecVerifier, UdpTcpDnsTransport,
    classify_name,
};
use hns_sync::{
    HeaderSyncCoordinator, HeaderSyncRunner, HeaderSyncRunnerConfig, ProofScheduler, SyncError,
    TcpHeaderPeerConnector,
};
pub use hns_transport::DEFAULT_MAX_REQUEST_BODY_BYTES;
use hns_transport::{
    OriginProtocol, OriginRequest, OriginResponse, OriginResponseHead, OriginTransport, ReadWrite,
    TcpHttpTransport, TlsCertificateInspection, TlsValidation, TlsaRecordSource, TransportError,
};
use hns_urkel::UrkelProofVerifier;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock, RwLockReadGuard, TryLockError, Weak};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const DEFAULT_RESOURCE_CACHE_LIMIT_BYTES: usize = 50 * 1024 * 1024;
pub const MAX_GATEWAY_HEADER_TEXT_BYTES: usize = 64 * 1024;
pub const LOCAL_TLS_CERT_FINGERPRINT_BYTES: usize = 32;
const DNS_CLASS_IN: u16 = 1;
const DNS_OPT_RECORD_TYPE: u16 = 41;
const DNS_RCODE_NOERROR: u8 = 0;
const DNS_RCODE_NXDOMAIN: u8 = 3;
const DNS_RECURSION_DESIRED_FLAG: u16 = 0x0100;
const DNS_AUTHENTIC_DATA_FLAG: u16 = 0x0020;
const DNSSEC_DO_FLAG: u32 = 0x8000;
const DEFAULT_DNS_UDP_PAYLOAD: usize = 1232;
const DEFAULT_GATEWAY_PROOF_PEERS: usize = 8;
const DEFAULT_GATEWAY_PROOF_TIMEOUT: Duration = Duration::from_secs(3);
const ANDROID_COMPAT_AUTHORITATIVE_DNS_TIMEOUT: Duration = Duration::from_millis(900);
const DNS_INTERCEPTION_PROBE_TIMEOUT: Duration = Duration::from_millis(350);
const DNS_INTERCEPTION_PROBE_ID: u16 = 0x484a;
const DNS_INTERCEPTION_PROBE_NAME: &str = "hns-dns-interception-probe.invalid";
const RESOURCE_PROOF_CACHE_CANONICAL_WINDOW: u32 = 144;
const ANDROID_HEADER_SYNC_PEERS: usize = 12;
const ANDROID_HEADER_SYNC_BATCHES_PER_PEER: usize = 16;
const ANDROID_PARALLEL_PEER_PROBES: usize = 32;
const ANDROID_PARALLEL_HEADER_FETCH_PEERS: usize = 4;
const ANDROID_MIN_PEER_TARGET: usize = 64;
const ANDROID_PEER_HEIGHT_REFRESH_INTERVAL_SECONDS: u64 = 10 * 60;
const HEADER_SNAPSHOT_MAGIC: &[u8] = b"HNSHDRSNAP1";
const HEADER_SNAPSHOT_IMPORT_BATCH: usize = 2_000;
const HEADER_SNAPSHOT_MAX_HEIGHT: u32 = 1_000_000;
const MAINNET_GENESIS_TIME: u64 = 1_580_745_078;
const MAINNET_TARGET_SPACING_SECONDS: u64 = 10 * 60;
const LOCAL_CHAIN_CURRENTNESS_ALLOWED_LAG: u32 = RESOURCE_PROOF_CACHE_CANONICAL_WINDOW;
const HNS_DOH_HOST: &str = "zorro.hnsdoh.com";
const HNS_DOH_PATH: &str = "/dns-query";
const ICANN_DOH_HOST: &str = "cloudflare-dns.com";
const ICANN_DOH_PATH: &str = "/dns-query";
const HNS_GATEWAY_STRICT_MODE_HEADER: &str = "X-HNS-Browser-Strict-Mode";
const HNS_GATEWAY_DOH_RESOLVER_HEADER: &str = "X-HNS-Browser-DoH-Resolver";
const HNS_GATEWAY_STATELESS_DANE_HEADER: &str = "X-HNS-Browser-Stateless-DANE";
const HNS_GATEWAY_NETWORK_HEADER: &str = "X-HNS-Browser-Network";
const HNS_RESOLUTION_TRACE_HEADER: &str = "X-HNS-Resolution-Trace";
const HNS_RESOLVER_MODE_HEADER: &str = "X-HNS-Resolver-Mode";
const HNS_DOH_FALLBACK_HEADER: &str = "X-HNS-DoH-Fallback";
const HNS_SECURITY_PATH_HEADER: &str = "X-HNS-Security-Path";
const TUNNEL_COPY_BUFFER_BYTES: usize = 16 * 1024;
const PROXY_MAINTENANCE_POLL_INTERVAL: Duration = Duration::from_millis(25);
const MAX_PROXY_UPGRADE_HEADERS: usize = 256;
const DOH_DNS_ID: u16 = 0;
static SHARED_HTTP_TRANSPORT: OnceLock<TcpHttpTransport> = OnceLock::new();

fn shared_http_transport() -> TcpHttpTransport {
    SHARED_HTTP_TRANSPORT
        .get_or_init(TcpHttpTransport::default)
        .clone()
}

pub struct GatewayHttpRequestInput<'a> {
    pub data_dir: &'a str,
    pub method: &'a str,
    pub scheme: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub path_and_query: &'a str,
    pub header_text: &'a str,
    pub body: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeConfiguration {
    data_dir: PathBuf,
    network: NetworkKind,
    sync: SyncOptions,
    initial_policy: RuntimePolicy,
}

impl RuntimeConfiguration {
    pub fn new(data_dir: impl Into<PathBuf>, network: NetworkKind) -> Self {
        Self {
            data_dir: data_dir.into(),
            network,
            sync: SyncOptions::default(),
            initial_policy: RuntimePolicy::compatibility(),
        }
    }

    pub fn with_sync_options(mut self, sync: SyncOptions) -> Self {
        self.sync = sync;
        self
    }

    pub fn with_initial_policy(mut self, policy: RuntimePolicy) -> Self {
        self.initial_policy = policy;
        self
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn network(&self) -> NetworkKind {
        self.network
    }

    pub fn sync_options(&self) -> &SyncOptions {
        &self.sync
    }

    pub fn initial_policy(&self) -> &RuntimePolicy {
        &self.initial_policy
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncOptions {
    pub seed_peers: bool,
    pub timeout: Duration,
    pub resource_cache_limit_bytes: usize,
}

impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            seed_peers: true,
            timeout: Duration::from_secs(3),
            resource_cache_limit_bytes: DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePolicy {
    pub resolution_mode: ResolutionMode,
    pub hns_doh_resolver: Option<String>,
    pub stateless_dane_certificates: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionMode {
    Strict,
    Compatibility,
}

impl RuntimePolicy {
    pub fn compatibility() -> Self {
        Self {
            resolution_mode: ResolutionMode::Compatibility,
            hns_doh_resolver: None,
            stateless_dane_certificates: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayHttpRequest {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayHttpResponse {
    pub encoded_http: Vec<u8>,
}

impl GatewayHttpResponse {
    pub fn into_bytes(self) -> Vec<u8> {
        self.encoded_http
    }
}

struct GeneratedLocalCertificate {
    certificate_der: Vec<u8>,
    private_key_pkcs8_der: Vec<u8>,
    certificate_sha256: [u8; LOCAL_TLS_CERT_FINGERPRINT_BYTES],
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RuntimeError {
    #[error("invalid runtime configuration: {0}")]
    InvalidConfiguration(String),
    #[error("runtime operation failed: {0}")]
    Operation(String),
    #[error("runtime synchronization state is poisoned: {0}")]
    Synchronization(&'static str),
}

#[derive(Clone)]
pub struct BrowserRuntime {
    inner: Arc<RuntimeInner>,
}

/// Cloneable, platform-neutral adapter from the shared browser runtime into
/// the Rust loopback proxy's typed request and tunnel boundary.
#[derive(Clone)]
pub struct RuntimeProxyBackend {
    runtime: BrowserRuntime,
}

impl std::fmt::Debug for RuntimeProxyBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RuntimeProxyBackend(<redacted runtime>)")
    }
}

struct RuntimeInner {
    configuration: RuntimeConfiguration,
    policy: RwLock<RuntimePolicy>,
    data_dir: String,
    transport: TcpHttpTransport,
    coordination: Arc<RuntimeCoordination>,
    policy_revision: AtomicU64,
}

struct RuntimeCoordination {
    sync_lock: Mutex<()>,
    maintenance: RwLock<()>,
    peer_state: Arc<Mutex<()>>,
}

static RUNTIME_COORDINATION: OnceLock<Mutex<HashMap<PathBuf, Weak<RuntimeCoordination>>>> =
    OnceLock::new();

fn runtime_coordination(base: &Path) -> Result<Arc<RuntimeCoordination>, RuntimeError> {
    let identity = fs::canonicalize(base).map_err(|error| {
        RuntimeError::Operation(format!("canonicalize runtime storage directory: {error}"))
    })?;
    let registry = RUNTIME_COORDINATION.get_or_init(|| Mutex::new(HashMap::new()));
    let mut registry = registry
        .lock()
        .map_err(|_| RuntimeError::Synchronization("runtime coordination registry"))?;
    registry.retain(|_, coordination| coordination.strong_count() != 0);
    if let Some(coordination) = registry.get(&identity).and_then(Weak::upgrade) {
        return Ok(coordination);
    }
    let coordination = Arc::new(RuntimeCoordination {
        sync_lock: Mutex::new(()),
        maintenance: RwLock::new(()),
        peer_state: Arc::new(Mutex::new(())),
    });
    registry.insert(identity, Arc::downgrade(&coordination));
    Ok(coordination)
}

impl BrowserRuntime {
    pub fn open(mut configuration: RuntimeConfiguration) -> Result<Self, RuntimeError> {
        let configured_data_dir = configuration
            .data_dir
            .to_str()
            .filter(|path| !path.is_empty())
            .ok_or_else(|| {
                RuntimeError::InvalidConfiguration(
                    "data directory must be a non-empty UTF-8 path".to_owned(),
                )
            })?
            .to_owned();
        fs::create_dir_all(&configured_data_dir).map_err(|error| {
            RuntimeError::Operation(format!("create runtime data directory: {error}"))
        })?;
        let canonical_data_dir = fs::canonicalize(&configured_data_dir).map_err(|error| {
            RuntimeError::Operation(format!("canonicalize runtime data directory: {error}"))
        })?;
        let data_dir = canonical_data_dir
            .to_str()
            .ok_or_else(|| {
                RuntimeError::InvalidConfiguration(
                    "canonical data directory must be a UTF-8 path".to_owned(),
                )
            })?
            .to_owned();
        configuration.data_dir = canonical_data_dir;
        let mut policy = configuration.initial_policy.clone();
        if let Some(endpoint) = policy.hns_doh_resolver.as_deref() {
            policy.hns_doh_resolver = Some(
                HnsDohEndpoint::parse(endpoint)
                    .map_err(|error| RuntimeError::InvalidConfiguration(error.to_owned()))?
                    .display(),
            );
        }
        let base = network_base_path(&data_dir, configuration.network);
        fs::create_dir_all(&base).map_err(|error| {
            RuntimeError::Operation(format!("create runtime directory: {error}"))
        })?;
        let coordination = runtime_coordination(&base)?;

        configuration.initial_policy = policy.clone();
        Ok(Self {
            inner: Arc::new(RuntimeInner {
                configuration,
                policy: RwLock::new(policy),
                data_dir,
                transport: TcpHttpTransport::default(),
                coordination,
                policy_revision: AtomicU64::new(0),
            }),
        })
    }

    pub fn configuration(&self) -> Result<RuntimeConfiguration, RuntimeError> {
        let mut configuration = self.inner.configuration.clone();
        let policy = self.policy()?;
        configuration.initial_policy = policy;
        Ok(configuration)
    }

    pub fn network(&self) -> NetworkKind {
        self.inner.configuration.network
    }

    pub fn policy(&self) -> Result<RuntimePolicy, RuntimeError> {
        self.policy_snapshot().map(|(policy, _)| policy)
    }

    pub fn policy_snapshot(&self) -> Result<(RuntimePolicy, u64), RuntimeError> {
        let policy = self
            .inner
            .policy
            .read()
            .map_err(|_| RuntimeError::Synchronization("policy lock"))?;
        let revision = self.inner.policy_revision.load(Ordering::Acquire);
        Ok((policy.clone(), revision))
    }

    pub fn set_policy(&self, mut policy: RuntimePolicy) -> Result<u64, RuntimeError> {
        if let Some(endpoint) = policy.hns_doh_resolver.as_deref() {
            policy.hns_doh_resolver = Some(
                HnsDohEndpoint::parse(endpoint)
                    .map_err(|error| RuntimeError::InvalidConfiguration(error.to_owned()))?
                    .display(),
            );
        }
        let mut current = self
            .inner
            .policy
            .write()
            .map_err(|_| RuntimeError::Synchronization("policy lock"))?;
        *current = policy;
        let revision = self.inner.policy_revision.fetch_add(1, Ordering::AcqRel) + 1;
        Ok(revision)
    }

    pub fn policy_revision(&self) -> u64 {
        self.inner.policy_revision.load(Ordering::Acquire)
    }

    /// Returns a proxy backend that shares this runtime's policy, persistent
    /// stores, resolver coordination, and origin transport state.
    pub fn proxy_backend(&self) -> RuntimeProxyBackend {
        RuntimeProxyBackend {
            runtime: self.clone(),
        }
    }

    pub fn sync_once(&self) -> Result<SyncStatus, RuntimeError> {
        let _sync = self
            .inner
            .coordination
            .sync_lock
            .lock()
            .map_err(|_| RuntimeError::Synchronization("sync lock"))?;
        let _maintenance = self
            .inner
            .coordination
            .maintenance
            .read()
            .map_err(|_| RuntimeError::Synchronization("maintenance lock"))?;
        let _peer_state = self
            .inner
            .coordination
            .peer_state
            .lock()
            .map_err(|_| RuntimeError::Synchronization("peer state lock"))?;
        run_sync_once(
            &self.inner.data_dir,
            self.inner.configuration.network,
            self.inner.configuration.sync.seed_peers,
            self.inner.configuration.sync.timeout,
            self.inner.configuration.sync.resource_cache_limit_bytes,
        )
        .map_err(RuntimeError::Operation)
    }

    pub fn sync_status(&self) -> Result<SyncStatus, RuntimeError> {
        let _maintenance = self
            .inner
            .coordination
            .maintenance
            .read()
            .map_err(|_| RuntimeError::Synchronization("maintenance lock"))?;
        read_sync_status(&self.inner.data_dir, self.inner.configuration.network)
            .map_err(RuntimeError::Operation)
    }

    pub fn clear_resolver_cache(&self) -> Result<SyncStatus, RuntimeError> {
        let _sync = self
            .inner
            .coordination
            .sync_lock
            .lock()
            .map_err(|_| RuntimeError::Synchronization("sync lock"))?;
        let _maintenance = self
            .inner
            .coordination
            .maintenance
            .write()
            .map_err(|_| RuntimeError::Synchronization("maintenance lock"))?;
        clear_resolver_cache_inner(&self.inner.data_dir, self.inner.configuration.network)
            .map_err(RuntimeError::Operation)
    }

    pub fn install_header_snapshot(
        &self,
        snapshot_path: impl AsRef<Path>,
    ) -> Result<SyncStatus, RuntimeError> {
        let snapshot_path = snapshot_path.as_ref().to_str().ok_or_else(|| {
            RuntimeError::InvalidConfiguration("snapshot must be a UTF-8 path".to_owned())
        })?;
        let _sync = self
            .inner
            .coordination
            .sync_lock
            .lock()
            .map_err(|_| RuntimeError::Synchronization("sync lock"))?;
        let _maintenance = self
            .inner
            .coordination
            .maintenance
            .write()
            .map_err(|_| RuntimeError::Synchronization("maintenance lock"))?;
        install_header_snapshot_inner(
            &self.inner.data_dir,
            snapshot_path,
            self.inner.configuration.network,
        )
        .map_err(RuntimeError::Operation)
    }

    pub fn reset_headers_from_peers(&self) -> Result<SyncStatus, RuntimeError> {
        let _sync = self
            .inner
            .coordination
            .sync_lock
            .lock()
            .map_err(|_| RuntimeError::Synchronization("sync lock"))?;
        let _maintenance = self
            .inner
            .coordination
            .maintenance
            .write()
            .map_err(|_| RuntimeError::Synchronization("maintenance lock"))?;
        reset_headers_from_peers_inner(&self.inner.data_dir, self.inner.configuration.network)
            .map_err(RuntimeError::Operation)
    }

    pub fn proof_details(&self, host_or_url: &str) -> Result<String, RuntimeError> {
        let _maintenance = self
            .inner
            .coordination
            .maintenance
            .read()
            .map_err(|_| RuntimeError::Synchronization("maintenance lock"))?;
        Ok(hns_proof_details_for_network(
            &self.inner.data_dir,
            host_or_url,
            self.inner.configuration.network,
        ))
    }

    pub fn gateway_request(
        &self,
        request: GatewayHttpRequest,
    ) -> Result<GatewayHttpResponse, RuntimeError> {
        self.validate_gateway_request(&request)?;
        let _maintenance = self
            .inner
            .coordination
            .maintenance
            .read()
            .map_err(|_| RuntimeError::Synchronization("maintenance lock"))?;
        let header_text = self.gateway_header_text(&request.headers)?;
        let encoded_http = gateway_http_response_with_transport(
            GatewayHttpRequestInput {
                data_dir: &self.inner.data_dir,
                method: &request.method,
                scheme: &request.scheme,
                host: &request.host,
                port: request.port,
                path_and_query: &request.path_and_query,
                header_text: &header_text,
                body: &request.body,
            },
            self.inner.transport.clone(),
            Some(Arc::clone(&self.inner.coordination.peer_state)),
        );
        Ok(GatewayHttpResponse { encoded_http })
    }

    pub fn gateway_request_body_to_file(
        &self,
        request: GatewayHttpRequest,
        body_path: impl AsRef<Path>,
    ) -> Result<Vec<u8>, RuntimeError> {
        self.validate_gateway_request(&request)?;
        let _maintenance = self
            .inner
            .coordination
            .maintenance
            .read()
            .map_err(|_| RuntimeError::Synchronization("maintenance lock"))?;
        let header_text = self.gateway_header_text(&request.headers)?;
        gateway_http_response_body_to_file_with_transport(
            GatewayHttpRequestInput {
                data_dir: &self.inner.data_dir,
                method: &request.method,
                scheme: &request.scheme,
                host: &request.host,
                port: request.port,
                path_and_query: &request.path_and_query,
                header_text: &header_text,
                body: &request.body,
            },
            body_path.as_ref(),
            self.inner.transport.clone(),
            Some(Arc::clone(&self.inner.coordination.peer_state)),
        )
        .map_err(RuntimeError::Operation)
    }

    fn validate_gateway_request(&self, request: &GatewayHttpRequest) -> Result<(), RuntimeError> {
        if request.body.len() > DEFAULT_MAX_REQUEST_BODY_BYTES {
            return Err(RuntimeError::InvalidConfiguration(format!(
                "gateway request body exceeds {DEFAULT_MAX_REQUEST_BODY_BYTES} bytes"
            )));
        }
        let header_bytes = request
            .headers
            .iter()
            .try_fold(0usize, |total, (name, value)| {
                total
                    .checked_add(name.len())
                    .and_then(|total| total.checked_add(value.len()))
                    .and_then(|total| total.checked_add(4))
            });
        if header_bytes.is_none_or(|bytes| bytes > MAX_GATEWAY_HEADER_TEXT_BYTES) {
            return Err(RuntimeError::InvalidConfiguration(format!(
                "gateway request headers exceed {MAX_GATEWAY_HEADER_TEXT_BYTES} bytes"
            )));
        }
        Ok(())
    }

    fn gateway_header_text(&self, headers: &[(String, String)]) -> Result<String, RuntimeError> {
        let policy = self.policy()?;
        let mut header_text = String::new();
        for (name, value) in headers {
            if !is_valid_gateway_header_name(name) || !is_valid_gateway_header_value(value) {
                return Err(RuntimeError::InvalidConfiguration(
                    "gateway request contains an invalid header".to_owned(),
                ));
            }
            if is_reserved_hns_header(name) {
                continue;
            }
            header_text.push_str(name);
            header_text.push_str(": ");
            header_text.push_str(value);
            header_text.push_str("\r\n");
        }
        if policy.resolution_mode == ResolutionMode::Strict {
            header_text.push_str(HNS_GATEWAY_STRICT_MODE_HEADER);
            header_text.push_str(": 1\r\n");
        }
        if let Some(endpoint) = policy.hns_doh_resolver.as_deref() {
            header_text.push_str(HNS_GATEWAY_DOH_RESOLVER_HEADER);
            header_text.push_str(": ");
            header_text.push_str(endpoint);
            header_text.push_str("\r\n");
        }
        if policy.stateless_dane_certificates {
            header_text.push_str(HNS_GATEWAY_STATELESS_DANE_HEADER);
            header_text.push_str(": 1\r\n");
        }
        header_text.push_str(HNS_GATEWAY_NETWORK_HEADER);
        header_text.push_str(": ");
        header_text.push_str(self.inner.configuration.network.as_str());
        header_text.push_str("\r\n");
        Ok(header_text)
    }
}

struct PreparedRuntimeGateway {
    gateway: Gateway<AndroidGatewayResolver, TcpHttpTransport>,
    request: GatewayRequest,
    network: NetworkKind,
    mode: GatewayResolutionMode,
    fallback_marker: FallbackMarker,
    dns_trace: DnsTraceRecorder,
}

impl BrowserRuntime {
    fn acquire_proxy_maintenance<'a>(
        &'a self,
        cancellation: &ProxyCancellationToken,
    ) -> Result<RwLockReadGuard<'a, ()>, ProxyBackendError> {
        loop {
            if cancellation.is_cancelled() {
                return Err(ProxyBackendError::Cancelled);
            }
            match self.inner.coordination.maintenance.try_read() {
                Ok(guard) => return Ok(guard),
                Err(TryLockError::Poisoned(_)) => return Err(ProxyBackendError::Internal),
                Err(TryLockError::WouldBlock) => {
                    if cancellation.wait_cancelled_timeout(PROXY_MAINTENANCE_POLL_INTERVAL) {
                        return Err(ProxyBackendError::Cancelled);
                    }
                }
            }
        }
    }

    fn prepare_proxy_gateway(
        &self,
        request: &GatewayHttpRequest,
    ) -> Result<PreparedRuntimeGateway, RuntimeError> {
        self.validate_gateway_request(request)?;
        let header_text = self.gateway_header_text(&request.headers)?;
        let parsed_headers = parse_gateway_headers(&header_text)
            .map_err(|error| RuntimeError::InvalidConfiguration(error.to_owned()))?;
        let network = parsed_headers.network;
        let mode = GatewayResolutionMode::from_strict_hns_mode(parsed_headers.strict_hns_mode);
        let input = GatewayHttpRequestInput {
            data_dir: &self.inner.data_dir,
            method: &request.method,
            scheme: &request.scheme,
            host: &request.host,
            port: request.port,
            path_and_query: &request.path_and_query,
            header_text: &header_text,
            body: &request.body,
        };
        let gateway_request = gateway_request(&input, parsed_headers.headers);
        let base = network_base_path(&self.inner.data_dir, network);
        fs::create_dir_all(&base).map_err(|error| {
            RuntimeError::Operation(format!("create gateway directory: {error}"))
        })?;
        let values = SqliteResourceValueProvider::open(base.join("resources.sqlite"))
            .map_err(|error| RuntimeError::Operation(format!("open resource cache: {error}")))?;
        let fallback_marker = FallbackMarker::default();
        let dns_trace = DnsTraceRecorder::default();
        let resolver = android_gateway_resolver(
            base.clone(),
            values,
            GatewayResolverContext {
                network,
                mode,
                doh_endpoint: parsed_headers.doh_endpoint,
                peer_state: Some(Arc::clone(&self.inner.coordination.peer_state)),
                http: self.inner.transport.clone(),
            },
            fallback_marker.clone(),
            dns_trace.clone(),
        );
        let stateless_dane =
            stateless_dane_config(&base, parsed_headers.stateless_dane_certificates);
        let gateway = Gateway::new(
            GatewayConfig {
                hns_https_mode: HnsHttpsMode::Compatibility,
                stateless_dane,
                allow_non_public_origin_addresses: network == NetworkKind::Regtest || cfg!(test),
                allow_unsafe_origin_ports: network == NetworkKind::Regtest,
                ..GatewayConfig::default()
            },
            resolver,
            self.inner.transport.clone(),
        )
        .map_err(|error| RuntimeError::Operation(format!("create gateway: {error}")))?;
        Ok(PreparedRuntimeGateway {
            gateway,
            request: gateway_request,
            network,
            mode,
            fallback_marker,
            dns_trace,
        })
    }
}

impl ProxyBackend for RuntimeProxyBackend {
    fn execute(
        &self,
        request: LoopbackProxyRequest,
        cancellation: &ProxyCancellationToken,
    ) -> Result<ProxyResponse, ProxyBackendError> {
        if cancellation.is_cancelled() {
            return Err(ProxyBackendError::Cancelled);
        }
        let request = gateway_request_from_proxy(request);
        let _maintenance = self.runtime.acquire_proxy_maintenance(cancellation)?;
        let prepared = self
            .runtime
            .prepare_proxy_gateway(&request)
            .map_err(runtime_error_to_proxy_backend)?;
        if cancellation.is_cancelled() {
            return Err(ProxyBackendError::Cancelled);
        }
        let response = match prepared.gateway.handle(&prepared.request) {
            Ok(response) => response,
            Err(error) => {
                if cancellation.is_cancelled() {
                    return Err(ProxyBackendError::Cancelled);
                }
                return Ok(proxy_error_response_from_gateway(
                    &self.runtime,
                    &request,
                    prepared.network,
                    prepared.mode,
                    &error,
                    &prepared.fallback_marker,
                    &prepared.dns_trace,
                ));
            }
        };
        if cancellation.is_cancelled() {
            return Err(ProxyBackendError::Cancelled);
        }
        proxy_response_from_gateway(
            &self.runtime,
            &request,
            prepared.network,
            prepared.mode,
            response,
            &prepared.fallback_marker,
            &prepared.dns_trace,
        )
    }

    fn open_tunnel(
        &self,
        request: LoopbackProxyRequest,
        cancellation: &ProxyCancellationToken,
    ) -> Result<ProxyTunnelOpen, ProxyBackendError> {
        if cancellation.is_cancelled() {
            return Err(ProxyBackendError::Cancelled);
        }
        let request = gateway_request_from_proxy(request);
        let _maintenance = self.runtime.acquire_proxy_maintenance(cancellation)?;
        let prepared = self
            .runtime
            .prepare_proxy_gateway(&request)
            .map_err(runtime_error_to_proxy_backend)?;
        if cancellation.is_cancelled() {
            return Err(ProxyBackendError::Cancelled);
        }
        let response = match prepared.gateway.handle_tunnel(&prepared.request) {
            Ok(response) => response,
            Err(error) => {
                if cancellation.is_cancelled() {
                    return Err(ProxyBackendError::Cancelled);
                }
                return Ok(ProxyTunnelOpen::Response(
                    proxy_error_response_from_gateway(
                        &self.runtime,
                        &request,
                        prepared.network,
                        prepared.mode,
                        &error,
                        &prepared.fallback_marker,
                        &prepared.dns_trace,
                    ),
                ));
            }
        };
        if cancellation.is_cancelled() {
            return Err(ProxyBackendError::Cancelled);
        }
        proxy_tunnel_from_gateway(
            &self.runtime,
            &request,
            prepared.network,
            prepared.mode,
            response,
            &prepared.fallback_marker,
            &prepared.dns_trace,
        )
        .map(ProxyTunnelOpen::Tunnel)
    }
}

fn gateway_request_from_proxy(request: LoopbackProxyRequest) -> GatewayHttpRequest {
    GatewayHttpRequest {
        method: request.method,
        scheme: request.scheme,
        host: request.host,
        port: request.port,
        path_and_query: request.path_and_query,
        headers: request
            .headers
            .into_iter()
            .map(|header| (header.name, header.value))
            .collect(),
        body: match request.body {
            ProxyRequestBody::Empty => Vec::new(),
            ProxyRequestBody::Bytes(bytes) => bytes,
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn proxy_response_from_gateway(
    runtime: &BrowserRuntime,
    request: &GatewayHttpRequest,
    network: NetworkKind,
    mode: GatewayResolutionMode,
    response: hns_gateway::GatewayResponse,
    fallback_marker: &FallbackMarker,
    dns_trace: &DnsTraceRecorder,
) -> Result<ProxyResponse, ProxyBackendError> {
    let input = runtime_gateway_input(runtime, request);
    let resolver_policy = fallback_marker.used().then_some("hns-doh-compat");
    let security_path = security_path_name(
        &input,
        response.origin_request.port,
        &response.origin.dane_decision,
        &dns_trace.snapshot(),
    );
    let trace = resolution_trace_json(
        &input,
        network,
        mode,
        Some(&response.resolution),
        TlsTraceInput {
            validation: Some(&response.origin_request.tls),
            decision: Some(&response.origin.dane_decision),
            inspection: response.origin.tls_inspection.as_ref(),
            origin_address: response.origin_request.connect_host.as_deref(),
        },
        None,
        fallback_marker,
        dns_trace,
    );
    let mut headers = sanitize_typed_origin_headers(response.origin.headers)?;
    append_runtime_response_metadata(
        &mut headers,
        &response.origin.dane_decision,
        resolver_policy,
        security_path,
        &trace,
    );
    Ok(ProxyResponse {
        head: ProxyResponseHead {
            status_code: response.origin.status,
            reason_phrase: "OK".to_owned(),
            headers: proxy_headers(headers),
        },
        body: ProxyResponseBody::Bytes(response.origin.body),
    })
}

#[allow(clippy::too_many_arguments)]
fn proxy_error_response_from_gateway(
    runtime: &BrowserRuntime,
    request: &GatewayHttpRequest,
    network: NetworkKind,
    mode: GatewayResolutionMode,
    error: &GatewayError,
    fallback_marker: &FallbackMarker,
    dns_trace: &DnsTraceRecorder,
) -> ProxyResponse {
    let input = runtime_gateway_input(runtime, request);
    let (status, reason, detail) = map_gateway_error_for_host(&request.host, error);
    let trace = resolution_trace_json(
        &input,
        network,
        mode,
        None,
        TlsTraceInput::default(),
        Some(error),
        fallback_marker,
        dns_trace,
    );
    let address = gateway_request_address(&input);
    let body = plain_response_body(status, reason, detail, Some(&address));
    let mut headers = vec![(
        "Content-Type".to_owned(),
        "text/plain; charset=utf-8".to_owned(),
    )];
    append_runtime_response_metadata(&mut headers, &DaneDecision::NoTlsa, None, None, &trace);
    ProxyResponse {
        head: ProxyResponseHead {
            status_code: status,
            reason_phrase: reason.to_owned(),
            headers: proxy_headers(headers),
        },
        body: ProxyResponseBody::Bytes(body),
    }
}

#[allow(clippy::too_many_arguments)]
fn proxy_tunnel_from_gateway(
    runtime: &BrowserRuntime,
    request: &GatewayHttpRequest,
    network: NetworkKind,
    mode: GatewayResolutionMode,
    response: hns_gateway::GatewayTunnel,
    fallback_marker: &FallbackMarker,
    dns_trace: &DnsTraceRecorder,
) -> Result<ProxyTunnel, ProxyBackendError> {
    let input = runtime_gateway_input(runtime, request);
    let resolver_policy = fallback_marker.used().then_some("hns-doh-compat");
    let trace = resolution_trace_json(
        &input,
        network,
        mode,
        Some(&response.resolution),
        TlsTraceInput {
            validation: Some(&response.origin_request.tls),
            decision: Some(&response.origin.dane_decision),
            inspection: response.origin.tls_inspection.as_ref(),
            origin_address: response.origin_request.connect_host.as_deref(),
        },
        None,
        fallback_marker,
        dns_trace,
    );
    let parsed = parse_upgrade_response_head(&response.origin.response_head)?;
    let mut headers = sanitize_typed_upgrade_headers(parsed.headers)?;
    append_runtime_response_metadata(
        &mut headers,
        &response.origin.dane_decision,
        resolver_policy,
        None,
        &trace,
    );
    Ok(ProxyTunnel {
        head: ProxyResponseHead {
            status_code: parsed.status_code,
            reason_phrase: "Switching Protocols".to_owned(),
            headers: proxy_headers(headers),
        },
        // A boxed transport trait object is itself a concrete Read + Write +
        // Send value and therefore satisfies the proxy tunnel trait.
        stream: Box::new(response.origin.stream),
    })
}

fn runtime_gateway_input<'a>(
    runtime: &'a BrowserRuntime,
    request: &'a GatewayHttpRequest,
) -> GatewayHttpRequestInput<'a> {
    GatewayHttpRequestInput {
        data_dir: &runtime.inner.data_dir,
        method: &request.method,
        scheme: &request.scheme,
        host: &request.host,
        port: request.port,
        path_and_query: &request.path_and_query,
        header_text: "",
        body: &request.body,
    }
}

fn sanitize_typed_origin_headers(
    headers: Vec<(String, String)>,
) -> Result<Vec<(String, String)>, ProxyBackendError> {
    let nominated = connection_nominated_response_headers(&headers)?;
    Ok(headers
        .into_iter()
        .filter(|(name, _)| {
            !suppressed_origin_response_header(name)
                && !nominated.contains(&name.to_ascii_lowercase())
        })
        .collect())
}

fn sanitize_typed_upgrade_headers(
    headers: Vec<(String, String)>,
) -> Result<Vec<(String, String)>, ProxyBackendError> {
    let nominated = connection_nominated_response_headers(&headers)?;
    let mut headers: Vec<_> = headers
        .into_iter()
        .filter(|(name, _)| {
            !name.eq_ignore_ascii_case("upgrade")
                && !suppressed_origin_response_header(name)
                && !nominated.contains(&name.to_ascii_lowercase())
        })
        .collect();
    headers.push(("Connection".to_owned(), "Upgrade".to_owned()));
    headers.push(("Upgrade".to_owned(), "websocket".to_owned()));
    Ok(headers)
}

fn connection_nominated_response_headers(
    headers: &[(String, String)],
) -> Result<HashSet<String>, ProxyBackendError> {
    let mut nominated = HashSet::new();
    for (_, value) in headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
    {
        for token in value.split(',').map(str::trim) {
            if !is_valid_gateway_header_name(token) {
                return Err(ProxyBackendError::InvalidResponse);
            }
            nominated.insert(token.to_ascii_lowercase());
        }
    }
    Ok(nominated)
}

fn append_runtime_response_metadata(
    headers: &mut Vec<(String, String)>,
    decision: &DaneDecision,
    resolver_policy: Option<&str>,
    security_path: Option<&str>,
    trace_json: &str,
) {
    if let Some(policy) = hns_tls_policy_header(decision) {
        headers.push(("X-HNS-TLS-Policy".to_owned(), policy.to_owned()));
    }
    if let Some(policy) = resolver_policy {
        headers.push(("X-HNS-Resolver-Policy".to_owned(), policy.to_owned()));
    }
    if let Some(path) = security_path {
        headers.push((HNS_SECURITY_PATH_HEADER.to_owned(), path.to_owned()));
    }
    headers.push((
        HNS_RESOLVER_MODE_HEADER.to_owned(),
        trace_mode(trace_json).to_owned(),
    ));
    headers.push((
        HNS_DOH_FALLBACK_HEADER.to_owned(),
        trace_doh_fallback(trace_json).to_owned(),
    ));
    headers.push((
        HNS_RESOLUTION_TRACE_HEADER.to_owned(),
        trace_json.to_owned(),
    ));
}

fn proxy_headers(headers: Vec<(String, String)>) -> Vec<ProxyHeader> {
    headers
        .into_iter()
        .map(|(name, value)| ProxyHeader::new(name, value))
        .collect()
}

struct ParsedUpgradeResponseHead {
    status_code: u16,
    headers: Vec<(String, String)>,
}

fn parse_upgrade_response_head(
    bytes: &[u8],
) -> Result<ParsedUpgradeResponseHead, ProxyBackendError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_PROXY_UPGRADE_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    let parsed = response
        .parse(bytes)
        .map_err(|_error| ProxyBackendError::InvalidResponse)?;
    let httparse::Status::Complete(consumed) = parsed else {
        return Err(ProxyBackendError::InvalidResponse);
    };
    if consumed != bytes.len() || !matches!(response.version, Some(0 | 1)) {
        return Err(ProxyBackendError::InvalidResponse);
    }
    let status_code = response.code.ok_or(ProxyBackendError::InvalidResponse)?;
    if status_code != 101 {
        return Err(ProxyBackendError::InvalidResponse);
    }
    let headers = response
        .headers
        .iter()
        .map(|header| {
            let value = std::str::from_utf8(header.value)
                .map_err(|_error| ProxyBackendError::InvalidResponse)?;
            Ok((header.name.to_owned(), value.trim().to_owned()))
        })
        .collect::<Result<Vec<_>, ProxyBackendError>>()?;
    let connection_upgrade = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("connection")
            && value
                .split(',')
                .map(str::trim)
                .any(|token| token.eq_ignore_ascii_case("upgrade"))
    });
    let upgrade_values: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("upgrade"))
        .map(|(_, value)| value.as_str())
        .collect();
    if !connection_upgrade
        || upgrade_values.len() != 1
        || !upgrade_values[0].eq_ignore_ascii_case("websocket")
    {
        return Err(ProxyBackendError::InvalidResponse);
    }
    Ok(ParsedUpgradeResponseHead {
        status_code,
        headers,
    })
}

fn runtime_error_to_proxy_backend(error: RuntimeError) -> ProxyBackendError {
    match error {
        RuntimeError::InvalidConfiguration(_) => ProxyBackendError::InvalidRequest,
        RuntimeError::Operation(_) | RuntimeError::Synchronization(_) => {
            ProxyBackendError::Internal
        }
    }
}

fn is_reserved_hns_header(name: &str) -> bool {
    name.get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("X-HNS-"))
}

fn is_valid_gateway_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_valid_gateway_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte == b'\t' || (byte >= b' ' && byte != 0x7f))
}

struct ParsedGatewayHeaders {
    headers: Vec<(String, String)>,
    strict_hns_mode: bool,
    doh_endpoint: HnsDohEndpoint,
    stateless_dane_certificates: bool,
    network: NetworkKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GatewayResolutionMode {
    Strict,
    Compatibility,
}

impl GatewayResolutionMode {
    fn from_strict_hns_mode(strict_hns_mode: bool) -> Self {
        if strict_hns_mode {
            Self::Strict
        } else {
            Self::Compatibility
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Compatibility => "compatibility",
        }
    }
}

pub fn parse_network_kind(value: &str) -> Result<NetworkKind, String> {
    value
        .parse()
        .map_err(|_| format!("unsupported Handshake network: {value}"))
}

fn network_base_path(data_dir: &str, network: NetworkKind) -> PathBuf {
    match network {
        NetworkKind::Mainnet => Path::new(data_dir).join("hns"),
        NetworkKind::Testnet => Path::new(data_dir).join("hns-testnet"),
        NetworkKind::Regtest => Path::new(data_dir).join("hns-regtest"),
    }
}

fn chain_for_network(
    store: SqliteHeaderStore,
    network: NetworkKind,
) -> HeaderChain<SqliteHeaderStore> {
    match network {
        NetworkKind::Mainnet => HeaderChain::new(store),
        NetworkKind::Testnet | NetworkKind::Regtest => {
            HeaderChain::with_difficulty_policy(store, DifficultyPolicy::Permissive)
        }
    }
}

fn seed_peers_for_network(
    peers: &mut hns_p2p::PeerManager,
    network: &hns_core::network::Network,
    network_kind: NetworkKind,
) -> Result<usize, hns_p2p::P2pError> {
    if !network.dns_seeds.is_empty() {
        let source = DnsSeedPeerSource::from_network(network);
        let discovered = source.discover()?;
        return Ok(peers.seed(
            discovered
                .into_iter()
                .filter(|address| is_allowed_peer_endpoint(network, *address)),
        ));
    }

    if network_kind == NetworkKind::Regtest {
        let source = StaticPeerSource::new([
            SocketAddr::from((Ipv4Addr::LOCALHOST, network.port)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, network.port)),
        ]);
        let discovered = source.discover()?;
        return Ok(peers.seed(
            discovered
                .into_iter()
                .filter(|address| is_allowed_peer_endpoint(network, *address)),
        ));
    }

    Ok(0)
}

fn retain_allowed_peer_endpoints(
    peers: &mut hns_p2p::PeerManager,
    network: &hns_core::network::Network,
) -> usize {
    peers.retain(|peer| is_allowed_peer_endpoint(network, peer.address))
}

fn allowed_peer_count(peers: &hns_p2p::PeerManager, network: &hns_core::network::Network) -> usize {
    peers
        .iter()
        .filter(|peer| is_allowed_peer_endpoint(network, peer.address))
        .count()
}

fn sync_checkpoints_for_network(network: NetworkKind) -> Vec<hns_chain::HeaderCheckpoint> {
    match network {
        NetworkKind::Mainnet => mainnet_sync_checkpoints(),
        NetworkKind::Testnet | NetworkKind::Regtest => Vec::new(),
    }
}

fn estimated_tip_height_for_network(network: NetworkKind, now: u64) -> Option<u32> {
    match network {
        NetworkKind::Mainnet => estimated_mainnet_tip_height(now),
        NetworkKind::Testnet | NetworkKind::Regtest => None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HnsDohEndpoint {
    host: String,
    port: u16,
    path_and_query: String,
}

impl Default for HnsDohEndpoint {
    fn default() -> Self {
        Self {
            host: HNS_DOH_HOST.to_owned(),
            port: 443,
            path_and_query: HNS_DOH_PATH.to_owned(),
        }
    }
}

impl HnsDohEndpoint {
    fn parse(input: &str) -> Result<Self, &'static str> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(Self::default());
        }
        let rest = trimmed
            .get(..8)
            .filter(|scheme| scheme.eq_ignore_ascii_case("https://"))
            .and_then(|_| trimmed.get(8..))
            .ok_or("DoH resolver must be an HTTPS URL")?;
        let (authority, path) = rest
            .split_once('/')
            .unwrap_or((rest, HNS_DOH_PATH.trim_start_matches('/')));
        if authority.is_empty()
            || authority.contains('@')
            || authority.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err("DoH resolver authority is invalid");
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => {
                let port = port
                    .parse::<u16>()
                    .map_err(|_| "DoH resolver port is invalid")?;
                (host, port)
            }
            Some(_) if authority.contains(':') => {
                return Err("DoH resolver IPv6 literals are not supported");
            }
            _ => (authority, 443),
        };
        if !valid_doh_host(host) {
            return Err("DoH resolver host is invalid");
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let path_and_query = format!("/{path}");
        if path_and_query.contains('#')
            || path_and_query
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ')
        {
            return Err("DoH resolver path is invalid");
        }
        Ok(Self {
            host,
            port,
            path_and_query,
        })
    }

    fn display(&self) -> String {
        if self.port == 443 {
            format!("https://{}{}", self.host, self.path_and_query)
        } else {
            format!("https://{}:{}{}", self.host, self.port, self.path_and_query)
        }
    }
}

fn valid_doh_host(host: &str) -> bool {
    let trimmed = host.trim_end_matches('.');
    !trimmed.is_empty()
        && trimmed.len() <= 253
        && trimmed.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

struct GatewayProofProvider {
    base: PathBuf,
    values: SqliteResourceValueProvider,
    network: NetworkKind,
    preferred_peers: usize,
    timeout: Duration,
    seed_on_empty: bool,
    peer_state: Option<Arc<Mutex<()>>>,
}

impl GatewayProofProvider {
    fn new(base: PathBuf, values: SqliteResourceValueProvider, network: NetworkKind) -> Self {
        Self {
            base,
            values,
            network,
            preferred_peers: DEFAULT_GATEWAY_PROOF_PEERS,
            timeout: DEFAULT_GATEWAY_PROOF_TIMEOUT,
            seed_on_empty: true,
            peer_state: None,
        }
    }

    fn with_peer_state(mut self, peer_state: Option<Arc<Mutex<()>>>) -> Self {
        self.peer_state = peer_state;
        self
    }

    fn cached_records(
        &self,
        root_name: &str,
        name_hash: NameHash,
    ) -> Result<ProvenNameRecords, ResolverError> {
        let verified = self.values.prove_resource_value(root_name, name_hash)?;
        if verified.root_name != root_name || verified.name_hash != name_hash || !verified.secure {
            return Err(ResolverError::ProofNameMismatch);
        }
        let is_non_inclusion = verified.value.is_none();
        if !self.anchor_is_current_tip_canonical(verified.anchor)? {
            return Err(ResolverError::ProofUnavailable);
        }
        if is_non_inclusion
            && local_chain_is_stale_for_current_resolution(&self.base, self.network)?
        {
            return Err(ResolverError::LocalChainNotCurrent);
        }
        ProvenNameRecords::from_verified_resource_value(verified)
    }

    fn anchor_is_current_tip_canonical(
        &self,
        anchor: Option<ResourceValueAnchor>,
    ) -> Result<bool, ResolverError> {
        let Some(anchor) = anchor else {
            return Ok(false);
        };
        let header_store = SqliteHeaderStore::open(self.base.join("headers.sqlite"))
            .map_err(|error| ResolverError::Storage(format!("open header store: {error}")))?;
        let chain = chain_for_network(header_store, self.network);
        let best = chain
            .best_header()
            .map_err(|error| ResolverError::Storage(format!("read best header: {error}")))?;
        let Some(best) = best else {
            return Ok(false);
        };
        Ok(anchor.height == best.height && anchor.tree_root == best.header.tree_root)
    }

    fn fetch_and_store_live_proof(
        &self,
        root_name: &str,
        name_hash: NameHash,
    ) -> Result<(), ResolverError> {
        let _peer_state = match self.peer_state.as_ref() {
            Some(peer_state) => Some(
                peer_state
                    .lock()
                    .map_err(|_| ResolverError::CachePoisoned)?,
            ),
            None => None,
        };
        let best = best_synced_header(&self.base, self.network)?;
        let network = self.network.network();
        let peer_store = SqlitePeerStore::open(self.base.join("peers.sqlite"))
            .map_err(|error| ResolverError::Storage(format!("open peer store: {error}")))?;
        let mut peers = peer_store
            .load_manager()
            .map_err(|error| ResolverError::Storage(format!("load peer store: {error}")))?;
        retain_allowed_peer_endpoints(&mut peers, &network);
        if self.seed_on_empty && allowed_peer_count(&peers, &network) == 0 {
            let _ = seed_peers_for_network(&mut peers, &network, self.network);
        }

        let now = now_unix_seconds();
        let selected =
            select_live_proof_peers(&peers, &network, self.preferred_peers, now, best.height);
        if selected.is_empty() {
            peer_store
                .save_manager(&peers)
                .map_err(|error| ResolverError::Storage(format!("save peer store: {error}")))?;
            return Err(ResolverError::ProofUnavailable);
        }

        for address in selected {
            match self.fetch_from_peer(
                address,
                root_name,
                name_hash,
                best.header.tree_root,
                best.height,
            ) {
                Ok(remote_height) => {
                    peers.record_success(address, remote_height, now);
                    peer_store.save_manager(&peers).map_err(|error| {
                        ResolverError::Storage(format!("save peer store: {error}"))
                    })?;
                    return Ok(());
                }
                Err(_) => {
                    peers.record_transient_failure(address);
                }
            }
        }

        peer_store
            .save_manager(&peers)
            .map_err(|error| ResolverError::Storage(format!("save peer store: {error}")))?;
        Err(ResolverError::ProofUnavailable)
    }

    fn fetch_from_peer(
        &self,
        address: SocketAddr,
        root_name: &str,
        name_hash: NameHash,
        proof_root: hns_core::Hash,
        proof_height: Height,
    ) -> Result<Height, SyncError> {
        let network = self.network.network();
        let mut peer = PeerConnection::connect(address, network, self.timeout)?;
        let mut session = HeaderSyncSession::new(VersionPacket::default());
        let remote = peer.handshake(&mut session)?;
        if remote.height < proof_height {
            return Err(SyncError::UnexpectedAction);
        }
        let mut scheduler = ProofScheduler::new(UrkelProofVerifier, &self.values);
        scheduler.request_hash_and_store_at_height(
            &mut peer,
            &mut session,
            root_name,
            proof_root,
            name_hash,
            proof_height,
        )?;
        Ok(remote.height)
    }
}

impl HnsProofProvider for GatewayProofProvider {
    fn prove_name(
        &self,
        root_name: &str,
        name_hash: NameHash,
    ) -> Result<ProvenNameRecords, ResolverError> {
        match self.cached_records(root_name, name_hash) {
            Ok(records) => Ok(records),
            Err(ResolverError::ProofUnavailable) => {
                self.fetch_and_store_live_proof(root_name, name_hash)?;
                self.cached_records(root_name, name_hash)
            }
            Err(error) => Err(error),
        }
    }
}

type AndroidPrimaryResolver = DelegatingResolver<
    GatewayProofProvider,
    AuthoritativeDnssecResolver<AndroidAuthoritativeDnsTransport, SystemDnssecVerifier>,
>;
type AndroidDirectDelegatedResolver =
    AuthoritativeDnssecResolver<AndroidAuthoritativeDnsTransport, SystemDnssecVerifier>;
type AndroidDohDelegatedResolver =
    AuthoritativeDnssecResolver<HnsDohDnsTransport, SystemDnssecVerifier>;
type AndroidCompatibilityPrimaryResolver = DelegatingResolver<
    GatewayProofProvider,
    FallbackDelegatedResolver<AndroidDirectDelegatedResolver, AndroidDohDelegatedResolver>,
>;
type AndroidStrictGatewayResolver = CompositeResolver<AndroidPrimaryResolver, IcannDohResolver>;
type AndroidCompatibilityGatewayResolver = CompositeResolver<
    FallbackResolver<AndroidCompatibilityPrimaryResolver, HnsDohResolver>,
    IcannDohResolver,
>;

enum AndroidGatewayResolver {
    Strict(Box<AndroidStrictGatewayResolver>),
    Compatibility(Box<AndroidCompatibilityGatewayResolver>),
}

#[derive(Clone, Debug, Default)]
struct DnsTraceRecorder {
    events: Arc<Mutex<Vec<DnsTraceEvent>>>,
}

impl DnsTraceRecorder {
    fn push(&self, event: DnsTraceEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }

    fn snapshot(&self) -> Vec<DnsTraceEvent> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DnsTraceEvent {
    protocol: &'static str,
    server: String,
    question_name: Option<String>,
    question_type: Option<u16>,
    status: String,
    elapsed_ms: u64,
    error: Option<String>,
}

#[derive(Clone)]
struct AndroidAuthoritativeDnsTransport {
    direct: UdpTcpDnsTransport,
    doh_http: Arc<TcpHttpTransport>,
    trace: DnsTraceRecorder,
    interception_probe: Arc<Mutex<Option<DnsInterceptionStatus>>>,
}

impl AndroidAuthoritativeDnsTransport {
    fn new(direct: UdpTcpDnsTransport, trace: DnsTraceRecorder, http: TcpHttpTransport) -> Self {
        Self {
            direct,
            doh_http: Arc::new(http),
            trace,
            interception_probe: Arc::new(Mutex::new(None)),
        }
    }
}

impl DnsTransport for AndroidAuthoritativeDnsTransport {
    fn endpoint_policy(&self) -> DnsEndpointPolicy {
        self.direct.endpoint_policy
    }

    fn exchange_udp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
        let started = Instant::now();
        let result = self.direct.exchange_udp(server, query);
        self.trace.push(dns_trace_event(
            "udp53",
            server.to_string(),
            query,
            elapsed_millis(started),
            &result,
        ));
        result
    }

    fn exchange_tcp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
        let started = Instant::now();
        let result = self.direct.exchange_tcp(server, query);
        self.trace.push(dns_trace_event(
            "tcp53",
            server.to_string(),
            query,
            elapsed_millis(started),
            &result,
        ));
        result
    }

    fn exchange_doh(
        &self,
        endpoint: &AuthoritativeDohEndpoint,
        query: &[u8],
    ) -> Result<Vec<u8>, ResolverError> {
        let started = Instant::now();
        let response = fetch_authoritative_doh_message(&self.doh_http, endpoint, query.to_vec());
        self.trace.push(doh_trace_event(
            "authoritative_doh",
            authoritative_doh_endpoint_display(endpoint),
            query,
            elapsed_millis(started),
            &response,
        ));
        let response = response.map_err(|error| {
            ResolverError::DnsTransport(format!("authoritative DoH transport failed: {error}"))
        })?;
        if !doh_http_status_success(response.status) {
            return Err(ResolverError::DnsTransport(format!(
                "authoritative DoH returned HTTP {}",
                response.status
            )));
        }
        if !doh_response_has_dns_message_content_type(&response) {
            return Err(ResolverError::InvalidDnsResponse);
        }
        Ok(response.body)
    }

    fn probe_dns_interception(&self) -> DnsInterceptionStatus {
        if let Ok(probe) = self.interception_probe.lock()
            && let Some(status) = *probe
        {
            return status;
        }

        let started = Instant::now();
        let (status, error) = run_dns_interception_probe(DNS_INTERCEPTION_PROBE_TIMEOUT);
        self.trace.push(DnsTraceEvent {
            protocol: "dns_interception_probe",
            server: "192.0.2.1:53".to_owned(),
            question_name: Some(DNS_INTERCEPTION_PROBE_NAME.to_owned()),
            question_type: Some(RecordType::A.code()),
            status: dns_interception_status_name(status).to_owned(),
            elapsed_ms: elapsed_millis(started),
            error,
        });
        if let Ok(mut probe) = self.interception_probe.lock() {
            *probe = Some(status);
        }
        status
    }
}

fn run_dns_interception_probe(timeout: Duration) -> (DnsInterceptionStatus, Option<String>) {
    let qname = match DnsName::from_ascii(DNS_INTERCEPTION_PROBE_NAME) {
        Ok(name) => name,
        Err(_) => {
            return (
                DnsInterceptionStatus::Inconclusive,
                Some("probe name is invalid".to_owned()),
            );
        }
    };
    let query = match build_doh_query(DNS_INTERCEPTION_PROBE_ID, &qname, RecordType::A) {
        Ok(query) => query,
        Err(error) => return (DnsInterceptionStatus::Inconclusive, Some(error.to_string())),
    };
    let server = SocketAddr::from(([192, 0, 2, 1], 53));
    let socket = match UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))) {
        Ok(socket) => socket,
        Err(error) => return (DnsInterceptionStatus::Inconclusive, Some(error.to_string())),
    };
    if let Err(error) = socket.set_read_timeout(Some(timeout)) {
        return (DnsInterceptionStatus::Inconclusive, Some(error.to_string()));
    }
    if let Err(error) = socket.send_to(&query, server) {
        return (DnsInterceptionStatus::Inconclusive, Some(error.to_string()));
    }

    let mut response = vec![0u8; DEFAULT_DNS_UDP_PAYLOAD];
    let (length, source) = match socket.recv_from(&mut response) {
        Ok(received) => received,
        Err(error) if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
            return (DnsInterceptionStatus::NotDetected, None);
        }
        Err(error) => return (DnsInterceptionStatus::Inconclusive, Some(error.to_string())),
    };
    response.truncate(length);
    let parsed = DnsMessage::parse(&response);
    if source == server
        && parsed.as_ref().is_ok_and(|message| {
            message.header.id == DNS_INTERCEPTION_PROBE_ID
                && message.header.flags.is_response()
                && message.questions.len() == 1
                && message.questions[0].name == qname
                && message.questions[0].record_type == RecordType::A
                && message.questions[0].class == DNS_CLASS_IN
        })
    {
        return (
            DnsInterceptionStatus::Detected,
            Some(
                "received a matching DNS reply from a non-routable TEST-NET destination".to_owned(),
            ),
        );
    }

    (
        DnsInterceptionStatus::Inconclusive,
        Some("probe received an unrelated or malformed reply".to_owned()),
    )
}

fn dns_interception_status_name(status: DnsInterceptionStatus) -> &'static str {
    match status {
        DnsInterceptionStatus::NotTested => "not_tested",
        DnsInterceptionStatus::NotDetected => "not_detected",
        DnsInterceptionStatus::Detected => "detected",
        DnsInterceptionStatus::Inconclusive => "inconclusive",
    }
}

fn dns_trace_event(
    protocol: &'static str,
    server: String,
    query: &[u8],
    elapsed_ms: u64,
    result: &Result<Vec<u8>, ResolverError>,
) -> DnsTraceEvent {
    let (question_name, question_type) = dns_trace_question(query);
    match result {
        Ok(_) => DnsTraceEvent {
            protocol,
            server,
            question_name,
            question_type,
            status: "ok".to_owned(),
            elapsed_ms,
            error: None,
        },
        Err(error) => DnsTraceEvent {
            protocol,
            server,
            question_name,
            question_type,
            status: dns_trace_error_status(error).to_owned(),
            elapsed_ms,
            error: Some(error.to_string()),
        },
    }
}

fn doh_trace_event(
    protocol: &'static str,
    server: String,
    query: &[u8],
    elapsed_ms: u64,
    result: &Result<OriginResponse, TransportError>,
) -> DnsTraceEvent {
    let (question_name, question_type) = dns_trace_question(query);
    match result {
        Ok(response) if doh_response_matches_query(response, query) => DnsTraceEvent {
            protocol,
            server,
            question_name,
            question_type,
            status: "ok".to_owned(),
            elapsed_ms,
            error: None,
        },
        Ok(response) if !doh_http_status_success(response.status) => DnsTraceEvent {
            protocol,
            server,
            question_name,
            question_type,
            status: "http_error".to_owned(),
            elapsed_ms,
            error: Some(format!("HTTP {}", response.status)),
        },
        Ok(_) => DnsTraceEvent {
            protocol,
            server,
            question_name,
            question_type,
            status: "invalid_response".to_owned(),
            elapsed_ms,
            error: Some("DoH response did not match the DNS question".to_owned()),
        },
        Err(error) => DnsTraceEvent {
            protocol,
            server,
            question_name,
            question_type,
            status: "transport_error".to_owned(),
            elapsed_ms,
            error: Some(error.to_string()),
        },
    }
}

fn doh_response_matches_query(response: &OriginResponse, query: &[u8]) -> bool {
    if !doh_http_status_success(response.status)
        || !doh_response_has_dns_message_content_type(response)
    {
        return false;
    }
    let (Ok(query), Ok(answer)) = (DnsMessage::parse(query), DnsMessage::parse(&response.body))
    else {
        return false;
    };
    let ([question], [answered_question]) =
        (query.questions.as_slice(), answer.questions.as_slice())
    else {
        return false;
    };
    answer.header.flags.is_response()
        && answer.header.flags.opcode() == 0
        && matches!(
            answer.header.flags.rcode(),
            DNS_RCODE_NOERROR | DNS_RCODE_NXDOMAIN
        )
        && answer.header.id == query.header.id
        && answered_question.name == question.name
        && answered_question.record_type == question.record_type
        && answered_question.class == question.class
}

fn dns_trace_question(query: &[u8]) -> (Option<String>, Option<u16>) {
    let Ok(message) = DnsMessage::parse(query) else {
        return (None, None);
    };
    let Some(question) = message.questions.first() else {
        return (None, None);
    };
    (
        Some(question.name.to_string()),
        Some(question.record_type.code()),
    )
}

fn elapsed_millis(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u64::MAX as u128) as u64
}

fn dns_trace_error_status(error: &ResolverError) -> &'static str {
    match error {
        ResolverError::DnsTransport(message)
            if message.contains("timed out")
                || message.contains("timeout")
                || message.contains("deadline") =>
        {
            "timeout"
        }
        ResolverError::DnsTransport(_) => "transport_error",
        ResolverError::DnsResponseCode(_) => "response_code",
        ResolverError::InvalidDnsResponse => "invalid_response",
        ResolverError::DnssecFailed => "dnssec_failed",
        _ => "error",
    }
}

impl Resolver for AndroidGatewayResolver {
    fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
        match self {
            Self::Strict(resolver) => resolver.resolve(request),
            Self::Compatibility(resolver) => resolver.resolve(request),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct FallbackMarker {
    used: Arc<AtomicBool>,
    reason: Arc<Mutex<Option<&'static str>>>,
}

impl FallbackMarker {
    fn mark(&self, reason: &'static str) {
        self.used.store(true, Ordering::Relaxed);
        if let Ok(mut fallback_reason) = self.reason.lock()
            && fallback_reason.is_none()
        {
            *fallback_reason = Some(reason);
        }
    }

    fn used(&self) -> bool {
        self.used.load(Ordering::Relaxed)
    }

    fn reason(&self) -> Option<&'static str> {
        self.reason.lock().ok().and_then(|reason| *reason)
    }
}

struct FallbackResolver<P, F> {
    primary: P,
    fallback: F,
    fallback_marker: FallbackMarker,
    fallback_roots: Arc<Mutex<HashMap<String, &'static str>>>,
}

impl<P, F> FallbackResolver<P, F> {
    fn with_marker(primary: P, fallback: F, fallback_marker: FallbackMarker) -> Self {
        Self {
            primary,
            fallback,
            fallback_marker,
            fallback_roots: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn cached_fallback_reason(&self, request: &ResolutionRequest) -> Option<&'static str> {
        let root = fallback_cache_root(request);
        self.fallback_roots
            .lock()
            .ok()
            .and_then(|roots| roots.get(&root).copied())
    }

    fn remember_fallback_reason(&self, request: &ResolutionRequest, reason: &'static str) {
        let root = fallback_cache_root(request);
        if let Ok(mut roots) = self.fallback_roots.lock() {
            roots.entry(root).or_insert(reason);
        }
    }
}

impl<P, F> Resolver for FallbackResolver<P, F>
where
    P: Resolver,
    F: Resolver,
{
    fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
        if let Some(reason) = self.cached_fallback_reason(request) {
            self.fallback_marker.mark(reason);
            return self.fallback.resolve(request);
        }

        match self.primary.resolve(request) {
            Ok(answer) => Ok(answer),
            Err(error) => {
                let Some(reason) = doh_fallback_reason(&error) else {
                    return Err(error);
                };
                self.remember_fallback_reason(request, reason);
                self.fallback_marker.mark(reason);
                self.fallback.resolve(request)
            }
        }
    }
}

fn fallback_cache_root(request: &ResolutionRequest) -> String {
    hns_trace_root(&request.qname).to_ascii_lowercase()
}

#[derive(Clone, Debug)]
struct FallbackDelegatedResolver<P, F> {
    primary: P,
    fallback: F,
    fallback_marker: FallbackMarker,
    fallback_roots: Arc<Mutex<HashMap<String, &'static str>>>,
}

impl<P, F> FallbackDelegatedResolver<P, F> {
    fn new(primary: P, fallback: F, fallback_marker: FallbackMarker) -> Self {
        Self {
            primary,
            fallback,
            fallback_marker,
            fallback_roots: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn cached_fallback_reason(&self, request: &ResolutionRequest) -> Option<&'static str> {
        let root = fallback_cache_root(request);
        self.fallback_roots
            .lock()
            .ok()
            .and_then(|roots| roots.get(&root).copied())
    }

    fn remember_fallback_reason(&self, request: &ResolutionRequest, reason: &'static str) {
        let root = fallback_cache_root(request);
        if let Ok(mut roots) = self.fallback_roots.lock() {
            roots.entry(root).or_insert(reason);
        }
    }
}

impl<P, F> DelegatedResolver for FallbackDelegatedResolver<P, F>
where
    P: DelegatedResolver,
    F: DelegatedResolver,
{
    fn resolve_delegated(
        &self,
        request: &ResolutionRequest,
        delegation: &HnsDelegation,
    ) -> Result<ResolutionAnswer, ResolverError> {
        if let Some(reason) = self.cached_fallback_reason(request) {
            self.fallback_marker.mark(reason);
            return self.fallback.resolve_delegated(request, delegation);
        }

        match self.primary.resolve_delegated(request, delegation) {
            Ok(answer) => Ok(answer),
            Err(error) => {
                let Some(reason) = delegated_doh_transport_fallback_reason(&error) else {
                    return Err(error);
                };
                self.remember_fallback_reason(request, reason);
                self.fallback_marker.mark(reason);
                self.fallback.resolve_delegated(request, delegation)
            }
        }
    }
}

#[derive(Clone, Debug)]
struct HnsDohDnsTransport {
    endpoint: HnsDohEndpoint,
    trace: DnsTraceRecorder,
    endpoint_policy: DnsEndpointPolicy,
    http: TcpHttpTransport,
}

impl HnsDohDnsTransport {
    fn new(
        endpoint: HnsDohEndpoint,
        trace: DnsTraceRecorder,
        endpoint_policy: DnsEndpointPolicy,
        http: TcpHttpTransport,
    ) -> Self {
        Self {
            endpoint,
            trace,
            endpoint_policy,
            http,
        }
    }

    fn exchange_doh(&self, _server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
        let (query, original_id) = recursive_doh_query(query)?;
        let started = Instant::now();
        let response = fetch_doh_message(&self.http, &self.endpoint, query.clone());
        self.trace.push(doh_trace_event(
            "hns_doh",
            self.endpoint.display(),
            &query,
            elapsed_millis(started),
            &response,
        ));
        let response = response.map_err(|error| {
            ResolverError::DnsTransport(format!("HNS DoH DNS transport failed: {error}"))
        })?;
        if !doh_http_status_success(response.status) {
            return Err(ResolverError::DnsTransport(format!(
                "HNS DoH DNS transport returned HTTP {}",
                response.status
            )));
        }
        if !doh_response_has_dns_message_content_type(&response) {
            return Err(ResolverError::InvalidDnsResponse);
        }
        restore_doh_response_id(&response.body, original_id)
    }
}

impl DnsTransport for HnsDohDnsTransport {
    fn endpoint_policy(&self) -> DnsEndpointPolicy {
        self.endpoint_policy
    }

    fn exchange_udp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
        self.exchange_doh(server, query)
    }

    fn exchange_tcp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
        self.exchange_doh(server, query)
    }
}

#[derive(Clone, Debug)]
struct HnsDohResolver {
    endpoint: HnsDohEndpoint,
    trace: DnsTraceRecorder,
    http: TcpHttpTransport,
}

impl Default for HnsDohResolver {
    fn default() -> Self {
        Self::new(
            HnsDohEndpoint::default(),
            DnsTraceRecorder::default(),
            shared_http_transport(),
        )
    }
}

impl HnsDohResolver {
    fn new(endpoint: HnsDohEndpoint, trace: DnsTraceRecorder, http: TcpHttpTransport) -> Self {
        Self {
            endpoint,
            trace,
            http,
        }
    }
}

impl Resolver for HnsDohResolver {
    fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
        let qname =
            DnsName::from_ascii(&request.qname).map_err(|_| ResolverError::UnsupportedBackend)?;
        let qtype = RecordType::from_code(request.qtype);
        let id = DOH_DNS_ID;
        let query = build_doh_query(id, &qname, qtype)?;
        let started = Instant::now();
        let response = fetch_doh_message(&self.http, &self.endpoint, query.clone());
        self.trace.push(doh_trace_event(
            "hns_doh",
            self.endpoint.display(),
            &query,
            elapsed_millis(started),
            &response,
        ));
        let response = response.map_err(|error| {
            ResolverError::DnsTransport(format!("HNS DoH compatibility resolver failed: {error}"))
        })?;
        if !doh_http_status_success(response.status) {
            return Err(ResolverError::DnsTransport(format!(
                "HNS DoH compatibility resolver returned HTTP {}",
                response.status
            )));
        }
        if !doh_response_has_dns_message_content_type(&response) {
            return Err(ResolverError::InvalidDnsResponse);
        }

        doh_answer_from_body(id, &qname, qtype, &response.body)
    }
}

#[derive(Clone, Debug)]
struct IcannDohResolver {
    endpoint: HnsDohEndpoint,
    trace: DnsTraceRecorder,
    http: TcpHttpTransport,
}

impl IcannDohResolver {
    fn new(trace: DnsTraceRecorder, http: TcpHttpTransport) -> Self {
        Self {
            endpoint: default_icann_doh_endpoint(),
            trace,
            http,
        }
    }
}

impl Resolver for IcannDohResolver {
    fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
        let qname =
            DnsName::from_ascii(&request.qname).map_err(|_| ResolverError::UnsupportedBackend)?;
        let qtype = RecordType::from_code(request.qtype);
        let id = DOH_DNS_ID;
        let query = build_doh_query(id, &qname, qtype)?;
        let started = Instant::now();
        let response = fetch_doh_message(&self.http, &self.endpoint, query.clone());
        self.trace.push(doh_trace_event(
            "icann_doh",
            self.endpoint.display(),
            &query,
            elapsed_millis(started),
            &response,
        ));
        let response = response.map_err(|error| {
            ResolverError::DnsTransport(format!("ICANN DoH resolver failed: {error}"))
        })?;
        if !doh_http_status_success(response.status) {
            return Err(ResolverError::DnsTransport(format!(
                "ICANN DoH resolver returned HTTP {}",
                response.status
            )));
        }
        if !doh_response_has_dns_message_content_type(&response) {
            return Err(ResolverError::InvalidDnsResponse);
        }

        doh_answer_from_body(id, &qname, qtype, &response.body)
    }
}

fn default_icann_doh_endpoint() -> HnsDohEndpoint {
    HnsDohEndpoint {
        host: ICANN_DOH_HOST.to_owned(),
        port: 443,
        path_and_query: ICANN_DOH_PATH.to_owned(),
    }
}

fn doh_fallback_reason(error: &ResolverError) -> Option<&'static str> {
    match error {
        ResolverError::ProofUnavailable => Some("local_hns_proof_unavailable"),
        ResolverError::LocalChainNotCurrent => Some("local_chain_not_current"),
        ResolverError::NoNameserverAddress => Some("no_verified_nameserver_address"),
        _ => None,
    }
}

fn delegated_doh_transport_fallback_reason(error: &ResolverError) -> Option<&'static str> {
    match error {
        ResolverError::DnsTransport(_) => Some("authoritative_nameserver_transport_failed"),
        ResolverError::DnsResponseCode(_) => Some("authoritative_nameserver_response_code"),
        ResolverError::InvalidDnsResponse => Some("authoritative_nameserver_invalid_response"),
        ResolverError::DnssecFailed => Some("delegated_dnssec_validation_failed"),
        _ => None,
    }
}

fn fetch_doh_message(
    http: &TcpHttpTransport,
    endpoint: &HnsDohEndpoint,
    body: Vec<u8>,
) -> Result<OriginResponse, TransportError> {
    http.fetch(&OriginRequest {
        method: "POST".to_owned(),
        scheme: "https".to_owned(),
        host: endpoint.host.clone(),
        connect_host: None,
        port: endpoint.port,
        path_and_query: endpoint.path_and_query.clone(),
        protocol: OriginProtocol::Http11,
        tls: TlsValidation::default(),
        headers: vec![
            ("Accept".to_owned(), "application/dns-message".to_owned()),
            (
                "Content-Type".to_owned(),
                "application/dns-message".to_owned(),
            ),
        ],
        body,
    })
}

fn fetch_authoritative_doh_message(
    http: &TcpHttpTransport,
    endpoint: &AuthoritativeDohEndpoint,
    body: Vec<u8>,
) -> Result<OriginResponse, TransportError> {
    http.fetch(&OriginRequest {
        method: "POST".to_owned(),
        scheme: "https".to_owned(),
        host: endpoint.host.clone(),
        connect_host: Some(endpoint.connect_addr.to_string()),
        port: endpoint.port,
        path_and_query: endpoint.path_and_query.clone(),
        protocol: OriginProtocol::Http2,
        tls: authoritative_doh_tls_validation(endpoint),
        headers: vec![
            ("Accept".to_owned(), "application/dns-message".to_owned()),
            (
                "Content-Type".to_owned(),
                "application/dns-message".to_owned(),
            ),
        ],
        body,
    })
}

fn authoritative_doh_tls_validation(endpoint: &AuthoritativeDohEndpoint) -> TlsValidation {
    match &endpoint.tls_authentication {
        AuthoritativeDohTlsAuthentication::WebPki => TlsValidation::default(),
        AuthoritativeDohTlsAuthentication::HnsProofTlsa(records) => {
            let mut validation = TlsValidation::hns_strict(true, records.clone());
            validation.tlsa_source = Some(TlsaRecordSource::HnsProofTxt);
            validation.service_port = endpoint.port;
            validation
        }
    }
}

fn authoritative_doh_endpoint_display(endpoint: &AuthoritativeDohEndpoint) -> String {
    let base = if endpoint.port == 443 {
        format!("https://{}{}", endpoint.host, endpoint.path_and_query)
    } else {
        format!(
            "https://{}:{}{}",
            endpoint.host, endpoint.port, endpoint.path_and_query
        )
    };
    let authentication = match &endpoint.tls_authentication {
        AuthoritativeDohTlsAuthentication::WebPki => "WebPKI",
        AuthoritativeDohTlsAuthentication::HnsProofTlsa(_) => "HNS-proof TLSA",
    };
    format!("{base} via {} [{authentication}]", endpoint.connect_addr)
}

fn doh_http_status_success(status: u16) -> bool {
    (200..300).contains(&status)
}

fn doh_response_has_dns_message_content_type(response: &OriginResponse) -> bool {
    response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .any(|(_, value)| {
            value
                .split(';')
                .next()
                .map(str::trim)
                .is_some_and(|media_type| {
                    media_type.eq_ignore_ascii_case("application/dns-message")
                })
        })
}

fn recursive_doh_query(query: &[u8]) -> Result<(Vec<u8>, u16), ResolverError> {
    if query.len() < 4 {
        return Err(ResolverError::InvalidDnsResponse);
    }
    let original_id = u16::from_be_bytes([query[0], query[1]]);
    let mut query = query.to_vec();
    query[0] = 0;
    query[1] = 0;
    query[2] |= 0x01;
    Ok((query, original_id))
}

fn restore_doh_response_id(body: &[u8], original_id: u16) -> Result<Vec<u8>, ResolverError> {
    if body.len() < 2 || body[0] != 0 || body[1] != 0 {
        return Err(ResolverError::InvalidDnsResponse);
    }
    let mut body = body.to_vec();
    body[..2].copy_from_slice(&original_id.to_be_bytes());
    Ok(body)
}

fn build_doh_query(id: u16, qname: &DnsName, qtype: RecordType) -> Result<Vec<u8>, ResolverError> {
    let message = DnsMessage {
        header: DnsHeader {
            id,
            flags: DnsFlags::new(DNS_RECURSION_DESIRED_FLAG | DNS_AUTHENTIC_DATA_FLAG),
            question_count: 1,
            answer_count: 0,
            authority_count: 0,
            additional_count: 1,
        },
        questions: vec![DnsQuestion {
            name: qname.clone(),
            record_type: qtype,
            class: DNS_CLASS_IN,
        }],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: vec![ResourceRecord {
            name: DnsName::root(),
            record_type: RecordType::Unknown(DNS_OPT_RECORD_TYPE),
            class: DEFAULT_DNS_UDP_PAYLOAD as u16,
            ttl: DNSSEC_DO_FLAG,
            rdata: Vec::new(),
        }],
    };

    message
        .encode(&DnsEncodeConfig {
            max_message_len: DEFAULT_DNS_UDP_PAYLOAD,
        })
        .map_err(|_| ResolverError::InvalidDnsResponse)
}

fn doh_answer_from_body(
    id: u16,
    qname: &DnsName,
    qtype: RecordType,
    body: &[u8],
) -> Result<ResolutionAnswer, ResolverError> {
    let message = DnsMessage::parse(body).map_err(|_| ResolverError::InvalidDnsResponse)?;
    let rcode = message.header.flags.rcode();
    if message.header.id != id
        || !message.header.flags.is_response()
        || message.header.flags.opcode() != 0
        || message.questions.len() != 1
        || message.questions[0].name != *qname
        || message.questions[0].record_type != qtype
        || message.questions[0].class != DNS_CLASS_IN
    {
        return Err(ResolverError::InvalidDnsResponse);
    }
    if !matches!(rcode, DNS_RCODE_NOERROR | DNS_RCODE_NXDOMAIN) {
        return Err(ResolverError::DnsResponseCode(rcode));
    }

    Ok(ResolutionAnswer {
        name: qname.clone(),
        records: message.answers,
        secure: message.header.flags.bits() & 0x0020 != 0,
    })
}

pub fn core_version() -> &'static str {
    concat!("hns-dane-browser-rust-core/", env!("CARGO_PKG_VERSION"))
}

pub fn diagnostics_json() -> String {
    r#"{"core":"hns-dane-browser-rust-core","version":"__VERSION__","features":["header-hash","header-pow-validation","header-mainnet-difficulty-retarget","header-mainnet-checkpoints","header-canonical-height-index","hns-name-hash","hns-dotted-root-label","urkel-proof-verification","urkel-proof-value-handoff","hns-name-state-resource-extraction","hns-resource-decoder","hns-authoritative-doh-rfc8484","hns-resource-provider-adapter","hns-memory-resource-provider","hns-sqlite-resource-provider","hns-negative-cache","hns-ttl-cache-lru","hns-resource-cache-stats","hns-resource-cache-eviction","hns-resource-cache-cap-enforcement","hns-resource-cache-chain-anchors","hns-resource-cache-reorg-invalidation","hns-resource-cache-current-tip","hns-proof-backed-resolver-boundary","hns-delegating-resolver-boundary","hns-proof-backed-ns-address-hydration","hns-authoritative-dnssec-delegated-resolver","android-hns-doh-compat-resolver","dns-wire","dns-svcb-https","dnssec-ds-dnskey-link","dnssec-ds-sha1","dnssec-ds-sha384","dnssec-rrsig-signed-data","dnssec-canonical-name-rdata","dnssec-ecdsa-p256-verify","dnssec-ecdsa-p384-verify","dnssec-rsa-sha1-verify","dnssec-rsa-sha256-sha512-verify","dnssec-ed25519-verify","dnssec-signed-rrset-validation","dnssec-delegated-chain-validation","dnssec-delegated-no-data-validation","dnssec-delegated-name-error-validation","dnssec-delegated-cname-chain","dnssec-child-referral-validation","dnssec-child-cname-chain","dnssec-child-no-data-validation","dnssec-child-name-error-validation","dnssec-nsec-denial-validation","dnssec-nsec3-denial-validation","dnssec-nxdomain-name-error-validation","dane-policy","dane-certificate-chain-policy","x509-spki-extraction","x509-stateless-dane-evidence","hip17-experimental-urkel-extension","rfc9102-authentication-chain-parser","p2p-codec","p2p-tcp-peer-connection","p2p-static-peer-source","p2p-dns-seed-source","p2p-getaddr-peer-discovery","p2p-discovery-rotation","p2p-peer-diversity","p2p-sqlite-peer-store","sync-coordinator","sync-header-runner","sync-multi-batch-header-runner","sync-parallel-peer-probing","sync-ranged-peer-rotation","sync-checkpoint-prefetch","sync-proof-scheduler","android-native-sync-once","android-sync-status","android-sync-outcome-status","android-sync-progress-heights","android-sync-high-batch-catchup","android-clear-resolver-cache","android-persistent-gateway-resolver","android-gateway-live-proof-fetch","android-gateway-header-forwarding","android-gateway-range-forwarding","android-gateway-body-forwarding","android-gateway-file-body-stream","android-webview-hns-intercept","android-service-worker-hns-intercept","android-hns-redirect-follow","android-actionable-hns-errors","hns-name-not-found-error","gateway-policy","gateway-hns-address-required","gateway-tlsa-service-scope","gateway-delegated-origin-address-lookup","gateway-origin-address-query","gateway-https-service-query","gateway-svcb-alpn-policy","gateway-actionable-nameserver-errors","gateway-cname-address-routing","android-proxy-gateway-hook","android-random-loopback-proxy-port","android-local-hns-connect-certs","hns-websocket-native-tunnel","http-origin-transport","http-origin-connection-pooling","http2-origin-transport","http3-origin-transport","http-origin-response-framing","https-rustls-transport","https-tls-session-resumption","https-alt-svc-promotion","dane-tls-policy"],"securityDefault":"fail-closed"}"#
        .replace("__VERSION__", env!("CARGO_PKG_VERSION"))
}

pub fn sync_once(data_dir: &str) -> String {
    sync_once_for_network(data_dir, NetworkKind::Mainnet)
}

pub fn sync_once_for_network(data_dir: &str, network: NetworkKind) -> String {
    sync_once_with_options(
        data_dir,
        network,
        true,
        Duration::from_secs(3),
        DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
    )
    .to_json()
}

pub fn sync_status(data_dir: &str) -> String {
    sync_status_for_network(data_dir, NetworkKind::Mainnet)
}

pub fn sync_status_for_network(data_dir: &str, network: NetworkKind) -> String {
    read_sync_status(data_dir, network)
        .unwrap_or_else(|error| NativeSyncStatus::error_for(network, error))
        .to_json()
}

pub fn clear_resolver_cache(data_dir: &str) -> String {
    clear_resolver_cache_for_network(data_dir, NetworkKind::Mainnet)
}

pub fn clear_resolver_cache_for_network(data_dir: &str, network: NetworkKind) -> String {
    clear_resolver_cache_inner(data_dir, network)
        .unwrap_or_else(|error| NativeSyncStatus::error_for(network, error))
        .to_json()
}

pub fn install_header_snapshot(data_dir: &str, snapshot_path: &str) -> String {
    install_header_snapshot_for_network(data_dir, snapshot_path, NetworkKind::Mainnet)
}

pub fn install_header_snapshot_for_network(
    data_dir: &str,
    snapshot_path: &str,
    network: NetworkKind,
) -> String {
    install_header_snapshot_inner(data_dir, snapshot_path, network)
        .unwrap_or_else(|error| NativeSyncStatus::error_for(network, error))
        .to_json()
}

pub fn reset_headers_from_peers(data_dir: &str) -> String {
    reset_headers_from_peers_for_network(data_dir, NetworkKind::Mainnet)
}

pub fn reset_headers_from_peers_for_network(data_dir: &str, network: NetworkKind) -> String {
    reset_headers_from_peers_inner(data_dir, network)
        .unwrap_or_else(|error| NativeSyncStatus::error_for(network, error))
        .to_json()
}

pub fn local_tls_certificate_bundle(host: &str) -> Option<Vec<u8>> {
    let certificate = generate_local_tls_certificate(host).ok()?;
    let mut bundle = Vec::with_capacity(
        4 + certificate.certificate_der.len()
            + 4
            + certificate.private_key_pkcs8_der.len()
            + LOCAL_TLS_CERT_FINGERPRINT_BYTES,
    );
    bundle.extend(
        u32::try_from(certificate.certificate_der.len())
            .ok()?
            .to_be_bytes(),
    );
    bundle.extend(&certificate.certificate_der);
    bundle.extend(
        u32::try_from(certificate.private_key_pkcs8_der.len())
            .ok()?
            .to_be_bytes(),
    );
    bundle.extend(&certificate.private_key_pkcs8_der);
    bundle.extend(certificate.certificate_sha256);
    Some(bundle)
}

fn generate_local_tls_certificate(host: &str) -> Result<GeneratedLocalCertificate, RuntimeError> {
    let host = normalized_local_tls_host(host).ok_or_else(|| {
        RuntimeError::InvalidConfiguration("local TLS host is invalid".to_owned())
    })?;
    let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(vec![host])
        .map_err(|error| RuntimeError::Operation(format!("generate local certificate: {error}")))?;
    let certificate_der = cert.der().as_ref().to_vec();
    let private_key_pkcs8_der = signing_key.serialize_der();
    let certificate_sha256 = Sha256::digest(&certificate_der).into();
    Ok(GeneratedLocalCertificate {
        certificate_der,
        private_key_pkcs8_der,
        certificate_sha256,
    })
}

fn normalized_local_tls_host(host: &str) -> Option<String> {
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 253 {
        return None;
    }
    if normalized.contains(':') || normalized.starts_with('[') || normalized.ends_with(']') {
        return None;
    }
    if is_ipv4_literal(&normalized) {
        return None;
    }
    let labels = normalized.split('.').collect::<Vec<_>>();
    if labels.iter().any(|label| !valid_local_tls_label(label)) {
        return None;
    }
    Some(normalized)
}

fn is_ipv4_literal(host: &str) -> bool {
    let parts = host.split('.').collect::<Vec<_>>();
    parts.len() == 4
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 3
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && part.parse::<u8>().is_ok()
        })
}

fn valid_local_tls_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

fn sync_once_with_options(
    data_dir: &str,
    network: NetworkKind,
    seed_on_empty: bool,
    timeout: Duration,
    resource_cache_limit_bytes: usize,
) -> NativeSyncStatus {
    match run_sync_once(
        data_dir,
        network,
        seed_on_empty,
        timeout,
        resource_cache_limit_bytes,
    ) {
        Ok(status) => status,
        Err(error) => NativeSyncStatus::error_for(network, error),
    }
}

pub fn gateway_http_response(input: GatewayHttpRequestInput<'_>) -> Vec<u8> {
    gateway_http_response_with_transport(input, shared_http_transport(), None)
}

fn gateway_http_response_with_transport(
    input: GatewayHttpRequestInput<'_>,
    transport: TcpHttpTransport,
    peer_state: Option<Arc<Mutex<()>>>,
) -> Vec<u8> {
    let parsed_headers = match parse_gateway_headers(input.header_text) {
        Ok(headers) => headers,
        Err(error) => return plain_response_for_request(&input, 400, "Bad Request", error),
    };
    let network = parsed_headers.network;
    let mode = GatewayResolutionMode::from_strict_hns_mode(parsed_headers.strict_hns_mode);
    let request = gateway_request(&input, parsed_headers.headers);
    let dns_trace = DnsTraceRecorder::default();

    let base = network_base_path(input.data_dir, network);
    if let Err(error) = fs::create_dir_all(&base) {
        return plain_response_for_request(
            &input,
            500,
            "Gateway Storage Error",
            &format!("create gateway directory: {error}"),
        );
    }
    let values = match SqliteResourceValueProvider::open(base.join("resources.sqlite")) {
        Ok(values) => values,
        Err(error) => {
            return plain_response_for_request(
                &input,
                500,
                "Gateway Storage Error",
                &format!("open resource cache: {error}"),
            );
        }
    };
    let fallback_marker = FallbackMarker::default();
    let resolver = android_gateway_resolver(
        base.clone(),
        values,
        GatewayResolverContext {
            network,
            mode,
            doh_endpoint: parsed_headers.doh_endpoint,
            peer_state,
            http: transport.clone(),
        },
        fallback_marker.clone(),
        dns_trace.clone(),
    );
    let stateless_dane = stateless_dane_config(&base, parsed_headers.stateless_dane_certificates);
    let gateway = match Gateway::new(
        GatewayConfig {
            hns_https_mode: HnsHttpsMode::Compatibility,
            stateless_dane,
            allow_non_public_origin_addresses: network == NetworkKind::Regtest || cfg!(test),
            allow_unsafe_origin_ports: network == NetworkKind::Regtest,
            ..GatewayConfig::default()
        },
        resolver,
        transport,
    ) {
        Ok(gateway) => gateway,
        Err(error) => {
            return plain_response_for_request(
                &input,
                500,
                "Gateway Configuration Error",
                &error.to_string(),
            );
        }
    };

    match gateway.handle(&request) {
        Ok(response) => {
            let resolver_policy = fallback_marker.used().then_some("hns-doh-compat");
            let security_path = security_path_name(
                &input,
                response.origin_request.port,
                &response.origin.dane_decision,
                &dns_trace.snapshot(),
            );
            let trace = resolution_trace_json(
                &input,
                network,
                mode,
                Some(&response.resolution),
                TlsTraceInput {
                    validation: Some(&response.origin_request.tls),
                    decision: Some(&response.origin.dane_decision),
                    inspection: response.origin.tls_inspection.as_ref(),
                    origin_address: response.origin_request.connect_host.as_deref(),
                },
                None,
                &fallback_marker,
                &dns_trace,
            );
            origin_response_with_resolver_policy_and_trace(
                response.origin,
                resolver_policy,
                security_path,
                &trace,
            )
        }
        Err(error) => {
            let (status, reason, detail) = map_gateway_error_for_host(input.host, &error);
            let trace = resolution_trace_json(
                &input,
                network,
                mode,
                None,
                TlsTraceInput::default(),
                Some(&error),
                &fallback_marker,
                &dns_trace,
            );
            plain_response_for_request_with_trace(&input, status, reason, detail, &trace)
        }
    }
}

pub fn gateway_http_response_body_to_file(
    input: GatewayHttpRequestInput<'_>,
    body_path: &Path,
) -> Result<Vec<u8>, String> {
    gateway_http_response_body_to_file_with_transport(
        input,
        body_path,
        shared_http_transport(),
        None,
    )
}

fn gateway_http_response_body_to_file_with_transport(
    input: GatewayHttpRequestInput<'_>,
    body_path: &Path,
    transport: TcpHttpTransport,
    peer_state: Option<Arc<Mutex<()>>>,
) -> Result<Vec<u8>, String> {
    let parsed_headers = match parse_gateway_headers(input.header_text) {
        Ok(headers) => headers,
        Err(error) => {
            return plain_response_to_file_for_request(
                &input,
                400,
                "Bad Request",
                error,
                body_path,
            );
        }
    };
    let network = parsed_headers.network;
    let mode = GatewayResolutionMode::from_strict_hns_mode(parsed_headers.strict_hns_mode);
    let request = gateway_request(&input, parsed_headers.headers);
    let dns_trace = DnsTraceRecorder::default();

    let base = network_base_path(input.data_dir, network);
    if let Err(error) = fs::create_dir_all(&base) {
        return plain_response_to_file_for_request(
            &input,
            500,
            "Gateway Storage Error",
            &format!("create gateway directory: {error}"),
            body_path,
        );
    }
    let values = match SqliteResourceValueProvider::open(base.join("resources.sqlite")) {
        Ok(values) => values,
        Err(error) => {
            return plain_response_to_file_for_request(
                &input,
                500,
                "Gateway Storage Error",
                &format!("open resource cache: {error}"),
                body_path,
            );
        }
    };
    let fallback_marker = FallbackMarker::default();
    let resolver = android_gateway_resolver(
        base.clone(),
        values,
        GatewayResolverContext {
            network,
            mode,
            doh_endpoint: parsed_headers.doh_endpoint,
            peer_state,
            http: transport.clone(),
        },
        fallback_marker.clone(),
        dns_trace.clone(),
    );
    let stateless_dane = stateless_dane_config(&base, parsed_headers.stateless_dane_certificates);
    let gateway = match Gateway::new(
        GatewayConfig {
            hns_https_mode: HnsHttpsMode::Compatibility,
            stateless_dane,
            allow_non_public_origin_addresses: network == NetworkKind::Regtest || cfg!(test),
            allow_unsafe_origin_ports: network == NetworkKind::Regtest,
            ..GatewayConfig::default()
        },
        resolver,
        transport,
    ) {
        Ok(gateway) => gateway,
        Err(error) => {
            return plain_response_to_file_for_request(
                &input,
                500,
                "Gateway Configuration Error",
                &error.to_string(),
                body_path,
            );
        }
    };

    if let Some(parent) = body_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create response directory: {error}"))?;
    }
    let mut body_file =
        fs::File::create(body_path).map_err(|error| format!("create response body: {error}"))?;
    match gateway.handle_to_writer(&request, &mut body_file) {
        Ok(response) => {
            let resolver_policy = fallback_marker.used().then_some("hns-doh-compat");
            let security_path = security_path_name(
                &input,
                response.origin_request.port,
                &response.origin.dane_decision,
                &dns_trace.snapshot(),
            );
            let trace = resolution_trace_json(
                &input,
                network,
                mode,
                Some(&response.resolution),
                TlsTraceInput {
                    validation: Some(&response.origin_request.tls),
                    decision: Some(&response.origin.dane_decision),
                    inspection: response.origin.tls_inspection.as_ref(),
                    origin_address: response.origin_request.connect_host.as_deref(),
                },
                None,
                &fallback_marker,
                &dns_trace,
            );
            Ok(origin_response_head_with_resolver_policy_and_trace(
                response.origin,
                resolver_policy,
                security_path,
                &trace,
            ))
        }
        Err(error) => {
            let (status, reason, detail) = map_gateway_error_for_host(input.host, &error);
            let trace = resolution_trace_json(
                &input,
                network,
                mode,
                None,
                TlsTraceInput::default(),
                Some(&error),
                &fallback_marker,
                &dns_trace,
            );
            plain_response_to_file_for_request_with_trace(
                &input, status, reason, detail, body_path, &trace,
            )
        }
    }
}

pub fn gateway_http_upgrade_tunnel(
    input: GatewayHttpRequestInput<'_>,
    client_input: impl Read + Send + 'static,
    client_output: impl Write + Send + 'static,
) -> bool {
    gateway_http_upgrade_tunnel_with_transport(
        input,
        client_input,
        client_output,
        shared_http_transport(),
        None,
    )
}

fn gateway_http_upgrade_tunnel_with_transport(
    input: GatewayHttpRequestInput<'_>,
    mut client_input: impl Read + Send + 'static,
    mut client_output: impl Write + Send + 'static,
    transport: TcpHttpTransport,
    peer_state: Option<Arc<Mutex<()>>>,
) -> bool {
    let parsed_headers = match parse_gateway_headers(input.header_text) {
        Ok(headers) => headers,
        Err(error) => {
            return write_tunnel_response(
                &mut client_output,
                &plain_response_for_request(&input, 400, "Bad Request", error),
            );
        }
    };
    let network = parsed_headers.network;
    let mode = GatewayResolutionMode::from_strict_hns_mode(parsed_headers.strict_hns_mode);
    let request = gateway_request(&input, parsed_headers.headers);
    let dns_trace = DnsTraceRecorder::default();

    let base = network_base_path(input.data_dir, network);
    if let Err(error) = fs::create_dir_all(&base) {
        return write_tunnel_response(
            &mut client_output,
            &plain_response_for_request(
                &input,
                500,
                "Gateway Storage Error",
                &format!("create gateway directory: {error}"),
            ),
        );
    }
    let values = match SqliteResourceValueProvider::open(base.join("resources.sqlite")) {
        Ok(values) => values,
        Err(error) => {
            return write_tunnel_response(
                &mut client_output,
                &plain_response_for_request(
                    &input,
                    500,
                    "Gateway Storage Error",
                    &format!("open resource cache: {error}"),
                ),
            );
        }
    };
    let fallback_marker = FallbackMarker::default();
    let resolver = android_gateway_resolver(
        base.clone(),
        values,
        GatewayResolverContext {
            network,
            mode,
            doh_endpoint: parsed_headers.doh_endpoint,
            peer_state,
            http: transport.clone(),
        },
        fallback_marker.clone(),
        dns_trace.clone(),
    );
    let stateless_dane = stateless_dane_config(&base, parsed_headers.stateless_dane_certificates);
    let gateway = match Gateway::new(
        GatewayConfig {
            hns_https_mode: HnsHttpsMode::Compatibility,
            stateless_dane,
            allow_non_public_origin_addresses: network == NetworkKind::Regtest || cfg!(test),
            allow_unsafe_origin_ports: network == NetworkKind::Regtest,
            ..GatewayConfig::default()
        },
        resolver,
        transport,
    ) {
        Ok(gateway) => gateway,
        Err(error) => {
            return write_tunnel_response(
                &mut client_output,
                &plain_response_for_request(
                    &input,
                    500,
                    "Gateway Configuration Error",
                    &error.to_string(),
                ),
            );
        }
    };

    match gateway.handle_tunnel(&request) {
        Ok(response) => {
            let resolver_policy = fallback_marker.used().then_some("hns-doh-compat");
            let trace = resolution_trace_json(
                &input,
                network,
                mode,
                Some(&response.resolution),
                TlsTraceInput {
                    validation: Some(&response.origin_request.tls),
                    decision: Some(&response.origin.dane_decision),
                    inspection: response.origin.tls_inspection.as_ref(),
                    origin_address: response.origin_request.connect_host.as_deref(),
                },
                None,
                &fallback_marker,
                &dns_trace,
            );
            let response_head = upgrade_response_head_with_resolver_policy_and_trace(
                &response.origin.response_head,
                &response.origin.dane_decision,
                resolver_policy,
                &trace,
            );
            if !write_tunnel_response(&mut client_output, &response_head) {
                return false;
            }

            let origin = Arc::new(Mutex::new(response.origin.stream));
            let done = Arc::new(AtomicBool::new(false));
            let origin_writer = Arc::clone(&origin);
            let writer_done = Arc::clone(&done);
            let _client_to_origin = thread::spawn(move || {
                let _ = copy_client_to_origin(&mut client_input, origin_writer);
                writer_done.store(true, Ordering::SeqCst);
            });
            let result = copy_origin_to_client(origin, &mut client_output, Arc::clone(&done));
            done.store(true, Ordering::SeqCst);
            result.is_ok()
        }
        Err(error) => {
            let (status, reason, detail) = map_gateway_error_for_host(input.host, &error);
            let trace = resolution_trace_json(
                &input,
                network,
                mode,
                None,
                TlsTraceInput::default(),
                Some(&error),
                &fallback_marker,
                &dns_trace,
            );
            write_tunnel_response(
                &mut client_output,
                &plain_response_for_request_with_trace(&input, status, reason, detail, &trace),
            )
        }
    }
}

fn write_tunnel_response(output: &mut impl Write, bytes: &[u8]) -> bool {
    output.write_all(bytes).and_then(|_| output.flush()).is_ok()
}

fn copy_client_to_origin(
    client_input: &mut impl Read,
    origin: Arc<Mutex<Box<dyn ReadWrite>>>,
) -> std::io::Result<()> {
    let mut buffer = [0u8; TUNNEL_COPY_BUFFER_BYTES];
    loop {
        let read = match client_input.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(read) => read,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let mut origin = origin
            .lock()
            .map_err(|_| std::io::Error::other("origin tunnel lock is poisoned"))?;
        origin.write_all(&buffer[..read])?;
        origin.flush()?;
    }
}

fn copy_origin_to_client(
    origin: Arc<Mutex<Box<dyn ReadWrite>>>,
    client_output: &mut impl Write,
    done: Arc<AtomicBool>,
) -> std::io::Result<()> {
    let mut buffer = [0u8; TUNNEL_COPY_BUFFER_BYTES];
    loop {
        let read = {
            let mut origin = origin
                .lock()
                .map_err(|_| std::io::Error::other("origin tunnel lock is poisoned"))?;
            match origin.read(&mut buffer) {
                Ok(0) => return Ok(()),
                Ok(read) => Some(read),
                Err(error)
                    if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
                {
                    None
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => None,
                Err(error) => return Err(error),
            }
        };
        let Some(read) = read else {
            if done.load(Ordering::SeqCst) {
                return Ok(());
            }
            continue;
        };
        client_output.write_all(&buffer[..read])?;
        client_output.flush()?;
    }
}

fn gateway_request(
    input: &GatewayHttpRequestInput<'_>,
    headers: Vec<(String, String)>,
) -> GatewayRequest {
    GatewayRequest {
        auth_token: None,
        origin: OriginRequest {
            method: input.method.to_owned(),
            scheme: input.scheme.to_ascii_lowercase(),
            host: input.host.to_owned(),
            connect_host: None,
            port: input.port,
            path_and_query: input.path_and_query.to_owned(),
            protocol: OriginProtocol::Http11,
            tls: if input.scheme.eq_ignore_ascii_case("https")
                || input.scheme.eq_ignore_ascii_case("wss")
            {
                TlsValidation::hns_compatibility(false, Vec::new())
            } else {
                TlsValidation::default()
            },
            headers,
            body: input.body.to_vec(),
        },
        resolution: ResolutionRequest {
            qname: input.host.to_owned(),
            qtype: RecordType::A.code(),
        },
    }
}

fn stateless_dane_config(base: &Path, enabled: bool) -> StatelessDaneConfig {
    if !enabled {
        return StatelessDaneConfig::default();
    }
    StatelessDaneConfig {
        enabled: true,
        accepted_tree_roots: recent_stateless_dane_tree_roots(base).unwrap_or_default(),
    }
}

fn recent_stateless_dane_tree_roots(base: &Path) -> Result<Vec<[u8; 32]>, ResolverError> {
    let header_store = SqliteHeaderStore::open(base.join("headers.sqlite"))
        .map_err(|error| ResolverError::Storage(format!("open header store: {error}")))?;
    let chain = HeaderChain::new(header_store);
    let Some(best) = chain
        .best_header()
        .map_err(|error| ResolverError::Storage(format!("read best header: {error}")))?
    else {
        return Ok(Vec::new());
    };

    let mut roots = Vec::new();
    let mut height = best.height.0;
    let mut steps = 0usize;
    while steps < MAX_STATELESS_DANE_ROOTS {
        if let Some(header) = chain.canonical_header(Height(height)) {
            let root = header.header.tree_root.into_bytes();
            if !roots.contains(&root) {
                roots.push(root);
            }
        }
        if height == 0 {
            break;
        }
        height -= 1;
        steps += 1;
    }
    Ok(roots)
}

fn android_gateway_resolver(
    base: PathBuf,
    values: SqliteResourceValueProvider,
    context: GatewayResolverContext,
    fallback_marker: FallbackMarker,
    dns_trace: DnsTraceRecorder,
) -> AndroidGatewayResolver {
    let GatewayResolverContext {
        network,
        mode,
        doh_endpoint,
        peer_state,
        http,
    } = context;
    let endpoint_policy = DnsEndpointPolicy::for_network(network);
    let authoritative_dns_transport =
        android_authoritative_dns_transport(mode, dns_trace.clone(), endpoint_policy, http.clone());
    match mode {
        GatewayResolutionMode::Strict => {
            let primary = DelegatingResolver::new(
                GatewayProofProvider::new(base, values, network).with_peer_state(peer_state),
                AuthoritativeDnssecResolver::new(authoritative_dns_transport, SystemDnssecVerifier)
                    .with_authoritative_doh_preferred(),
            );
            AndroidGatewayResolver::Strict(Box::new(CompositeResolver::new(
                primary,
                IcannDohResolver::new(dns_trace, http),
            )))
        }
        GatewayResolutionMode::Compatibility => {
            let direct =
                AuthoritativeDnssecResolver::new(authoritative_dns_transport, SystemDnssecVerifier)
                    .with_authoritative_doh_preferred();
            let doh = AuthoritativeDnssecResolver::new(
                HnsDohDnsTransport::new(
                    doh_endpoint.clone(),
                    dns_trace.clone(),
                    endpoint_policy,
                    http.clone(),
                ),
                SystemDnssecVerifier,
            );
            let delegated = FallbackDelegatedResolver::new(direct, doh, fallback_marker.clone());
            let primary = DelegatingResolver::new(
                GatewayProofProvider::new(base, values, network).with_peer_state(peer_state),
                delegated,
            );
            let hns = FallbackResolver::with_marker(
                primary,
                HnsDohResolver::new(doh_endpoint, dns_trace.clone(), http.clone()),
                fallback_marker,
            );
            AndroidGatewayResolver::Compatibility(Box::new(CompositeResolver::new(
                hns,
                IcannDohResolver::new(dns_trace, http),
            )))
        }
    }
}

struct GatewayResolverContext {
    network: NetworkKind,
    mode: GatewayResolutionMode,
    doh_endpoint: HnsDohEndpoint,
    peer_state: Option<Arc<Mutex<()>>>,
    http: TcpHttpTransport,
}

fn android_authoritative_dns_transport(
    mode: GatewayResolutionMode,
    dns_trace: DnsTraceRecorder,
    endpoint_policy: DnsEndpointPolicy,
    http: TcpHttpTransport,
) -> AndroidAuthoritativeDnsTransport {
    let mut transport = UdpTcpDnsTransport {
        endpoint_policy,
        ..UdpTcpDnsTransport::default()
    };
    if mode == GatewayResolutionMode::Compatibility {
        transport.timeout = ANDROID_COMPAT_AUTHORITATIVE_DNS_TIMEOUT;
    }
    AndroidAuthoritativeDnsTransport::new(transport, dns_trace, http)
}

fn parse_gateway_headers(header_text: &str) -> Result<ParsedGatewayHeaders, &'static str> {
    if header_text.len() > MAX_GATEWAY_HEADER_TEXT_BYTES {
        return Err("request headers are too large");
    }

    let mut headers = Vec::new();
    let mut strict_hns_mode = false;
    let mut doh_endpoint = HnsDohEndpoint::default();
    let mut stateless_dane_certificates = false;
    let mut network = NetworkKind::Mainnet;
    for line in header_text.split("\r\n").filter(|line| !line.is_empty()) {
        let Some(separator) = line.find(':') else {
            return Err("request header is malformed");
        };
        let name = line[..separator].trim();
        let value = line[separator + 1..].trim();
        if !is_valid_gateway_header_name(name) || !is_valid_gateway_header_value(value) {
            return Err("request header is invalid");
        }
        if name.eq_ignore_ascii_case(HNS_GATEWAY_STRICT_MODE_HEADER) {
            if value == "1" || value.eq_ignore_ascii_case("true") {
                strict_hns_mode = true;
            }
            continue;
        }
        if name.eq_ignore_ascii_case(HNS_GATEWAY_DOH_RESOLVER_HEADER) {
            doh_endpoint = HnsDohEndpoint::parse(value)?;
            continue;
        }
        if name.eq_ignore_ascii_case(HNS_GATEWAY_STATELESS_DANE_HEADER) {
            if value == "1" || value.eq_ignore_ascii_case("true") {
                stateless_dane_certificates = true;
            }
            continue;
        }
        if name.eq_ignore_ascii_case(HNS_GATEWAY_NETWORK_HEADER) {
            network = value.parse().map_err(|_| "Handshake network is invalid")?;
            continue;
        }
        if name.eq_ignore_ascii_case(HNS_SECURITY_PATH_HEADER) {
            continue;
        }
        headers.push((name.to_owned(), value.to_owned()));
    }

    Ok(ParsedGatewayHeaders {
        headers,
        strict_hns_mode,
        doh_endpoint,
        stateless_dane_certificates,
        network,
    })
}

#[cfg(test)]
fn origin_response(response: OriginResponse) -> Vec<u8> {
    origin_response_with_resolver_policy_and_trace(response, None, None, "{}")
}

fn origin_response_with_resolver_policy_and_trace(
    response: OriginResponse,
    resolver_policy: Option<&str>,
    security_path: Option<&str>,
    trace_json: &str,
) -> Vec<u8> {
    let body = response.body;
    let mut out = origin_response_head_with_resolver_policy_and_trace(
        OriginResponseHead {
            status: response.status,
            headers: response.headers,
            body_len: body.len(),
            dane_decision: response.dane_decision,
            tls_inspection: response.tls_inspection,
        },
        resolver_policy,
        security_path,
        trace_json,
    );
    out.extend(body);
    out
}

#[cfg(test)]
fn origin_response_with_resolver_policy(
    response: OriginResponse,
    resolver_policy: Option<&str>,
) -> Vec<u8> {
    origin_response_with_resolver_policy_and_trace(response, resolver_policy, None, "{}")
}

fn origin_response_head_with_resolver_policy_and_trace(
    response: OriginResponseHead,
    resolver_policy: Option<&str>,
    security_path: Option<&str>,
    trace_json: &str,
) -> Vec<u8> {
    let mut out = response_head(response.status, "OK", None, response.body_len);
    for (name, value) in response.headers {
        if suppressed_origin_response_header(&name) {
            continue;
        }
        out.extend(format!("{name}: {value}\r\n").as_bytes());
    }
    if let Some(policy) = hns_tls_policy_header(&response.dane_decision) {
        out.extend(format!("X-HNS-TLS-Policy: {policy}\r\n").as_bytes());
    }
    if let Some(policy) = resolver_policy {
        out.extend(format!("X-HNS-Resolver-Policy: {policy}\r\n").as_bytes());
    }
    if let Some(path) = security_path {
        out.extend(format!("{HNS_SECURITY_PATH_HEADER}: {path}\r\n").as_bytes());
    }
    out.extend(format!("{HNS_RESOLVER_MODE_HEADER}: {}\r\n", trace_mode(trace_json)).as_bytes());
    out.extend(
        format!(
            "{HNS_DOH_FALLBACK_HEADER}: {}\r\n",
            trace_doh_fallback(trace_json)
        )
        .as_bytes(),
    );
    out.extend(format!("{HNS_RESOLUTION_TRACE_HEADER}: {trace_json}\r\n").as_bytes());
    out.extend(b"\r\n");
    out
}

fn upgrade_response_head_with_resolver_policy_and_trace(
    response_head: &[u8],
    decision: &DaneDecision,
    resolver_policy: Option<&str>,
    trace_json: &str,
) -> Vec<u8> {
    let header_text = String::from_utf8_lossy(response_head);
    let header_text = header_text.strip_suffix("\r\n\r\n").unwrap_or(&header_text);
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().unwrap_or("HTTP/1.1 101 Switching Protocols");
    let header_lines = lines.filter(|line| !line.is_empty()).collect::<Vec<_>>();
    let connection_nominated = header_lines
        .iter()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect::<HashSet<_>>();
    let mut out = format!("{status_line}\r\n").into_bytes();
    for line in header_lines {
        let Some((name, _)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("upgrade")
            || connection_nominated.contains(&name.to_ascii_lowercase())
            || suppressed_origin_response_header(name)
        {
            continue;
        }
        out.extend(line.as_bytes());
        out.extend(b"\r\n");
    }
    // The Android bridge validates the browser-visible WebSocket handshake itself. Preserve the
    // required hop-by-hop pair in canonical form while stripping every other Connection-nominated
    // field from the origin response.
    out.extend(b"Upgrade: websocket\r\nConnection: Upgrade\r\n");
    if let Some(policy) = hns_tls_policy_header(decision) {
        out.extend(format!("X-HNS-TLS-Policy: {policy}\r\n").as_bytes());
    }
    if let Some(policy) = resolver_policy {
        out.extend(format!("X-HNS-Resolver-Policy: {policy}\r\n").as_bytes());
    }
    out.extend(format!("{HNS_RESOLVER_MODE_HEADER}: {}\r\n", trace_mode(trace_json)).as_bytes());
    out.extend(
        format!(
            "{HNS_DOH_FALLBACK_HEADER}: {}\r\n",
            trace_doh_fallback(trace_json)
        )
        .as_bytes(),
    );
    out.extend(format!("{HNS_RESOLUTION_TRACE_HEADER}: {trace_json}\r\n").as_bytes());
    out.extend(b"\r\n");
    out
}

fn suppressed_origin_response_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("trailer")
        || is_reserved_hns_header(name)
}

#[derive(Clone, Copy, Default)]
struct TlsTraceInput<'a> {
    validation: Option<&'a TlsValidation>,
    decision: Option<&'a DaneDecision>,
    inspection: Option<&'a TlsCertificateInspection>,
    origin_address: Option<&'a str>,
}

// The trace deliberately keeps its independent resolution, TLS, fallback, and DNS inputs
// explicit so security diagnostics cannot silently inherit state from a mutable context object.
#[allow(clippy::too_many_arguments)]
fn resolution_trace_json(
    input: &GatewayHttpRequestInput<'_>,
    network: NetworkKind,
    mode: GatewayResolutionMode,
    resolution: Option<&ResolutionAnswer>,
    tls: TlsTraceInput<'_>,
    error: Option<&GatewayError>,
    fallback_marker: &FallbackMarker,
    dns_trace: &DnsTraceRecorder,
) -> String {
    let dns_events = dns_trace.snapshot();
    let name_class = classify_name(input.host);
    let resource_types = resolution
        .map(|answer| {
            answer
                .records
                .iter()
                .map(|record| record_type_name(&record.record_type))
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .map(|record_type| format!(r#""{}""#, json_escape(record_type)))
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    let authoritative_dns_used = dns_events
        .iter()
        .any(|event| event.protocol == "udp53" || event.protocol == "tcp53");
    let delegation = resolution
        .map(|answer| {
            authoritative_dns_used
                || answer.records.iter().any(|record| {
                    matches!(
                        record.record_type,
                        RecordType::Ns | RecordType::Ds | RecordType::Unknown(6)
                    )
                })
        })
        .unwrap_or(false);
    let origin_address = tls.origin_address.is_some()
        || resolution
            .map(|answer| {
                answer
                    .records
                    .iter()
                    .any(|record| matches!(record.record_type, RecordType::A | RecordType::Aaaa))
            })
            .unwrap_or(false);
    let hns_proof = hns_proof_trace_status(input, network, name_class, resolution, error);
    let fallback_reason = fallback_marker.reason().unwrap_or("none");
    let fallback_type = if fallback_marker.used() {
        r#""HNS_DOH""#
    } else {
        "null"
    };
    let fallback_reason_json = if fallback_marker.used() {
        format!(r#""{}""#, json_escape(fallback_reason))
    } else {
        "null".to_owned()
    };
    let final_error = error
        .map(|error| format!(r#""{}""#, json_escape(&error.to_string())))
        .unwrap_or_else(|| "null".to_owned());
    let authoritative_dns = authoritative_dns_trace_json(&dns_events);
    let port53_interception = dns_protocol_status(&dns_events, "dns_interception_probe");
    let dns_attempts = dns_trace_attempts_json(&dns_events);
    let resolution_source = resolution_source_name(
        input.host,
        name_class,
        resolution,
        authoritative_dns_used,
        error,
        &dns_events,
    );
    let local_currentness = local_chain_currentness_for_trace(input.data_dir, network);
    let local_best_height =
        optional_u32_json(local_currentness.and_then(|value| value.best_height));
    let target_height = optional_u32_json(local_currentness.and_then(|value| value.target_height));
    let estimated_tip_height =
        optional_u32_json(local_currentness.and_then(|value| value.estimated_tip_height));
    let local_chain_stale = optional_bool_json(local_currentness.and_then(|value| value.stale));

    format!(
        r#"{{"host":"{}","url":"{}","nameClass":"{}","root":"{}","network":"{}","mode":"{}","hnsProof":"{}","localBestHeight":{},"targetHeight":{},"estimatedTargetHeight":{},"localChainStale":{},"delegation":{},"resolutionSource":"{}","resourceRecords":[{}],"nameserverCandidates":{},"authoritativeDns":{},"port53Interception":"{}","dnssec":"{}","originAddress":"{}","tls":{},"fallback":{{"used":{},"type":{},"reason":{}}},"dnsAttempts":[{}],"finalError":{}}}"#,
        json_escape(input.host),
        json_escape(&gateway_request_address(input)),
        name_class_trace_name(name_class),
        json_escape(&hns_trace_root(input.host)),
        network.as_str(),
        mode.as_str(),
        hns_proof,
        local_best_height,
        target_height,
        estimated_tip_height,
        local_chain_stale,
        delegation,
        resolution_source,
        resource_types,
        nameserver_candidates_json(&dns_events),
        authoritative_dns,
        port53_interception,
        dnssec_trace_status(resolution, error),
        if origin_address { "found" } else { "missing" },
        tls_trace_json(input, tls.validation, tls.decision, tls.inspection, error),
        fallback_marker.used(),
        fallback_type,
        fallback_reason_json,
        dns_attempts,
        final_error,
    )
}

fn name_class_trace_name(name_class: NameClass) -> &'static str {
    match name_class {
        NameClass::Hns => "hns",
        NameClass::Icann => "icann",
        NameClass::Search => "search",
    }
}

fn resolution_source_name(
    host: &str,
    name_class: NameClass,
    resolution: Option<&ResolutionAnswer>,
    authoritative_dns_used: bool,
    error: Option<&GatewayError>,
    dns_events: &[DnsTraceEvent],
) -> &'static str {
    if name_class == NameClass::Icann {
        if dns_events.iter().any(|event| event.protocol == "icann_doh")
            || matches!(
                error,
                Some(GatewayError::Resolver(ResolverError::DnsTransport(message)))
                    if message.contains("ICANN DoH")
            )
        {
            return "trusted_icann_doh";
        }
        if resolution.is_some() {
            return "icann_dns";
        }
        return "unknown";
    }

    if resolution.is_some() {
        match successful_dns_path_for_types(dns_events, host, &[RecordType::A, RecordType::Aaaa]) {
            Some("authoritative_doh") => return "authoritative_doh",
            Some("udp53" | "tcp53") => return "authoritative_dns",
            Some("hns_doh") => return "hns_doh",
            _ => return "hns_resource",
        }
    }
    if matches!(
        error,
        Some(GatewayError::Resolver(ResolverError::DnsTransport(_)))
            | Some(GatewayError::Resolver(ResolverError::DnsResponseCode(_)))
            | Some(GatewayError::Resolver(ResolverError::InvalidDnsResponse))
            | Some(GatewayError::Resolver(ResolverError::DnssecFailed))
    ) {
        return "authoritative_dns";
    }
    if authoritative_dns_used {
        "authoritative_dns"
    } else {
        "unknown"
    }
}

fn hns_proof_trace_status(
    input: &GatewayHttpRequestInput<'_>,
    network: NetworkKind,
    name_class: NameClass,
    resolution: Option<&ResolutionAnswer>,
    error: Option<&GatewayError>,
) -> &'static str {
    if name_class != NameClass::Hns {
        return "not_applicable";
    }

    match (resolution, error) {
        (Some(answer), _) if answer.secure => "verified",
        (_, Some(GatewayError::Resolver(ResolverError::ProofUnavailable))) => "unavailable",
        (_, Some(GatewayError::Resolver(ResolverError::NameNotFound))) => "not_found",
        (_, Some(GatewayError::Resolver(ResolverError::LocalChainNotCurrent))) => "stale",
        (_, Some(GatewayError::Resolver(ResolverError::ProofNameMismatch))) => "failed",
        _ => {
            hns_cached_proof_trace_status(input.data_dir, network, input.host).unwrap_or("unknown")
        }
    }
}

fn hns_cached_proof_trace_status(
    data_dir: &str,
    network: NetworkKind,
    host: &str,
) -> Option<&'static str> {
    let (_, root_name) = hns_proof_host_and_root(host).ok()?;
    let name_hash = NameHash::from_name(&root_name).ok()?;
    let resources_path = network_base_path(data_dir, network).join("resources.sqlite");
    if !resources_path.exists() {
        return Some("unavailable");
    }
    let provider = SqliteResourceValueProvider::open(resources_path).ok()?;
    match provider.prove_resource_value(&root_name, name_hash) {
        Ok(verified) if !verified.secure => Some("failed"),
        Ok(verified) if verified.value.is_some() => Some("verified"),
        Ok(_)
            if local_chain_currentness_for_trace(data_dir, network)
                .and_then(|currentness| currentness.stale)
                .unwrap_or(false) =>
        {
            Some("stale")
        }
        Ok(_) => Some("not_found"),
        Err(ResolverError::ProofUnavailable) => Some("unavailable"),
        Err(ResolverError::ProofNameMismatch) => Some("failed"),
        Err(_) => None,
    }
}

fn local_chain_currentness_for_trace(
    data_dir: &str,
    network: NetworkKind,
) -> Option<LocalChainCurrentness> {
    local_chain_currentness(&network_base_path(data_dir, network), network).ok()
}

fn optional_u32_json(value: Option<u32>) -> String {
    value
        .map(|height| height.to_string())
        .unwrap_or_else(|| "null".to_owned())
}

fn optional_bool_json(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "null",
    }
}

fn authoritative_dns_trace_json(events: &[DnsTraceEvent]) -> String {
    format!(
        r#"{{"udp53":"{}","tcp53":"{}","doh":"{}"}}"#,
        dns_protocol_status(events, "udp53"),
        dns_protocol_status(events, "tcp53"),
        dns_protocol_status(events, "authoritative_doh"),
    )
}

fn tls_trace_json(
    input: &GatewayHttpRequestInput<'_>,
    tls_validation: Option<&TlsValidation>,
    dane_decision: Option<&DaneDecision>,
    tls_inspection: Option<&TlsCertificateInspection>,
    error: Option<&GatewayError>,
) -> String {
    if !input.scheme.eq_ignore_ascii_case("https")
        && tls_validation
            .map(|tls| tls.tlsa_records.is_empty())
            .unwrap_or(true)
        && dane_decision.is_none()
    {
        return "null".to_owned();
    }

    let owner = tlsa_owner_name(
        input.host,
        tls_validation
            .map(|tls| tls.service_port)
            .unwrap_or(input.port),
    );
    let stateless_dane = matches!(dane_decision, Some(DaneDecision::StatelessMatched(_)));
    let tlsa_evaluated = tls_validation.is_some();
    let tlsa_status = if stateless_dane {
        "present"
    } else {
        tlsa_status_name(tls_validation)
    };
    let tlsa_blocked_by = tlsa_blocked_by_json(tls_validation, error);
    let records = tls_validation
        .map(|tls| tlsa_records_json(&tls.tlsa_records))
        .unwrap_or_else(|| "[]".to_owned());
    let records_found = stateless_dane
        || tls_validation
            .map(|tls| !tls.tlsa_records.is_empty())
            .unwrap_or(false);
    let dnssec_secure = if stateless_dane {
        "true"
    } else {
        tls_validation
            .map(|tls| if tls.dnssec_secure { "true" } else { "false" })
            .unwrap_or("null")
    };
    let tlsa_source = if stateless_dane {
        r#""stateless_certificate""#.to_owned()
    } else {
        tls_validation
            .and_then(|tls| tls.tlsa_source)
            .map(|source| format!(r#""{}""#, tlsa_record_source_name(source)))
            .unwrap_or_else(|| "null".to_owned())
    };
    let mode = tls_validation
        .map(|tls| format!(r#""{}""#, json_escape(tls_mode_name(tls))))
        .unwrap_or_else(|| "null".to_owned());
    let decision = dane_trace_decision(dane_decision, error);
    let matched_usage = dane_decision
        .and_then(|decision| match decision {
            DaneDecision::Matched(usage) | DaneDecision::StatelessMatched(usage) => {
                Some(format!(r#""{}""#, tlsa_usage_name(*usage)))
            }
            _ => None,
        })
        .unwrap_or_else(|| "null".to_owned());
    let certificate_match = dane_certificate_match(dane_decision, error);
    let fallback = matches!(dane_decision, Some(DaneDecision::WebPkiFallback));

    format!(
        r#"{{"mode":{},"tlsaOwner":"{}","tlsaEvaluated":{},"tlsaStatus":"{}","tlsaBlockedBy":{},"tlsaFound":{},"dnssecSecure":{},"tlsaSource":{},"records":{},"certificate":{},"dane":{{"decision":"{}","matchedUsage":{},"certificateMatch":"{}","webPkiFallback":{}}}}}"#,
        mode,
        json_escape(&owner),
        tlsa_evaluated,
        tlsa_status,
        tlsa_blocked_by,
        records_found,
        dnssec_secure,
        tlsa_source,
        records,
        tls_certificate_inspection_json(tls_inspection),
        decision,
        matched_usage,
        certificate_match,
        fallback,
    )
}

fn tlsa_record_source_name(source: TlsaRecordSource) -> &'static str {
    match source {
        TlsaRecordSource::NativeTlsa => "native_tlsa",
        TlsaRecordSource::HnsProofTxt => "hns_proof_txt",
    }
}

fn tls_certificate_inspection_json(inspection: Option<&TlsCertificateInspection>) -> String {
    let Some(inspection) = inspection else {
        return "null".to_owned();
    };
    format!(
        r#"{{"webPkiStatus":"{}","endEntitySha256":"{}","spkiSha256":"{}","spkiDerHex":"{}","intermediateCount":{},"intermediateSha256":[{}]}}"#,
        webpki_status_name(inspection.webpki_status),
        sha256_hex(&inspection.end_entity_der),
        sha256_hex(&inspection.end_entity_spki_der),
        hex_lower(&inspection.end_entity_spki_der),
        inspection.intermediate_der.len(),
        inspection
            .intermediate_der
            .iter()
            .map(|certificate| format!(r#""{}""#, sha256_hex(certificate)))
            .collect::<Vec<_>>()
            .join(","),
    )
}

fn webpki_status_name(status: hns_dane::WebPkiStatus) -> &'static str {
    match status {
        hns_dane::WebPkiStatus::Valid => "valid",
        hns_dane::WebPkiStatus::Invalid => "invalid",
        hns_dane::WebPkiStatus::NotEvaluated => "not_evaluated",
    }
}

fn sha256_hex(value: &[u8]) -> String {
    hex_lower(&Sha256::digest(value))
}

fn tlsa_owner_name(host: &str, port: u16) -> String {
    format!("_{}._tcp.{}", port, host.trim_end_matches('.'))
}

fn tlsa_status_name(tls_validation: Option<&TlsValidation>) -> &'static str {
    match tls_validation {
        Some(tls) if tls.tlsa_records.is_empty() => "absent",
        Some(_) => "present",
        None => "not_evaluated",
    }
}

fn tlsa_blocked_by_json(
    tls_validation: Option<&TlsValidation>,
    error: Option<&GatewayError>,
) -> String {
    if tls_validation.is_some() {
        return "null".to_owned();
    }
    tlsa_blocked_by(error)
        .map(|reason| format!(r#""{}""#, json_escape(reason)))
        .unwrap_or_else(|| "null".to_owned())
}

fn tlsa_blocked_by(error: Option<&GatewayError>) -> Option<&'static str> {
    match error {
        Some(GatewayError::Resolver(ResolverError::ProofUnavailable)) => {
            Some("local_hns_proof_unavailable")
        }
        Some(GatewayError::Resolver(ResolverError::LocalChainNotCurrent)) => {
            Some("local_chain_not_current")
        }
        Some(GatewayError::Resolver(ResolverError::NoNameserverAddress)) => {
            Some("no_verified_nameserver_address")
        }
        Some(GatewayError::Resolver(ResolverError::NonPublicDnsEndpoint)) => {
            Some("authoritative_nameserver_address_blocked")
        }
        Some(GatewayError::Resolver(ResolverError::UnsafeAuthoritativeDohPort(_))) => {
            Some("authoritative_nameserver_port_blocked")
        }
        Some(GatewayError::Resolver(ResolverError::DnsTransport(_))) => {
            Some("authoritative_nameserver_transport_failed")
        }
        Some(GatewayError::Resolver(ResolverError::DnsResponseCode(_))) => {
            Some("authoritative_nameserver_response_code")
        }
        Some(GatewayError::Resolver(ResolverError::InvalidDnsResponse)) => {
            Some("authoritative_nameserver_invalid_response")
        }
        Some(GatewayError::Resolver(ResolverError::DnssecFailed)) => {
            Some("delegated_dnssec_validation_failed")
        }
        Some(GatewayError::Resolver(ResolverError::InvalidResource(_))) => {
            Some("hns_resource_invalid")
        }
        Some(GatewayError::Resolver(ResolverError::InvalidAuthoritativeDoh)) => {
            Some("hns_authoritative_doh_invalid")
        }
        Some(GatewayError::Resolver(ResolverError::ProofNameMismatch)) => {
            Some("hns_proof_validation_failed")
        }
        Some(GatewayError::Resolver(ResolverError::UnsupportedBackend)) => {
            Some("resolver_backend_unsupported")
        }
        Some(GatewayError::Resolver(ResolverError::CachePoisoned))
        | Some(GatewayError::Resolver(ResolverError::Storage(_))) => {
            Some("resolver_storage_failed")
        }
        Some(GatewayError::NonLoopbackBind | GatewayError::EmptyAuthToken) => {
            Some("gateway_configuration_invalid")
        }
        Some(GatewayError::Unauthorized) => Some("gateway_authentication_failed"),
        Some(GatewayError::InsecureResolution) => Some("insecure_resolution"),
        Some(GatewayError::NoResolvedAddress) => Some("origin_address_missing"),
        Some(GatewayError::NonPublicOriginAddress) => Some("origin_address_blocked"),
        Some(GatewayError::UnsafeOriginPort(_)) => Some("origin_port_blocked"),
        Some(GatewayError::InvalidSvcb(_)) | Some(GatewayError::UnsupportedSvcb) => {
            Some("https_service_unsupported")
        }
        Some(GatewayError::HostResolutionMismatch) => Some("hns_request_mismatch"),
        Some(GatewayError::Transport(TransportError::UnsupportedTransport)) => {
            Some("transport_unsupported")
        }
        Some(GatewayError::Transport(TransportError::UnsupportedScheme)) => {
            Some("scheme_unsupported")
        }
        Some(GatewayError::Transport(error))
            if transport_certificate_failure_reason(error).is_some() =>
        {
            transport_certificate_failure_reason(error)
        }
        Some(GatewayError::Transport(TransportError::Tls(_))) => Some("tls_failed"),
        Some(GatewayError::Transport(TransportError::Io(_))) => Some("origin_transport_failed"),
        Some(GatewayError::Transport(TransportError::Http3(_))) => Some("http3_failed"),
        Some(GatewayError::Transport(TransportError::Quic(_))) => Some("quic_failed"),
        Some(GatewayError::Transport(TransportError::DaneFailed))
        | Some(GatewayError::InvalidTlsa(_)) => Some("dane_validation_failed"),
        Some(GatewayError::Transport(_)) => Some("origin_transport_failed"),
        Some(GatewayError::Resolver(ResolverError::NameNotFound))
        | Some(GatewayError::Resolver(ResolverError::InvalidName(_)))
        | None => None,
    }
}

fn transport_certificate_failure_reason(error: &TransportError) -> Option<&'static str> {
    let message = transport_error_message(error)?;
    if transport_certificate_message_is_expired(message) {
        return Some("origin_certificate_expired");
    }
    if message
        .to_ascii_lowercase()
        .contains("invalid peer certificate")
    {
        return Some("origin_certificate_invalid");
    }
    None
}

fn transport_certificate_expired(error: &TransportError) -> bool {
    transport_certificate_failure_reason(error) == Some("origin_certificate_expired")
}

fn transport_error_message(error: &TransportError) -> Option<&str> {
    match error {
        TransportError::Io(message)
        | TransportError::Tls(message)
        | TransportError::Http2(message)
        | TransportError::Http3(message)
        | TransportError::Quic(message) => Some(message),
        _ => None,
    }
}

fn transport_certificate_message_is_expired(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("certificate expired")
        || message.contains("certificate has expired")
        || message.contains("cert has expired")
        || message.contains("not valid after")
}

fn tls_mode_name(tls: &TlsValidation) -> &'static str {
    match tls.mode {
        hns_dane::DomainTrustMode::HnsStrict => "hns_strict",
        hns_dane::DomainTrustMode::HnsCompatibility => "hns_compatibility",
        hns_dane::DomainTrustMode::IcannWebPki => "icann_webpki",
    }
}

fn dane_trace_decision(
    dane_decision: Option<&DaneDecision>,
    error: Option<&GatewayError>,
) -> &'static str {
    match (dane_decision, error) {
        (Some(DaneDecision::Matched(_) | DaneDecision::StatelessMatched(_)), _) => "verified",
        (Some(DaneDecision::WebPkiFallback), _) => "webpki_fallback",
        (Some(DaneDecision::NoTlsa), _) => "no_tlsa",
        (Some(DaneDecision::Failed), _) => "failed",
        (_, Some(GatewayError::InvalidTlsa(_)))
        | (_, Some(GatewayError::Transport(TransportError::DaneFailed))) => "failed",
        _ => "not_evaluated",
    }
}

fn dane_certificate_match(
    dane_decision: Option<&DaneDecision>,
    error: Option<&GatewayError>,
) -> &'static str {
    match (dane_decision, error) {
        (Some(DaneDecision::Matched(_) | DaneDecision::StatelessMatched(_)), _) => "pass",
        (Some(DaneDecision::WebPkiFallback), _) => "webpki_valid",
        (Some(DaneDecision::NoTlsa), _) => "not_checked",
        (Some(DaneDecision::Failed), _) => "failed",
        (_, Some(GatewayError::InvalidTlsa(_)))
        | (_, Some(GatewayError::Transport(TransportError::DaneFailed))) => "failed",
        _ => "unknown",
    }
}

fn tlsa_records_json(records: &[TlsaRecord]) -> String {
    format!(
        "[{}]",
        records
            .iter()
            .map(tlsa_record_json)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn tlsa_record_json(record: &TlsaRecord) -> String {
    format!(
        r#"{{"usage":"{}","selector":"{}","matching":"{}","associationDataHex":"{}"}}"#,
        tlsa_usage_name(record.usage),
        tlsa_selector_name(record.selector),
        tlsa_matching_name(record.matching),
        hex_lower(&record.association_data),
    )
}

fn tlsa_usage_name(usage: TlsaUsage) -> &'static str {
    match usage {
        TlsaUsage::PkixTa => "PKIX-TA",
        TlsaUsage::PkixEe => "PKIX-EE",
        TlsaUsage::DaneTa => "DANE-TA",
        TlsaUsage::DaneEe => "DANE-EE",
    }
}

fn tlsa_selector_name(selector: TlsaSelector) -> &'static str {
    match selector {
        TlsaSelector::FullCertificate => "Cert",
        TlsaSelector::SubjectPublicKeyInfo => "SPKI",
    }
}

fn tlsa_matching_name(matching: TlsaMatching) -> &'static str {
    match matching {
        TlsaMatching::Exact => "Exact",
        TlsaMatching::Sha256 => "SHA-256",
        TlsaMatching::Sha512 => "SHA-512",
    }
}

fn dns_protocol_status(events: &[DnsTraceEvent], protocol: &str) -> String {
    let statuses = events
        .iter()
        .filter(|event| event.protocol == protocol)
        .map(|event| event.status.as_str())
        .collect::<Vec<_>>();
    if statuses.is_empty() {
        return "not_attempted".to_owned();
    }
    if statuses.contains(&"ok") {
        return "ok".to_owned();
    }
    if statuses.contains(&"timeout") {
        return "timeout".to_owned();
    }
    statuses.last().copied().unwrap_or("error").to_owned()
}

fn dns_trace_attempts_json(events: &[DnsTraceEvent]) -> String {
    events
        .iter()
        .map(|event| {
            let error = event
                .error
                .as_ref()
                .map(|error| format!(r#""{}""#, json_escape(error)))
                .unwrap_or_else(|| "null".to_owned());
            let question_name = event
                .question_name
                .as_ref()
                .map(|name| format!(r#""{}""#, json_escape(name)))
                .unwrap_or_else(|| "null".to_owned());
            let question_type = event
                .question_type
                .map(|record_type| record_type.to_string())
                .unwrap_or_else(|| "null".to_owned());
            format!(
                r#"{{"protocol":"{}","server":"{}","questionName":{},"questionType":{},"status":"{}","elapsedMs":{},"error":{}}}"#,
                event.protocol,
                json_escape(&event.server),
                question_name,
                question_type,
                json_escape(&event.status),
                event.elapsed_ms,
                error,
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn successful_dns_path<'a>(
    events: &'a [DnsTraceEvent],
    qname: &str,
    qtype: RecordType,
) -> Option<&'a str> {
    successful_dns_path_for_types(events, qname, &[qtype])
}

fn successful_dns_path_for_types<'a>(
    events: &'a [DnsTraceEvent],
    qname: &str,
    qtypes: &[RecordType],
) -> Option<&'a str> {
    let qname = qname.trim_end_matches('.');
    events
        .iter()
        .rev()
        .find(|event| {
            event.status == "ok"
                && event
                    .question_type
                    .is_some_and(|code| qtypes.iter().any(|qtype| qtype.code() == code))
                && event
                    .question_name
                    .as_deref()
                    .is_some_and(|name| name.trim_end_matches('.').eq_ignore_ascii_case(qname))
        })
        .map(|event| event.protocol)
}

fn security_path_name(
    input: &GatewayHttpRequestInput<'_>,
    effective_port: u16,
    decision: &DaneDecision,
    events: &[DnsTraceEvent],
) -> Option<&'static str> {
    match decision {
        DaneDecision::StatelessMatched(_) => return Some("stateless-dane"),
        DaneDecision::Matched(_) => {
            let owner = tlsa_owner_name(input.host, effective_port);
            return match successful_dns_path(events, &owner, RecordType::Tlsa) {
                Some("authoritative_doh") => Some("dane-authoritative-doh"),
                Some("udp53" | "tcp53") => Some("dane-authoritative-dns53"),
                Some("hns_doh") => Some("dane-third-party-doh"),
                Some("icann_doh") => Some("dane-icann-doh"),
                _ => None,
            };
        }
        DaneDecision::WebPkiFallback | DaneDecision::Failed => return None,
        DaneDecision::NoTlsa => {}
    }

    if !input.scheme.eq_ignore_ascii_case("http") && !input.scheme.eq_ignore_ascii_case("ws") {
        return None;
    }
    match successful_dns_path_for_types(events, input.host, &[RecordType::A, RecordType::Aaaa]) {
        Some("authoritative_doh") => Some("hns-authoritative-doh"),
        Some("udp53" | "tcp53") => Some("hns-authoritative-dns53"),
        Some("hns_doh") => Some("hns-third-party-doh"),
        _ => None,
    }
}

fn nameserver_candidates_json(events: &[DnsTraceEvent]) -> String {
    let servers = events
        .iter()
        .filter(|event| matches!(event.protocol, "udp53" | "tcp53" | "authoritative_doh"))
        .map(|event| event.server.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    format!(
        "[{}]",
        servers
            .into_iter()
            .map(|server| format!(r#""{}""#, json_escape(server)))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn dnssec_trace_status(
    resolution: Option<&ResolutionAnswer>,
    error: Option<&GatewayError>,
) -> &'static str {
    if matches!(
        error,
        Some(GatewayError::Resolver(ResolverError::DnssecFailed))
    ) {
        "bogus"
    } else if resolution.map(|answer| answer.secure).unwrap_or(false) {
        "secure"
    } else if resolution.is_some() {
        "unsigned"
    } else {
        "unknown"
    }
}

fn hns_trace_root(host: &str) -> String {
    host.trim()
        .trim_end_matches('.')
        .rsplit('.')
        .next()
        .unwrap_or(host)
        .to_owned()
}

#[cfg(test)]
fn hns_proof_details(data_dir: &str, host_or_url: &str) -> String {
    hns_proof_details_for_network(data_dir, host_or_url, NetworkKind::Mainnet)
}

pub fn hns_proof_details_for_network(
    data_dir: &str,
    host_or_url: &str,
    network: NetworkKind,
) -> String {
    let (host, root_name) = match hns_proof_host_and_root(host_or_url) {
        Ok(value) => value,
        Err(error) => return hns_proof_details_error_json(host_or_url, &error),
    };
    let name_hash = match NameHash::from_name(&root_name) {
        Ok(value) => value,
        Err(error) => {
            return hns_proof_details_base_json(HnsProofDetailsJson {
                host: &host,
                root_name: &root_name,
                name_hash: None,
                proof_status: "failed",
                cache_status: "invalid_name",
                anchor: None,
                secure: None,
                exists: None,
                records: Vec::new(),
                raw_resource: None,
                current_tip_base: None,
                network,
                error: &format!("invalid HNS name: {error}"),
            });
        }
    };

    let base = network_base_path(data_dir, network);
    let resources_path = base.join("resources.sqlite");
    if !resources_path.exists() {
        return hns_proof_details_base_json(HnsProofDetailsJson {
            host: &host,
            root_name: &root_name,
            name_hash: Some(name_hash),
            proof_status: "unavailable",
            cache_status: "resource_cache_missing",
            anchor: None,
            secure: None,
            exists: None,
            records: Vec::new(),
            raw_resource: None,
            current_tip_base: Some(&base),
            network,
            error: "resource cache is not initialized",
        });
    }

    let provider = match SqliteResourceValueProvider::open(resources_path) {
        Ok(value) => value,
        Err(error) => {
            return hns_proof_details_base_json(HnsProofDetailsJson {
                host: &host,
                root_name: &root_name,
                name_hash: Some(name_hash),
                proof_status: "error",
                cache_status: "resource_cache_open_failed",
                anchor: None,
                secure: None,
                exists: None,
                records: Vec::new(),
                raw_resource: None,
                current_tip_base: Some(&base),
                network,
                error: &format!("open resource cache: {error}"),
            });
        }
    };

    let verified = match provider.prove_resource_value(&root_name, name_hash) {
        Ok(value) => value,
        Err(ResolverError::ProofUnavailable) => {
            return hns_proof_details_base_json(HnsProofDetailsJson {
                host: &host,
                root_name: &root_name,
                name_hash: Some(name_hash),
                proof_status: "unavailable",
                cache_status: "not_cached",
                anchor: None,
                secure: None,
                exists: None,
                records: Vec::new(),
                raw_resource: None,
                current_tip_base: Some(&base),
                network,
                error: "no cached proof is available for this HNS root",
            });
        }
        Err(error) => {
            return hns_proof_details_base_json(HnsProofDetailsJson {
                host: &host,
                root_name: &root_name,
                name_hash: Some(name_hash),
                proof_status: "error",
                cache_status: "proof_read_failed",
                anchor: None,
                secure: None,
                exists: None,
                records: Vec::new(),
                raw_resource: None,
                current_tip_base: Some(&base),
                network,
                error: &error.to_string(),
            });
        }
    };

    let raw_resource = verified.value.as_deref();
    let records = match ProvenNameRecords::from_verified_resource_value(verified.clone()) {
        Ok(proven) => proven.records,
        Err(error) => {
            return hns_proof_details_base_json(HnsProofDetailsJson {
                host: &host,
                root_name: &root_name,
                name_hash: Some(name_hash),
                proof_status: "invalid_resource",
                cache_status: &proof_cache_status(&base, network, verified.anchor),
                anchor: verified.anchor,
                secure: Some(verified.secure),
                exists: Some(verified.value.is_some()),
                records: Vec::new(),
                raw_resource,
                current_tip_base: Some(&base),
                network,
                error: &format!("decode resource records: {error}"),
            });
        }
    };
    let status = match (verified.secure, verified.value.is_some()) {
        (false, _) => "failed",
        (true, false) => "not_found",
        (true, true) => "verified",
    };

    hns_proof_details_base_json(HnsProofDetailsJson {
        host: &host,
        root_name: &root_name,
        name_hash: Some(name_hash),
        proof_status: status,
        cache_status: &proof_cache_status(&base, network, verified.anchor),
        anchor: verified.anchor,
        secure: Some(verified.secure),
        exists: Some(verified.value.is_some()),
        records,
        raw_resource,
        current_tip_base: Some(&base),
        network,
        error: "",
    })
}

fn hns_proof_host_and_root(host_or_url: &str) -> Result<(String, String), String> {
    let mut value = host_or_url.trim();
    if let Some(rest) = value.strip_prefix("https://") {
        value = rest;
    } else if let Some(rest) = value.strip_prefix("http://") {
        value = rest;
    }
    let authority = value
        .split(&['/', '?', '#'][..])
        .next()
        .unwrap_or(value)
        .trim();
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => host,
        _ => authority,
    }
    .trim_end_matches('.')
    .to_ascii_lowercase();
    if host.is_empty() {
        return Err("missing HNS host".to_owned());
    }
    let root = hns_trace_root(&host).to_ascii_lowercase();
    if root.is_empty() {
        return Err("missing HNS root".to_owned());
    }
    Ok((host, root))
}

pub fn hns_proof_details_error_json(host_or_url: &str, error: &str) -> String {
    format!(
        r#"{{"host":"{}","name":null,"nameHash":null,"hnsProof":"error","proofStatus":"error","secure":null,"exists":null,"treeRoot":null,"blockHeight":null,"cacheStatus":"invalid_input","resourceValueHex":null,"recordTypes":[],"resourceRecords":[],"currentTip":null,"error":"{}"}}"#,
        json_escape(host_or_url),
        json_escape(error),
    )
}

struct HnsProofDetailsJson<'a> {
    host: &'a str,
    root_name: &'a str,
    name_hash: Option<NameHash>,
    proof_status: &'a str,
    cache_status: &'a str,
    anchor: Option<ResourceValueAnchor>,
    secure: Option<bool>,
    exists: Option<bool>,
    records: Vec<ResourceRecord>,
    raw_resource: Option<&'a [u8]>,
    current_tip_base: Option<&'a Path>,
    network: NetworkKind,
    error: &'a str,
}

fn hns_proof_details_base_json(details: HnsProofDetailsJson<'_>) -> String {
    let name_hash = details
        .name_hash
        .map(|value| format!(r#""{}""#, value.as_hash()))
        .unwrap_or_else(|| "null".to_owned());
    let tree_root = details
        .anchor
        .map(|value| format!(r#""{}""#, value.tree_root))
        .unwrap_or_else(|| "null".to_owned());
    let block_height = details
        .anchor
        .map(|value| value.height.0.to_string())
        .unwrap_or_else(|| "null".to_owned());
    let secure = json_bool_or_null(details.secure);
    let exists = json_bool_or_null(details.exists);
    let raw_resource = details
        .raw_resource
        .map(|value| format!(r#""{}""#, hex_lower(value)))
        .unwrap_or_else(|| "null".to_owned());
    let record_types = record_types_json(&details.records);
    let records_json = resource_records_json(&details.records);
    let current_tip = details
        .current_tip_base
        .map(|base| current_tip_json(base, details.network))
        .unwrap_or_else(|| "null".to_owned());
    let error = if details.error.is_empty() {
        "null".to_owned()
    } else {
        format!(r#""{}""#, json_escape(details.error))
    };

    format!(
        r#"{{"host":"{}","name":"{}","network":"{}","nameHash":{},"hnsProof":"{}","proofStatus":"{}","secure":{},"exists":{},"treeRoot":{},"blockHeight":{},"cacheStatus":"{}","resourceValueHex":{},"recordTypes":{},"resourceRecords":{},"currentTip":{},"error":{}}}"#,
        json_escape(details.host),
        json_escape(details.root_name),
        details.network.as_str(),
        name_hash,
        json_escape(details.proof_status),
        json_escape(details.proof_status),
        secure,
        exists,
        tree_root,
        block_height,
        json_escape(details.cache_status),
        raw_resource,
        record_types,
        records_json,
        current_tip,
        error,
    )
}

fn proof_cache_status(
    base: &Path,
    network: NetworkKind,
    anchor: Option<ResourceValueAnchor>,
) -> String {
    match (anchor, best_synced_header(base, network).ok()) {
        (None, _) => "no_anchor".to_owned(),
        (Some(anchor), Some(best))
            if anchor.height == best.height && anchor.tree_root == best.header.tree_root =>
        {
            "anchored_to_current_tip".to_owned()
        }
        (Some(_), Some(_)) => "anchored_to_height".to_owned(),
        (Some(_), None) => "anchored_no_current_tip".to_owned(),
    }
}

fn current_tip_json(base: &Path, network: NetworkKind) -> String {
    match best_synced_header(base, network) {
        Ok(best) => format!(
            r#"{{"height":{},"treeRoot":"{}"}}"#,
            best.height.0, best.header.tree_root,
        ),
        Err(_) => "null".to_owned(),
    }
}

fn json_bool_or_null(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "null",
    }
}

fn record_types_json(records: &[ResourceRecord]) -> String {
    let values = records
        .iter()
        .map(|record| record_type_name(&record.record_type))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|record_type| format!(r#""{}""#, json_escape(record_type)))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{values}]")
}

fn resource_records_json(records: &[ResourceRecord]) -> String {
    format!(
        "[{}]",
        records
            .iter()
            .map(resource_record_json)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn resource_record_json(record: &ResourceRecord) -> String {
    format!(
        r#"{{"name":"{}","type":"{}","class":{},"ttl":{},"rdataHex":"{}"}}"#,
        json_escape(&record.name.to_string()),
        json_escape(record_type_name(&record.record_type)),
        record.class,
        record.ttl,
        hex_lower(&record.rdata),
    )
}

fn hex_lower(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(value.len() * 2);
    for byte in value {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn record_type_name(record_type: &RecordType) -> &'static str {
    match record_type {
        RecordType::A => "A",
        RecordType::Aaaa => "AAAA",
        RecordType::Ns => "NS",
        RecordType::Ds => "DS",
        RecordType::Txt => "TXT",
        RecordType::Soa => "SOA",
        RecordType::Srv => "SRV",
        RecordType::Rrsig => "RRSIG",
        RecordType::Nsec => "NSEC",
        RecordType::Dnskey => "DNSKEY",
        RecordType::Nsec3 => "NSEC3",
        RecordType::Tlsa => "TLSA",
        RecordType::Svcb => "SVCB",
        RecordType::Https => "HTTPS",
        RecordType::Cname => "CNAME",
        RecordType::Unknown(1) => "GLUE4",
        RecordType::Unknown(2) => "GLUE6",
        RecordType::Unknown(6) => "SYNTH4",
        RecordType::Unknown(7) => "SYNTH6",
        RecordType::Unknown(_) => "UNKNOWN",
    }
}

fn trace_mode(trace_json: &str) -> &'static str {
    if trace_json.contains(r#""mode":"strict""#) {
        "strict"
    } else {
        "compatibility"
    }
}

fn trace_doh_fallback(trace_json: &str) -> &'static str {
    if trace_json.contains(r#""used":true"#) {
        "yes"
    } else {
        "no"
    }
}

fn hns_tls_policy_header(decision: &DaneDecision) -> Option<&'static str> {
    match decision {
        DaneDecision::Matched(_) | DaneDecision::StatelessMatched(_) => Some("dane"),
        DaneDecision::WebPkiFallback => Some("webpki-fallback"),
        DaneDecision::Failed => Some("failed"),
        DaneDecision::NoTlsa => None,
    }
}

fn map_gateway_error_for_host(
    host: &str,
    error: &GatewayError,
) -> (u16, &'static str, &'static str) {
    if classify_name(host) == NameClass::Icann {
        match error {
            GatewayError::Resolver(ResolverError::DnsTransport(_)) => (
                502,
                "ICANN DNS Unavailable",
                "Trusted ICANN DNS resolver transport failed closed.",
            ),
            GatewayError::Resolver(ResolverError::DnsResponseCode(_)) => (
                502,
                "ICANN DNS Response Code",
                "Trusted ICANN DNS resolver returned a DNS failure response code.",
            ),
            GatewayError::Resolver(ResolverError::InvalidDnsResponse) => (
                502,
                "ICANN DNS Response Invalid",
                "Trusted ICANN DNS resolver returned an invalid response.",
            ),
            GatewayError::Resolver(ResolverError::DnssecFailed)
            | GatewayError::InsecureResolution => (
                502,
                "ICANN DNSSEC Validation Failed",
                "Secure ICANN DNS resolution was required but validation failed closed.",
            ),
            GatewayError::NoResolvedAddress => (
                502,
                "ICANN Origin Address Missing",
                "Secure ICANN DNS resolution did not produce an origin A or AAAA address.",
            ),
            GatewayError::NonPublicOriginAddress => (
                403,
                "ICANN Origin Address Blocked",
                "Native gateway policy blocked a non-public origin address.",
            ),
            GatewayError::UnsafeOriginPort(_) => (
                403,
                "ICANN Origin Port Blocked",
                "Native gateway policy blocked a browser-unsafe origin port.",
            ),
            GatewayError::InvalidTlsa(_) | GatewayError::Transport(TransportError::DaneFailed) => (
                502,
                "ICANN DANE Validation Failed",
                "ICANN DANE/TLSA validation failed closed.",
            ),
            GatewayError::InvalidSvcb(_) | GatewayError::UnsupportedSvcb => (
                502,
                "ICANN HTTPS Service Unsupported",
                "HTTPS/SVCB service binding is malformed or requires unsupported transport policy.",
            ),
            GatewayError::HostResolutionMismatch => (
                400,
                "ICANN Request Mismatch",
                "Origin host does not match the resolved ICANN name.",
            ),
            GatewayError::Transport(TransportError::UnsupportedTransport) => (
                501,
                "ICANN Transport Unsupported",
                "Requested ICANN origin transport is not available.",
            ),
            GatewayError::Transport(TransportError::UnsupportedScheme) => (
                501,
                "ICANN Scheme Unsupported",
                "Requested ICANN origin scheme is not available.",
            ),
            GatewayError::Transport(error) if transport_certificate_expired(error) => (
                502,
                "ICANN Origin Certificate Expired",
                "Origin HTTPS certificate is expired; renew the certificate and retry.",
            ),
            GatewayError::Transport(TransportError::Tls(_)) => (
                502,
                "ICANN TLS Failed",
                "Origin TLS negotiation failed closed.",
            ),
            GatewayError::Transport(TransportError::InvalidRequest) => (
                400,
                "ICANN Origin Request Invalid",
                "Origin request could not be safely forwarded.",
            ),
            GatewayError::Transport(TransportError::RequestTooLarge) => (
                413,
                "ICANN Origin Request Too Large",
                "Origin request body exceeds the configured gateway limit.",
            ),
            GatewayError::Transport(TransportError::UnsupportedTransferEncoding)
            | GatewayError::Transport(TransportError::MalformedResponse) => (
                502,
                "ICANN Origin Response Invalid",
                "Origin HTTP response framing failed closed.",
            ),
            GatewayError::Transport(TransportError::UnsupportedUpgrade) => (
                501,
                "ICANN Protocol Upgrade Unsupported",
                "ICANN WebSocket/HTTP Upgrade must use the native tunnel path and the request failed validation.",
            ),
            GatewayError::Transport(TransportError::ResponseTooLarge) => (
                502,
                "ICANN Origin Response Too Large",
                "Origin response exceeds the configured gateway limit.",
            ),
            GatewayError::Transport(TransportError::Io(_)) => (
                502,
                "ICANN Origin Transport Failed",
                "Origin connection failed closed.",
            ),
            GatewayError::Transport(TransportError::Http2(_)) => (
                502,
                "ICANN HTTP/2 Transport Failed",
                "Origin HTTP/2 exchange failed closed.",
            ),
            GatewayError::Transport(TransportError::Http3(_)) => (
                502,
                "ICANN HTTP/3 Transport Failed",
                "Origin HTTP/3 exchange failed closed.",
            ),
            GatewayError::Transport(TransportError::Quic(_)) => (
                502,
                "ICANN QUIC Transport Failed",
                "Origin QUIC connection failed closed.",
            ),
            _ => map_gateway_error(error),
        }
    } else {
        map_gateway_error(error)
    }
}

fn map_gateway_error(error: &GatewayError) -> (u16, &'static str, &'static str) {
    match error {
        GatewayError::Resolver(ResolverError::UnsupportedBackend) => (
            503,
            "HNS Resolution Unavailable",
            "Rust HNS resolver backend is not ready.",
        ),
        GatewayError::Resolver(ResolverError::ProofUnavailable) => (
            503,
            "HNS Proof Unavailable",
            "No current verified HNS proof is available for this name.",
        ),
        GatewayError::Resolver(ResolverError::NameNotFound) => (
            404,
            "HNS Name Not Found",
            "A verified HNS non-inclusion proof says this name does not exist.",
        ),
        GatewayError::Resolver(ResolverError::LocalChainNotCurrent) => (
            503,
            "HNS Sync Incomplete",
            "The local HNS chain is not current enough to determine this name's current state.",
        ),
        GatewayError::Resolver(ResolverError::NoNameserverAddress) => (
            502,
            "HNS Nameserver Unavailable",
            "No verified nameserver address is available for this HNS delegation.",
        ),
        GatewayError::Resolver(ResolverError::NonPublicDnsEndpoint) => (
            403,
            "HNS Nameserver Address Blocked",
            "Native gateway policy blocked a non-public delegated nameserver address.",
        ),
        GatewayError::Resolver(ResolverError::UnsafeAuthoritativeDohPort(_)) => (
            403,
            "HNS Nameserver Port Blocked",
            "Native gateway policy blocked an unsafe delegated authoritative DoH port.",
        ),
        GatewayError::Resolver(ResolverError::DnsTransport(_)) => (
            502,
            "HNS Nameserver Unavailable",
            "Delegated HNS nameserver transport failed closed.",
        ),
        GatewayError::Resolver(ResolverError::DnsResponseCode(_)) => (
            502,
            "HNS Nameserver Response Code",
            "Delegated HNS nameserver returned a DNS failure response code.",
        ),
        GatewayError::Resolver(ResolverError::InvalidDnsResponse) => (
            502,
            "HNS Nameserver Response Invalid",
            "Delegated HNS nameserver response was invalid or lacked required secure denial data.",
        ),
        GatewayError::Resolver(ResolverError::DnssecFailed) => (
            502,
            "HNS DNSSEC Validation Failed",
            "Delegated HNS DNSSEC validation failed closed.",
        ),
        GatewayError::Resolver(ResolverError::InvalidName(_)) => {
            (400, "HNS Name Invalid", "Requested HNS name is invalid.")
        }
        GatewayError::Resolver(ResolverError::InvalidResource(_)) => (
            502,
            "HNS Resource Invalid",
            "Verified HNS resource data is malformed or unsupported.",
        ),
        GatewayError::Resolver(ResolverError::InvalidAuthoritativeDoh) => (
            502,
            "HNS Authoritative DoH Invalid",
            "Verified HNS authoritative DoH discovery data is malformed or unsupported.",
        ),
        GatewayError::Resolver(ResolverError::ProofNameMismatch) => (
            502,
            "HNS Proof Validation Failed",
            "HNS proof validation failed closed.",
        ),
        GatewayError::InsecureResolution => (
            502,
            "HNS DNSSEC Validation Failed",
            "Secure HNS resolution was required but the resolver returned an insecure result.",
        ),
        GatewayError::NoResolvedAddress => (
            502,
            "HNS Origin Address Missing",
            "Secure HNS resolution did not produce an origin A or AAAA address.",
        ),
        GatewayError::NonPublicOriginAddress => (
            403,
            "HNS Origin Address Blocked",
            "Native gateway policy blocked a non-public origin address.",
        ),
        GatewayError::UnsafeOriginPort(_) => (
            403,
            "HNS Origin Port Blocked",
            "Native gateway policy blocked a browser-unsafe origin port.",
        ),
        GatewayError::Unauthorized => (
            403,
            "HNS Gateway Authentication Failed",
            "Local gateway authentication failed closed.",
        ),
        GatewayError::InvalidTlsa(_) | GatewayError::Transport(TransportError::DaneFailed) => (
            502,
            "HNS DANE Validation Failed",
            "DANE/TLSA validation failed closed.",
        ),
        GatewayError::InvalidSvcb(_) | GatewayError::UnsupportedSvcb => (
            502,
            "HNS HTTPS Service Unsupported",
            "HTTPS/SVCB service binding is malformed or requires unsupported transport policy.",
        ),
        GatewayError::HostResolutionMismatch => (
            400,
            "HNS Request Mismatch",
            "Origin host does not match the HNS resolution name.",
        ),
        GatewayError::Transport(TransportError::UnsupportedTransport) => (
            501,
            "HNS Transport Unsupported",
            "Requested HNS origin transport is not available.",
        ),
        GatewayError::Transport(TransportError::UnsupportedScheme) => (
            501,
            "HNS Scheme Unsupported",
            "Requested HNS origin scheme is not available.",
        ),
        GatewayError::Transport(error) if transport_certificate_expired(error) => (
            502,
            "HNS Origin Certificate Expired",
            "Origin HTTPS certificate is expired; renew the certificate and retry.",
        ),
        GatewayError::Transport(TransportError::Tls(_)) => (
            502,
            "HNS TLS Failed",
            "Origin TLS negotiation failed closed.",
        ),
        GatewayError::Transport(TransportError::InvalidRequest) => (
            400,
            "HNS Origin Request Invalid",
            "Origin request could not be safely forwarded.",
        ),
        GatewayError::Transport(TransportError::RequestTooLarge) => (
            413,
            "HNS Origin Request Too Large",
            "Origin request body exceeds the configured gateway limit.",
        ),
        GatewayError::Transport(TransportError::UnsupportedTransferEncoding)
        | GatewayError::Transport(TransportError::MalformedResponse) => (
            502,
            "HNS Origin Response Invalid",
            "Origin HTTP response framing failed closed.",
        ),
        GatewayError::Transport(TransportError::UnsupportedUpgrade) => (
            501,
            "HNS Protocol Upgrade Unsupported",
            "HNS WebSocket/HTTP Upgrade must use the native tunnel path and the request failed validation.",
        ),
        GatewayError::Transport(TransportError::ResponseTooLarge) => (
            502,
            "HNS Origin Response Too Large",
            "Origin response exceeds the configured gateway limit.",
        ),
        GatewayError::Transport(TransportError::Io(_)) => (
            502,
            "HNS Origin Transport Failed",
            "Origin connection failed closed.",
        ),
        GatewayError::Transport(TransportError::Http2(_)) => (
            502,
            "HNS HTTP/2 Transport Failed",
            "Origin HTTP/2 exchange failed closed.",
        ),
        GatewayError::Transport(TransportError::Http3(_)) => (
            502,
            "HNS HTTP/3 Transport Failed",
            "Origin HTTP/3 exchange failed closed.",
        ),
        GatewayError::Transport(TransportError::Quic(_)) => (
            502,
            "HNS QUIC Transport Failed",
            "Origin QUIC connection failed closed.",
        ),
        GatewayError::Resolver(ResolverError::CachePoisoned)
        | GatewayError::Resolver(ResolverError::Storage(_))
        | GatewayError::NonLoopbackBind
        | GatewayError::EmptyAuthToken => (
            500,
            "HNS Gateway Storage Error",
            "Local HNS gateway state is unavailable.",
        ),
    }
}

fn plain_response_for_request(
    input: &GatewayHttpRequestInput<'_>,
    status: u16,
    reason: &str,
    detail: &str,
) -> Vec<u8> {
    let address = gateway_request_address(input);
    plain_response_with_address(status, reason, detail, Some(&address))
}

fn plain_response_for_request_with_trace(
    input: &GatewayHttpRequestInput<'_>,
    status: u16,
    reason: &str,
    detail: &str,
    trace_json: &str,
) -> Vec<u8> {
    let address = gateway_request_address(input);
    plain_response_with_address_and_trace(status, reason, detail, Some(&address), trace_json)
}

pub fn plain_response_with_address(
    status: u16,
    reason: &str,
    detail: &str,
    address: Option<&str>,
) -> Vec<u8> {
    plain_response_with_address_and_optional_trace(status, reason, detail, address, None)
}

fn plain_response_with_address_and_trace(
    status: u16,
    reason: &str,
    detail: &str,
    address: Option<&str>,
    trace_json: &str,
) -> Vec<u8> {
    plain_response_with_address_and_optional_trace(
        status,
        reason,
        detail,
        address,
        Some(trace_json),
    )
}

fn plain_response_with_address_and_optional_trace(
    status: u16,
    reason: &str,
    detail: &str,
    address: Option<&str>,
    trace_json: Option<&str>,
) -> Vec<u8> {
    let body = plain_response_body(status, reason, detail, address);
    let mut out = response_head(
        status,
        reason,
        Some("text/plain; charset=utf-8"),
        body.len(),
    );
    if let Some(trace_json) = trace_json {
        out.extend(
            format!("{HNS_RESOLVER_MODE_HEADER}: {}\r\n", trace_mode(trace_json)).as_bytes(),
        );
        out.extend(
            format!(
                "{HNS_DOH_FALLBACK_HEADER}: {}\r\n",
                trace_doh_fallback(trace_json)
            )
            .as_bytes(),
        );
        out.extend(format!("{HNS_RESOLUTION_TRACE_HEADER}: {trace_json}\r\n").as_bytes());
    }
    out.extend(b"\r\n");
    out.extend(body);
    out
}

fn plain_response_to_file_for_request(
    input: &GatewayHttpRequestInput<'_>,
    status: u16,
    reason: &str,
    detail: &str,
    body_path: &Path,
) -> Result<Vec<u8>, String> {
    let address = gateway_request_address(input);
    plain_response_to_file_with_address(status, reason, detail, Some(&address), body_path)
}

fn plain_response_to_file_for_request_with_trace(
    input: &GatewayHttpRequestInput<'_>,
    status: u16,
    reason: &str,
    detail: &str,
    body_path: &Path,
    trace_json: &str,
) -> Result<Vec<u8>, String> {
    let address = gateway_request_address(input);
    plain_response_to_file_with_address_and_trace(
        status,
        reason,
        detail,
        Some(&address),
        body_path,
        trace_json,
    )
}

pub fn plain_response_to_file_with_address(
    status: u16,
    reason: &str,
    detail: &str,
    address: Option<&str>,
    body_path: &Path,
) -> Result<Vec<u8>, String> {
    plain_response_to_file_with_address_and_optional_trace(
        status, reason, detail, address, body_path, None,
    )
}

fn plain_response_to_file_with_address_and_trace(
    status: u16,
    reason: &str,
    detail: &str,
    address: Option<&str>,
    body_path: &Path,
    trace_json: &str,
) -> Result<Vec<u8>, String> {
    plain_response_to_file_with_address_and_optional_trace(
        status,
        reason,
        detail,
        address,
        body_path,
        Some(trace_json),
    )
}

fn plain_response_to_file_with_address_and_optional_trace(
    status: u16,
    reason: &str,
    detail: &str,
    address: Option<&str>,
    body_path: &Path,
    trace_json: Option<&str>,
) -> Result<Vec<u8>, String> {
    let body = plain_response_body(status, reason, detail, address);
    if let Some(parent) = body_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create response directory: {error}"))?;
    }
    fs::write(body_path, &body).map_err(|error| format!("write response body: {error}"))?;
    let mut out = response_head(
        status,
        reason,
        Some("text/plain; charset=utf-8"),
        body.len(),
    );
    if let Some(trace_json) = trace_json {
        out.extend(
            format!("{HNS_RESOLVER_MODE_HEADER}: {}\r\n", trace_mode(trace_json)).as_bytes(),
        );
        out.extend(
            format!(
                "{HNS_DOH_FALLBACK_HEADER}: {}\r\n",
                trace_doh_fallback(trace_json)
            )
            .as_bytes(),
        );
        out.extend(format!("{HNS_RESOLUTION_TRACE_HEADER}: {trace_json}\r\n").as_bytes());
    }
    out.extend(b"\r\n");
    Ok(out)
}

fn plain_response_body(status: u16, reason: &str, detail: &str, address: Option<&str>) -> Vec<u8> {
    match address {
        Some(address) => format!("{address}\n{status} {reason}\n{detail}\n").into_bytes(),
        None => format!("{status} {reason}\n{detail}\n").into_bytes(),
    }
}

fn gateway_request_address(input: &GatewayHttpRequestInput<'_>) -> String {
    let scheme = input.scheme.to_ascii_lowercase();
    let port = match (scheme.as_str(), input.port) {
        ("http" | "ws", 80) | ("https" | "wss", 443) => String::new(),
        (_, port) => format!(":{port}"),
    };
    let path = if input.path_and_query.is_empty() {
        "/"
    } else {
        input.path_and_query
    };
    format!("{scheme}://{}{}{}", input.host, port, path)
}

fn response_head(
    status: u16,
    reason: &str,
    content_type: Option<&str>,
    body_len: usize,
) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Length: {body_len}\r\n"
    )
    .into_bytes();
    if let Some(content_type) = content_type {
        out.extend(format!("Content-Type: {content_type}\r\n").as_bytes());
    }
    out
}

fn run_sync_once(
    data_dir: &str,
    network_kind: NetworkKind,
    seed_on_empty: bool,
    timeout: Duration,
    resource_cache_limit_bytes: usize,
) -> Result<NativeSyncStatus, String> {
    let base = network_base_path(data_dir, network_kind);
    let chain = open_initialized_header_chain(&base, network_kind)?;
    let mut coordinator = HeaderSyncCoordinator::new(chain);

    let peer_store = SqlitePeerStore::open(base.join("peers.sqlite"))
        .map_err(|error| format!("open peer store: {error}"))?;
    let mut peers = peer_store
        .load_manager()
        .map_err(|error| format!("load peer store: {error}"))?;
    let network = network_kind.network();
    let pruned_peers = retain_allowed_peer_endpoints(&mut peers, &network);
    if pruned_peers > 0 {
        peer_store
            .save_manager(&peers)
            .map_err(|error| format!("save pruned peer store: {error}"))?;
    }
    let mut seed_error = None;
    if seed_on_empty && allowed_peer_count(&peers, &network) < ANDROID_MIN_PEER_TARGET {
        let was_empty = allowed_peer_count(&peers, &network) == 0;
        match seed_peers_for_network(&mut peers, &network, network_kind) {
            Ok(inserted) => {
                if inserted > 0 {
                    peer_store
                        .save_manager(&peers)
                        .map_err(|error| format!("save seeded peers: {error}"))?;
                }
            }
            Err(error) => {
                if was_empty {
                    seed_error = Some(error.to_string());
                }
            }
        }
    }

    let runner = HeaderSyncRunner::with_config(
        network,
        TcpHeaderPeerConnector,
        HeaderSyncRunnerConfig {
            preferred_peers: ANDROID_HEADER_SYNC_PEERS,
            max_header_batches_per_peer: ANDROID_HEADER_SYNC_BATCHES_PER_PEER,
            peer_discovery_target: ANDROID_MIN_PEER_TARGET,
            parallel_peer_probes: ANDROID_PARALLEL_PEER_PROBES,
            parallel_header_fetch_peers: ANDROID_PARALLEL_HEADER_FETCH_PEERS,
            peer_height_refresh_interval: ANDROID_PEER_HEIGHT_REFRESH_INTERVAL_SECONDS,
            checkpoint_header_prefetch: sync_checkpoints_for_network(network_kind),
            timeout,
            ..HeaderSyncRunnerConfig::default()
        },
    );
    let result = runner
        .sync_once_parallel_and_persist(
            &mut coordinator,
            &mut peers,
            &peer_store,
            now_unix_seconds(),
        )
        .map_err(|error| format!("sync headers: {error}"))?;
    let best = coordinator
        .chain()
        .best_header()
        .map_err(|error| format!("read synced best header: {error}"))?;
    let now = now_unix_seconds();
    let peer_count = peers.len();
    let peer_groups = peers.address_group_count(now);
    let best_peer_height = best_peer_height(&peers);
    let best_height = best.as_ref().map(|header| header.height.0);
    let estimated_tip_height = estimated_tip_height_for_network(network_kind, now);
    let resource_cache_evicted =
        prune_resource_cache_to_best_chain(&base, coordinator.chain())?.saturating_add(
            enforce_resource_cache_limit(&base, resource_cache_limit_bytes)?,
        );
    let (resource_cache_entries, resource_cache_bytes) = resource_cache_stats(&base)?;
    let failed = result.failures.len();
    let status = classify_sync_status(
        result.attempted,
        result.successful,
        result.accepted,
        failed,
        seed_error.is_some(),
        best_height,
        best_peer_height,
    );
    let error = if status == "peer_failed" {
        Some(format!(
            "all {} attempted sync peers failed; see failures",
            result.attempted,
        ))
    } else {
        seed_error
    };

    Ok(NativeSyncStatus {
        network: network_kind,
        status,
        attempted: result.attempted,
        successful: result.successful,
        accepted: result.accepted,
        failed,
        peer_count,
        peer_groups,
        best_height,
        best_peer_height,
        estimated_tip_height,
        resource_cache_entries,
        resource_cache_bytes,
        resource_cache_evicted,
        error,
        failures: result
            .failures
            .into_iter()
            .map(|failure| NativePeerFailure {
                address: failure.address.to_string(),
                stage: failure.stage.as_str(),
                error: failure.error,
            })
            .collect(),
    })
}

fn classify_sync_status(
    attempted: usize,
    successful: usize,
    accepted: usize,
    failed: usize,
    seed_failed: bool,
    best_height: Option<u32>,
    best_peer_height: Option<u32>,
) -> &'static str {
    if successful > 0 && accepted > 0 {
        if is_sync_behind(best_height, best_peer_height)
            || is_sync_target_unknown(best_height, best_peer_height)
        {
            "syncing"
        } else {
            "synced"
        }
    } else if successful > 0 {
        if is_sync_behind(best_height, best_peer_height) {
            "syncing"
        } else {
            "up_to_date"
        }
    } else if attempted > 0 && failed == attempted {
        "peer_failed"
    } else if attempted > 0 {
        "attempted"
    } else if seed_failed {
        "seed_failed"
    } else {
        "idle"
    }
}

fn is_sync_behind(best_height: Option<u32>, best_peer_height: Option<u32>) -> bool {
    matches!((best_height, best_peer_height), (Some(best), Some(peer)) if peer > best)
}

fn is_sync_target_unknown(best_height: Option<u32>, best_peer_height: Option<u32>) -> bool {
    matches!((best_height, best_peer_height), (Some(best), None) if best > 0)
}

fn best_peer_height(peers: &hns_p2p::PeerManager) -> Option<u32> {
    peers
        .iter()
        .map(|peer| peer.last_height.0)
        .filter(|height| *height > 0)
        .max()
}

fn open_initialized_header_chain(
    base: &Path,
    network: NetworkKind,
) -> Result<HeaderChain<SqliteHeaderStore>, String> {
    fs::create_dir_all(base).map_err(|error| format!("create sync directory: {error}"))?;
    let header_store = SqliteHeaderStore::open(base.join("headers.sqlite"))
        .map_err(|error| format!("open header store: {error}"))?;
    let mut chain = chain_for_network(header_store, network);
    if chain
        .best_header()
        .map_err(|error| format!("read best header: {error}"))?
        .is_none()
    {
        chain
            .insert_genesis(BlockHeader::genesis_for_network(network))
            .map_err(|error| format!("insert genesis header: {error}"))?;
    }
    Ok(chain)
}

fn install_header_snapshot_inner(
    data_dir: &str,
    snapshot_path: &str,
    network: NetworkKind,
) -> Result<NativeSyncStatus, String> {
    if network != NetworkKind::Mainnet {
        return Err("bundled header snapshot is only available for mainnet".to_owned());
    }
    let base = network_base_path(data_dir, network);
    let mut snapshot =
        fs::File::open(snapshot_path).map_err(|error| format!("open header snapshot: {error}"))?;
    let metadata = read_header_snapshot_metadata(&mut snapshot)?;
    let mut chain = open_initialized_header_chain(&base, network)?;
    if chain
        .best_header()
        .map_err(|error| format!("read best header before snapshot import: {error}"))?
        .is_some_and(|header| header.height.0 >= metadata.target_height)
    {
        return sync_status_with_override(data_dir, network, "snapshot_present", 1, 1, 0);
    }

    let mut header_bytes = [0u8; HEADER_SIZE];
    snapshot
        .read_exact(&mut header_bytes)
        .map_err(|error| format!("read snapshot genesis header: {error}"))?;
    let genesis = BlockHeader::parse(&header_bytes)
        .map_err(|error| format!("parse snapshot genesis header: {error}"))?;
    if genesis != BlockHeader::mainnet_genesis() {
        return Err("snapshot genesis header does not match mainnet".to_owned());
    }

    let mut accepted_total = 0usize;
    let mut batch = Vec::with_capacity(HEADER_SNAPSHOT_IMPORT_BATCH);
    for height in 1..=metadata.target_height {
        snapshot
            .read_exact(&mut header_bytes)
            .map_err(|error| format!("read snapshot header {height}: {error}"))?;
        let header = BlockHeader::parse(&header_bytes)
            .map_err(|error| format!("parse snapshot header {height}: {error}"))?;
        batch.push(header);
        if batch.len() >= HEADER_SNAPSHOT_IMPORT_BATCH {
            accepted_total = accepted_total
                .saturating_add(insert_header_snapshot_batch(&mut chain, &mut batch)?);
        }
    }
    accepted_total =
        accepted_total.saturating_add(insert_header_snapshot_batch(&mut chain, &mut batch)?);

    let mut trailing = [0u8; 1];
    if snapshot
        .read(&mut trailing)
        .map_err(|error| format!("read snapshot trailer: {error}"))?
        != 0
    {
        return Err("header snapshot has trailing bytes".to_owned());
    }

    let tip = chain
        .canonical_header(Height(metadata.target_height))
        .ok_or_else(|| "snapshot target height is not canonical after import".to_owned())?;
    if tip.hash != metadata.tip_hash {
        return Err(format!(
            "snapshot tip hash mismatch at height {}: got {}, expected {}",
            metadata.target_height, tip.hash, metadata.tip_hash
        ));
    }

    sync_status_with_override(data_dir, network, "snapshot_imported", 1, 1, accepted_total)
}

fn insert_header_snapshot_batch(
    chain: &mut HeaderChain<SqliteHeaderStore>,
    batch: &mut Vec<BlockHeader>,
) -> Result<usize, String> {
    if batch.is_empty() {
        return Ok(0);
    }
    let headers = std::mem::take(batch);
    let accepted = chain
        .insert_headers(headers)
        .map_err(|error| format!("import header snapshot batch: {error}"))?
        .len();
    batch.reserve(HEADER_SNAPSHOT_IMPORT_BATCH);
    Ok(accepted)
}

struct HeaderSnapshotMetadata {
    target_height: u32,
    tip_hash: hns_core::Hash,
}

fn read_header_snapshot_metadata<R: Read>(
    reader: &mut R,
) -> Result<HeaderSnapshotMetadata, String> {
    let mut magic = vec![0u8; HEADER_SNAPSHOT_MAGIC.len()];
    reader
        .read_exact(&mut magic)
        .map_err(|error| format!("read header snapshot magic: {error}"))?;
    if magic != HEADER_SNAPSHOT_MAGIC {
        return Err("header snapshot magic mismatch".to_owned());
    }

    let target_height = read_u32_be(reader, "target height")?;
    if target_height > HEADER_SNAPSHOT_MAX_HEIGHT {
        return Err(format!(
            "header snapshot target height {target_height} exceeds import limit {HEADER_SNAPSHOT_MAX_HEIGHT}"
        ));
    }
    let header_count = read_u32_be(reader, "header count")?;
    let expected_count = target_height.saturating_add(1);
    if header_count != expected_count {
        return Err(format!(
            "header snapshot count mismatch: got {header_count}, expected {expected_count}"
        ));
    }

    let mut tip_hash = [0u8; 32];
    reader
        .read_exact(&mut tip_hash)
        .map_err(|error| format!("read header snapshot tip hash: {error}"))?;
    let tip_hash = hns_core::Hash::from_slice(&tip_hash)
        .map_err(|error| format!("parse header snapshot tip hash: {error}"))?;

    Ok(HeaderSnapshotMetadata {
        target_height,
        tip_hash,
    })
}

fn read_u32_be<R: Read>(reader: &mut R, field: &str) -> Result<u32, String> {
    let mut bytes = [0u8; 4];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| format!("read header snapshot {field}: {error}"))?;
    Ok(u32::from_be_bytes(bytes))
}

fn reset_headers_from_peers_inner(
    data_dir: &str,
    network: NetworkKind,
) -> Result<NativeSyncStatus, String> {
    let base = network_base_path(data_dir, network);
    fs::create_dir_all(&base).map_err(|error| format!("create sync directory: {error}"))?;
    remove_sqlite_database(&base.join("headers.sqlite"))?;
    clear_resource_cache_at_base(&base)?;
    let _chain = open_initialized_header_chain(&base, network)?;
    let mut status = read_sync_status(data_dir, network)
        .unwrap_or_else(|_| NativeSyncStatus::empty_for(network));
    status.status = "headers_reset";
    status.resource_cache_entries = 0;
    status.resource_cache_bytes = 0;
    status.resource_cache_evicted = 0;
    Ok(status)
}

fn remove_sqlite_database(path: &Path) -> Result<(), String> {
    let mut paths = Vec::with_capacity(3);
    paths.push(path.to_path_buf());
    paths.push(PathBuf::from(format!("{}-wal", path.display())));
    paths.push(PathBuf::from(format!("{}-shm", path.display())));

    for candidate in paths {
        match fs::remove_file(&candidate) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "remove sqlite database file {}: {error}",
                    candidate.display()
                ));
            }
        }
    }
    Ok(())
}

fn sync_status_with_override(
    data_dir: &str,
    network: NetworkKind,
    status_label: &'static str,
    attempted: usize,
    successful: usize,
    accepted: usize,
) -> Result<NativeSyncStatus, String> {
    let mut status = read_sync_status(data_dir, network)?;
    status.status = status_label;
    status.attempted = attempted;
    status.successful = successful;
    status.accepted = accepted;
    Ok(status)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LocalChainCurrentness {
    best_height: Option<u32>,
    target_height: Option<u32>,
    estimated_tip_height: Option<u32>,
    stale: Option<bool>,
}

impl LocalChainCurrentness {
    fn new(
        best_height: Option<u32>,
        target_height: Option<u32>,
        estimated_tip_height: Option<u32>,
    ) -> Self {
        let current_target = target_height.or(estimated_tip_height);
        let stale = match (best_height, current_target) {
            (Some(best), Some(target)) => {
                Some(target.saturating_sub(best) > LOCAL_CHAIN_CURRENTNESS_ALLOWED_LAG)
            }
            _ => None,
        };
        Self {
            best_height,
            target_height,
            estimated_tip_height,
            stale,
        }
    }
}

fn local_chain_is_stale_for_current_resolution(
    base: &Path,
    network: NetworkKind,
) -> Result<bool, ResolverError> {
    Ok(local_chain_currentness(base, network)?
        .stale
        .unwrap_or(false))
}

fn local_chain_currentness(
    base: &Path,
    network: NetworkKind,
) -> Result<LocalChainCurrentness, ResolverError> {
    let header_store = SqliteHeaderStore::open(base.join("headers.sqlite"))
        .map_err(|error| ResolverError::Storage(format!("open header store: {error}")))?;
    let chain = chain_for_network(header_store, network);
    let best_height = chain
        .best_header()
        .map_err(|error| ResolverError::Storage(format!("read best header: {error}")))?
        .map(|header| header.height.0);
    let peer_store = SqlitePeerStore::open(base.join("peers.sqlite"))
        .map_err(|error| ResolverError::Storage(format!("open peer store: {error}")))?;
    let mut peers = peer_store
        .load_manager()
        .map_err(|error| ResolverError::Storage(format!("load peer store: {error}")))?;
    retain_allowed_peer_endpoints(&mut peers, &network.network());
    Ok(LocalChainCurrentness::new(
        best_height,
        best_peer_height(&peers),
        estimated_tip_height_for_network(network, now_unix_seconds()),
    ))
}

fn select_live_proof_peers(
    peers: &hns_p2p::PeerManager,
    network: &hns_core::network::Network,
    preferred_count: usize,
    now: u64,
    proof_height: Height,
) -> Vec<SocketAddr> {
    let mut candidates = peers
        .iter()
        .filter(|peer| {
            !peer.is_banned(now)
                && peer.last_height >= proof_height
                && is_allowed_peer_endpoint(network, peer.address)
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        left.score
            .cmp(&right.score)
            .then_with(|| right.last_height.cmp(&left.last_height))
            .then_with(|| left.address.cmp(&right.address))
    });
    candidates
        .into_iter()
        .take(preferred_count)
        .map(|peer| peer.address)
        .collect()
}

fn estimated_mainnet_tip_height(now: u64) -> Option<u32> {
    now.checked_sub(MAINNET_GENESIS_TIME)
        .map(|elapsed| elapsed / MAINNET_TARGET_SPACING_SECONDS)
        .and_then(|height| u32::try_from(height).ok())
}

fn read_sync_status(data_dir: &str, network: NetworkKind) -> Result<NativeSyncStatus, String> {
    let base = network_base_path(data_dir, network);
    let chain = open_initialized_header_chain(&base, network)?;
    let peer_store = SqlitePeerStore::open(base.join("peers.sqlite"))
        .map_err(|error| format!("open peer store: {error}"))?;
    let mut peers = peer_store
        .load_manager()
        .map_err(|error| format!("load peer store: {error}"))?;
    retain_allowed_peer_endpoints(&mut peers, &network.network());
    let best = chain
        .best_header()
        .map_err(|error| format!("read best header: {error}"))?;
    let now = now_unix_seconds();
    let best_height = best.map(|header| header.height.0);
    let best_peer_height = best_peer_height(&peers);
    let estimated_tip_height = estimated_tip_height_for_network(network, now);
    let (resource_cache_entries, resource_cache_bytes) = resource_cache_stats(&base)?;

    Ok(NativeSyncStatus {
        network,
        status: classify_cached_sync_status(best_height, best_peer_height),
        attempted: 0,
        successful: 0,
        accepted: 0,
        failed: 0,
        peer_count: peers.len(),
        peer_groups: peers.address_group_count(now),
        best_height,
        best_peer_height,
        estimated_tip_height,
        resource_cache_entries,
        resource_cache_bytes,
        resource_cache_evicted: 0,
        error: None,
        failures: Vec::new(),
    })
}

fn classify_cached_sync_status(
    best_height: Option<u32>,
    best_peer_height: Option<u32>,
) -> &'static str {
    match (best_height, best_peer_height) {
        (Some(best), Some(peer)) if best > 0 && peer <= best => "up_to_date",
        (Some(best), Some(peer)) if peer > best => "syncing",
        (Some(best), None) if best > 0 => "syncing",
        _ => "idle",
    }
}

fn best_synced_header(
    base: &Path,
    network: NetworkKind,
) -> Result<hns_chain::StoredHeader, ResolverError> {
    let header_store = SqliteHeaderStore::open(base.join("headers.sqlite"))
        .map_err(|error| ResolverError::Storage(format!("open header store: {error}")))?;
    let chain = chain_for_network(header_store, network);
    let best = chain
        .best_header()
        .map_err(|error| ResolverError::Storage(format!("read best header: {error}")))?
        .ok_or(ResolverError::ProofUnavailable)?;
    if best.height.0 == 0 {
        return Err(ResolverError::ProofUnavailable);
    }
    Ok(best)
}

fn clear_resolver_cache_inner(
    data_dir: &str,
    network: NetworkKind,
) -> Result<NativeSyncStatus, String> {
    let base = network_base_path(data_dir, network);
    fs::create_dir_all(&base).map_err(|error| format!("create sync directory: {error}"))?;
    clear_resource_cache_at_base(&base)?;

    let mut status = read_sync_status(data_dir, network)
        .unwrap_or_else(|_| NativeSyncStatus::empty_for(network));
    status.status = "cleared";
    status.resource_cache_entries = 0;
    status.resource_cache_bytes = 0;
    status.resource_cache_evicted = 0;
    Ok(status)
}

fn clear_resource_cache_at_base(base: &Path) -> Result<(), String> {
    let path = base.join("resources.sqlite");
    if path.exists() {
        let provider = SqliteResourceValueProvider::open(path)
            .map_err(|error| format!("open resource cache: {error}"))?;
        provider
            .clear()
            .map_err(|error| format!("clear resource cache: {error}"))?;
    }
    Ok(())
}

fn enforce_resource_cache_limit(base: &Path, max_bytes: usize) -> Result<usize, String> {
    let path = base.join("resources.sqlite");
    if !path.exists() {
        return Ok(0);
    }

    let provider = SqliteResourceValueProvider::open(path)
        .map_err(|error| format!("open resource cache: {error}"))?;
    provider
        .enforce_value_byte_limit(max_bytes)
        .map_err(|error| format!("enforce resource cache limit: {error}"))
}

fn prune_resource_cache_to_best_chain(
    base: &Path,
    chain: &HeaderChain<SqliteHeaderStore>,
) -> Result<usize, String> {
    let path = base.join("resources.sqlite");
    if !path.exists() {
        return Ok(0);
    }

    let provider = SqliteResourceValueProvider::open(path)
        .map_err(|error| format!("open resource cache: {error}"))?;
    let valid_anchors = recent_canonical_resource_anchors(chain)?;
    provider
        .prune_invalid_anchors(&valid_anchors, true)
        .map_err(|error| format!("prune resource cache anchors: {error}"))
}

fn recent_canonical_resource_anchors(
    chain: &HeaderChain<SqliteHeaderStore>,
) -> Result<Vec<ResourceValueAnchor>, String> {
    let Some(best) = chain
        .best_header()
        .map_err(|error| format!("read best header for resource cache anchors: {error}"))?
    else {
        return Ok(Vec::new());
    };
    if best.height.0 == 0 {
        return Ok(Vec::new());
    }

    let first_height = best
        .height
        .0
        .saturating_sub(RESOURCE_PROOF_CACHE_CANONICAL_WINDOW)
        .max(1);
    let mut anchors = Vec::new();
    for height in first_height..=best.height.0 {
        if let Some(header) = chain.canonical_header(Height(height)) {
            anchors.push(ResourceValueAnchor {
                tree_root: header.header.tree_root,
                height: header.height,
            });
        }
    }
    Ok(anchors)
}

fn resource_cache_stats(base: &Path) -> Result<(usize, usize), String> {
    let path = base.join("resources.sqlite");
    if !path.exists() {
        return Ok((0, 0));
    }

    let provider = SqliteResourceValueProvider::open(path)
        .map_err(|error| format!("open resource cache: {error}"))?;
    let stats = provider
        .stats()
        .map_err(|error| format!("read resource cache stats: {error}"))?;
    Ok((stats.entries, stats.value_bytes))
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncStatus {
    pub network: NetworkKind,
    pub status: &'static str,
    pub attempted: usize,
    pub successful: usize,
    pub accepted: usize,
    pub failed: usize,
    pub peer_count: usize,
    pub peer_groups: usize,
    pub best_height: Option<u32>,
    pub best_peer_height: Option<u32>,
    pub estimated_tip_height: Option<u32>,
    pub resource_cache_entries: usize,
    pub resource_cache_bytes: usize,
    pub resource_cache_evicted: usize,
    pub error: Option<String>,
    pub failures: Vec<NativePeerFailure>,
}

pub type NativeSyncStatus = SyncStatus;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativePeerFailure {
    pub address: String,
    pub stage: &'static str,
    pub error: String,
}

impl SyncStatus {
    fn empty_for(network: NetworkKind) -> Self {
        Self {
            network,
            status: "idle",
            attempted: 0,
            successful: 0,
            accepted: 0,
            failed: 0,
            peer_count: 0,
            peer_groups: 0,
            best_height: None,
            best_peer_height: None,
            estimated_tip_height: None,
            resource_cache_entries: 0,
            resource_cache_bytes: 0,
            resource_cache_evicted: 0,
            error: None,
            failures: Vec::new(),
        }
    }

    pub fn error(error: String) -> Self {
        Self::error_for(NetworkKind::Mainnet, error)
    }

    pub fn error_for(network: NetworkKind, error: String) -> Self {
        Self {
            network,
            status: "error",
            attempted: 0,
            successful: 0,
            accepted: 0,
            failed: 0,
            peer_count: 0,
            peer_groups: 0,
            best_height: None,
            best_peer_height: None,
            estimated_tip_height: None,
            resource_cache_entries: 0,
            resource_cache_bytes: 0,
            resource_cache_evicted: 0,
            error: Some(error),
            failures: Vec::new(),
        }
    }

    pub fn to_json(&self) -> String {
        let best_height = self
            .best_height
            .map(|height| height.to_string())
            .unwrap_or_else(|| "null".to_owned());
        let best_peer_height = self
            .best_peer_height
            .map(|height| height.to_string())
            .unwrap_or_else(|| "null".to_owned());
        let estimated_tip_height = self
            .estimated_tip_height
            .map(|height| height.to_string())
            .unwrap_or_else(|| "null".to_owned());
        let error = self
            .error
            .as_ref()
            .map(|error| format!(r#""{}""#, json_escape(error)))
            .unwrap_or_else(|| "null".to_owned());
        let failures = self
            .failures
            .iter()
            .map(NativePeerFailure::to_json)
            .collect::<Vec<_>>()
            .join(",");

        format!(
            r#"{{"network":"{}","status":"{}","attempted":{},"successful":{},"accepted":{},"failed":{},"peerCount":{},"peerGroups":{},"bestHeight":{},"bestPeerHeight":{},"estimatedTipHeight":{},"resourceCacheEntries":{},"resourceCacheBytes":{},"resourceCacheEvicted":{},"error":{},"failures":[{}]}}"#,
            self.network.as_str(),
            self.status,
            self.attempted,
            self.successful,
            self.accepted,
            self.failed,
            self.peer_count,
            self.peer_groups,
            best_height,
            best_peer_height,
            estimated_tip_height,
            self.resource_cache_entries,
            self.resource_cache_bytes,
            self.resource_cache_evicted,
            error,
            failures,
        )
    }
}

impl NativePeerFailure {
    fn to_json(&self) -> String {
        format!(
            r#"{{"address":"{}","stage":"{}","error":"{}"}}"#,
            json_escape(&self.address),
            self.stage,
            json_escape(&self.error),
        )
    }
}

fn json_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => "\\r".chars().collect::<Vec<_>>(),
            '\t' => "\\t".chars().collect::<Vec<_>>(),
            character if character.is_control() => {
                format!("\\u{:04x}", character as u32).chars().collect()
            }
            character => vec![character],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_chain::{HeaderStore, StoredHeader};
    use hns_core::dns::DnsName;
    use hns_core::hash::blake2b_256;
    use hns_core::pow::Chainwork;
    use hns_core::resource::ResourceError;
    use hns_core::{Hash, Height, NameHash};
    use hns_loopback_proxy::{
        NoopProxyObserver, ProxyConfig, ProxyInstanceId, ProxySessionId, RunningProxy,
    };
    use hns_p2p::{Packet, PeerManager, ProofPacket};
    use hns_resolver::{HnsResourceValueProvider, VerifiedResourceValue};
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::thread;

    #[test]
    fn version_is_stable() {
        assert_eq!(
            core_version(),
            concat!("hns-dane-browser-rust-core/", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn browser_runtime_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BrowserRuntime>();
        assert_send_sync::<RuntimeProxyBackend>();
        let data_dir = temp_dir_path("runtime-proxy-debug");
        assert_eq!(
            format!(
                "{:?}",
                BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest,))
                    .unwrap()
                    .proxy_backend()
            ),
            "RuntimeProxyBackend(<redacted runtime>)"
        );
        cleanup_dir(&data_dir);
    }

    #[test]
    fn browser_runtime_owns_network_and_storage_configuration() {
        let data_dir = temp_dir_path("browser-runtime-status");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();

        let status = runtime.sync_status().unwrap();

        let configuration = runtime.configuration().unwrap();
        assert_eq!(configuration.data_dir(), data_dir);
        assert_eq!(configuration.network(), NetworkKind::Regtest);
        assert_eq!(status.network, NetworkKind::Regtest);
        assert_eq!(status.best_height, Some(0));
        cleanup_dir(&data_dir);
    }

    #[test]
    fn browser_runtimes_share_coordination_for_the_same_storage() {
        let data_dir = temp_dir_path("browser-runtime-shared-coordination");
        let first =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();
        let second = BrowserRuntime::open(RuntimeConfiguration::new(
            data_dir.join("."),
            NetworkKind::Regtest,
        ))
        .unwrap();

        assert!(Arc::ptr_eq(
            &first.inner.coordination,
            &second.inner.coordination
        ));
        cleanup_dir(&data_dir);
    }

    #[test]
    fn browser_runtime_status_remains_available_while_peer_state_is_busy() {
        let data_dir = temp_dir_path("browser-runtime-concurrent-status");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();
        runtime.sync_status().unwrap();
        let peer_state = Arc::clone(&runtime.inner.coordination.peer_state);
        let peer_state_guard = peer_state.lock().unwrap();
        let call_runtime = runtime.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let call = thread::spawn(move || sender.send(call_runtime.sync_status()).unwrap());

        let status = receiver.recv_timeout(Duration::from_secs(2));
        drop(peer_state_guard);
        call.join().unwrap();

        assert!(status.unwrap().is_ok());
        cleanup_dir(&data_dir);
    }

    #[test]
    fn browser_runtime_configuration_replaces_untrusted_control_headers() {
        let data_dir = temp_dir_path("browser-runtime-headers");
        let configuration = RuntimeConfiguration::new(&data_dir, NetworkKind::Testnet)
            .with_initial_policy(RuntimePolicy {
                resolution_mode: ResolutionMode::Strict,
                hns_doh_resolver: Some("https://resolver.example/dns-query".to_owned()),
                stateless_dane_certificates: true,
            });
        let runtime = BrowserRuntime::open(configuration).unwrap();
        let header_text = runtime
            .gateway_header_text(&[
                ("Accept".to_owned(), "text/html".to_owned()),
                (HNS_GATEWAY_NETWORK_HEADER.to_owned(), "regtest".to_owned()),
                (HNS_GATEWAY_STRICT_MODE_HEADER.to_owned(), "0".to_owned()),
                (
                    "x-hns-unrecognized-metadata".to_owned(),
                    "spoofed".to_owned(),
                ),
            ])
            .unwrap();

        let parsed = parse_gateway_headers(&header_text).unwrap();
        assert_eq!(
            parsed.headers,
            vec![("Accept".to_owned(), "text/html".to_owned())]
        );
        assert!(parsed.strict_hns_mode);
        assert!(parsed.stateless_dane_certificates);
        assert_eq!(parsed.network, NetworkKind::Testnet);
        assert_eq!(
            parsed.doh_endpoint.display(),
            "https://resolver.example/dns-query"
        );
        cleanup_dir(&data_dir);
    }

    #[test]
    fn browser_runtime_rejects_header_injection_before_adding_control_metadata() {
        let data_dir = temp_dir_path("browser-runtime-header-injection");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();

        let error = runtime
            .gateway_header_text(&[(
                "Accept".to_owned(),
                "text/html\r\nX-HNS-Browser-Network: mainnet".to_owned(),
            )])
            .unwrap_err();

        assert!(matches!(error, RuntimeError::InvalidConfiguration(_)));
        cleanup_dir(&data_dir);
    }

    #[test]
    fn browser_runtime_policy_updates_are_revisioned_and_normalized() {
        let data_dir = temp_dir_path("browser-runtime-policy");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Mainnet))
                .unwrap();
        assert_eq!(runtime.policy_revision(), 0);

        let revision = runtime
            .set_policy(RuntimePolicy {
                resolution_mode: ResolutionMode::Strict,
                hns_doh_resolver: Some("https://Resolver.Example:443/dns-query".to_owned()),
                stateless_dane_certificates: true,
            })
            .unwrap();
        let (policy, snapshot_revision) = runtime.policy_snapshot().unwrap();

        assert_eq!(revision, 1);
        assert_eq!(snapshot_revision, revision);
        assert_eq!(policy.resolution_mode, ResolutionMode::Strict);
        assert_eq!(
            policy.hns_doh_resolver.as_deref(),
            Some("https://resolver.example/dns-query")
        );
        assert!(policy.stateless_dane_certificates);
        cleanup_dir(&data_dir);
    }

    #[test]
    fn browser_runtime_rejects_oversized_gateway_inputs_before_execution() {
        let data_dir = temp_dir_path("browser-runtime-gateway-limits");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();
        let mut request = GatewayHttpRequest {
            method: "POST".to_owned(),
            scheme: "http".to_owned(),
            host: "example".to_owned(),
            port: 80,
            path_and_query: "/".to_owned(),
            headers: Vec::new(),
            body: vec![0; DEFAULT_MAX_REQUEST_BODY_BYTES + 1],
        };
        assert!(matches!(
            runtime.gateway_request(request.clone()),
            Err(RuntimeError::InvalidConfiguration(_))
        ));

        request.body.clear();
        request.headers.push((
            "X-Large".to_owned(),
            "a".repeat(MAX_GATEWAY_HEADER_TEXT_BYTES),
        ));
        assert!(matches!(
            runtime.gateway_request(request),
            Err(RuntimeError::InvalidConfiguration(_))
        ));
        cleanup_dir(&data_dir);
    }

    fn runtime_with_cached_loopback_name(label: &str) -> (PathBuf, BrowserRuntime) {
        let data_dir = temp_dir_path(label);
        let base = data_dir.join("hns-regtest");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let anchor_root = Hash::new([33; 32]);
        let anchor_height =
            store_best_header_for_network_with_tree_root(&base, NetworkKind::Regtest, anchor_root);
        resources
            .insert(
                VerifiedResourceValue::inclusion(
                    root_name.clone(),
                    name_hash,
                    owner_glue4_resource(&root_name, [127, 0, 0, 1]),
                )
                .with_anchor(anchor_root, anchor_height),
            )
            .unwrap();
        drop(resources);
        let runtime = BrowserRuntime::open(
            RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest).with_initial_policy(
                RuntimePolicy {
                    resolution_mode: ResolutionMode::Strict,
                    hns_doh_resolver: None,
                    stateless_dane_certificates: false,
                },
            ),
        )
        .unwrap();
        (data_dir, runtime)
    }

    fn proxy_request(port: u16, scheme: &str) -> LoopbackProxyRequest {
        LoopbackProxyRequest {
            method: "GET".to_owned(),
            scheme: scheme.to_owned(),
            host: "welcome".to_owned(),
            port,
            path_and_query: "/socket".to_owned(),
            headers: vec![
                ProxyHeader::new("Host", format!("welcome:{port}")),
                ProxyHeader::new("X-Test", "yes"),
                ProxyHeader::new("X-HNS-Browser-Network", "mainnet"),
            ],
            body: ProxyRequestBody::Empty,
        }
    }

    fn read_test_http_head(stream: &mut impl Read) -> std::io::Result<Vec<u8>> {
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while head.len() < MAX_GATEWAY_HEADER_TEXT_BYTES {
            if stream.read(&mut byte)? == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "test HTTP head ended early",
                ));
            }
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                return Ok(head);
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "test HTTP head exceeded limit",
        ))
    }

    #[test]
    fn runtime_proxy_backend_returns_typed_sanitized_gateway_response() {
        let (data_dir, runtime) = runtime_with_cached_loopback_name("runtime-proxy-http");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let request = String::from_utf8(read_test_http_head(&mut stream).unwrap()).unwrap();
            assert!(request.starts_with("GET /socket HTTP/1.1\r\n"));
            assert!(request.contains("X-Test: yes\r\n"));
            assert!(!request.contains("X-HNS-"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nConnection: close, X-Origin-Hop\r\nX-Origin-Hop: secret\r\nX-HNS-TLS-Policy: spoofed\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
                )
                .unwrap();
        });

        let response = runtime
            .proxy_backend()
            .execute(proxy_request(port, "http"), &ProxyCancellationToken::new())
            .unwrap();

        assert_eq!(response.head.status_code, 200);
        assert_eq!(response.head.reason_phrase, "OK");
        assert!(response.head.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("content-type") && header.value == "text/plain"
        }));
        assert!(response.head.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case(HNS_RESOLVER_MODE_HEADER) && header.value == "strict"
        }));
        assert!(response.head.headers.iter().any(|header| {
            header
                .name
                .eq_ignore_ascii_case(HNS_RESOLUTION_TRACE_HEADER)
                && header.value.contains(r#""dnssec":"secure""#)
        }));
        assert!(!response.head.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("x-origin-hop")
                || header.name.eq_ignore_ascii_case("x-hns-tls-policy")
        }));
        match response.body {
            ProxyResponseBody::Bytes(body) => assert_eq!(body, b"ok"),
            ProxyResponseBody::Stream { .. } => panic!("runtime response must be bounded bytes"),
        }
        server.join().unwrap();
        cleanup_dir(&data_dir);
    }

    #[test]
    fn runtime_gateway_errors_remain_actionable_typed_http_responses() {
        let data_dir = temp_dir_path("runtime-proxy-error-response");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();
        let request = GatewayHttpRequest {
            method: "GET".to_owned(),
            scheme: "ws".to_owned(),
            host: "missing".to_owned(),
            port: 80,
            path_and_query: "/socket".to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let response = proxy_error_response_from_gateway(
            &runtime,
            &request,
            NetworkKind::Regtest,
            GatewayResolutionMode::Strict,
            &GatewayError::Resolver(ResolverError::NameNotFound),
            &FallbackMarker::default(),
            &DnsTraceRecorder::default(),
        );

        assert_eq!(response.head.status_code, 404);
        assert_eq!(response.head.reason_phrase, "HNS Name Not Found");
        assert!(response.head.headers.iter().any(|header| {
            header
                .name
                .eq_ignore_ascii_case(HNS_RESOLUTION_TRACE_HEADER)
                && header
                    .value
                    .contains(r#""finalError":"resolver error: HNS name does not exist""#)
        }));
        match response.body {
            ProxyResponseBody::Bytes(body) => {
                let body = String::from_utf8(body).unwrap();
                assert!(body.contains("ws://missing/socket"));
                assert!(body.contains("404 HNS Name Not Found"));
            }
            ProxyResponseBody::Stream { .. } => panic!("error response must be bounded bytes"),
        }
        cleanup_dir(&data_dir);
    }

    #[test]
    fn typed_upgrade_parser_requires_a_complete_websocket_handshake() {
        let parsed = parse_upgrade_response_head(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: accepted\r\n\r\n",
        )
        .unwrap();
        assert_eq!(parsed.status_code, 101);
        assert!(parsed.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("sec-websocket-accept") && value == "accepted"
        }));

        for invalid in [
            b"HTTP/1.1 200 OK\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"
                .as_slice(),
        ] {
            assert!(matches!(
                parse_upgrade_response_head(invalid),
                Err(ProxyBackendError::InvalidResponse)
            ));
        }
    }

    #[test]
    fn rust_proxy_uses_runtime_gateway_for_websocket_upgrade() {
        let (data_dir, runtime) = runtime_with_cached_loopback_name("runtime-proxy-websocket");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_port = listener.local_addr().unwrap().port();
        let origin = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let request = String::from_utf8(read_test_http_head(&mut stream).unwrap()).unwrap();
            assert!(request.starts_with("GET /socket HTTP/1.1\r\n"));
            assert!(request.contains("Connection: Upgrade\r\n"));
            assert!(request.contains("Upgrade: websocket\r\n"));
            assert!(request.contains("Sec-WebSocket-Key: key\r\n"));
            assert!(request.contains("X-Test: yes\r\n"));
            assert!(!request.contains("Proxy-Authorization"));
            assert!(!request.contains("X-HNS-"));
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade, X-Origin-Hop\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: accepted\r\nX-Origin-Hop: secret\r\nX-HNS-TLS-Policy: spoofed\r\n\r\norigin",
                )
                .unwrap();
            stream.flush().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(&payload).unwrap();
            stream.flush().unwrap();
        });
        let proxy = RunningProxy::start(
            ProxyConfig::new(
                ProxyInstanceId::new(ProxySessionId::generate().unwrap(), 1),
                hns_loopback_proxy::HostScope::new("welcome").unwrap(),
            ),
            Arc::new(runtime.proxy_backend()),
            Arc::new(NoopProxyObserver),
        )
        .unwrap();
        let mut client = TcpStream::connect(proxy.endpoint().address()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let request = format!(
            "GET ws://welcome:{origin_port}/socket HTTP/1.1\r\nHost: welcome:{origin_port}\r\nProxy-Authorization: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: key\r\nSec-WebSocket-Version: 13\r\nX-Test: yes\r\nX-HNS-Client: spoofed\r\n\r\n",
            proxy.endpoint().authorization_header_value(),
        );
        client.write_all(request.as_bytes()).unwrap();
        client.flush().unwrap();

        let response = String::from_utf8(read_test_http_head(&mut client).unwrap()).unwrap();
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(response.contains("Connection: Upgrade\r\n"));
        assert!(response.contains("Upgrade: websocket\r\n"));
        assert!(response.contains("Sec-WebSocket-Accept: accepted\r\n"));
        assert!(!response.contains("X-Origin-Hop"));
        assert!(!response.contains("X-HNS-"));
        let mut initial = [0_u8; 6];
        client.read_exact(&mut initial).unwrap();
        assert_eq!(&initial, b"origin");
        client.write_all(b"ping").unwrap();
        client.flush().unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"ping");
        drop(client);
        proxy.stop();
        origin.join().unwrap();
        cleanup_dir(&data_dir);
    }

    #[test]
    fn proxy_stop_cancels_runtime_backend_waiting_for_maintenance() {
        let data_dir = temp_dir_path("runtime-proxy-maintenance-cancellation");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();
        let maintenance = runtime.inner.coordination.maintenance.write().unwrap();
        let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
        let observer = move |event: &hns_loopback_proxy::ProxyEvent| {
            if matches!(
                event,
                hns_loopback_proxy::ProxyEvent::Request {
                    phase: hns_loopback_proxy::RequestPhase::Accepted,
                    ..
                }
            ) {
                let _result = accepted_tx.send(());
            }
        };
        let proxy = RunningProxy::start(
            ProxyConfig::new(
                ProxyInstanceId::new(ProxySessionId::generate().unwrap(), 1),
                hns_loopback_proxy::HostScope::new("welcome").unwrap(),
            ),
            Arc::new(runtime.proxy_backend()),
            Arc::new(observer),
        )
        .unwrap();
        let mut client = TcpStream::connect(proxy.endpoint().address()).unwrap();
        let request = format!(
            "GET http://welcome/ HTTP/1.1\r\nHost: welcome\r\nProxy-Authorization: {}\r\n\r\n",
            proxy.endpoint().authorization_header_value(),
        );
        client.write_all(request.as_bytes()).unwrap();
        client.flush().unwrap();
        accepted_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        thread::sleep(Duration::from_millis(50));

        let started = Instant::now();
        proxy.stop();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(proxy.is_stopped());
        assert_eq!(proxy.active_clients(), 0);
        let _result = client.shutdown(Shutdown::Both);
        drop(maintenance);
        cleanup_dir(&data_dir);
    }

    #[test]
    fn generated_local_certificate_matches_legacy_bundle() {
        let certificate = generate_local_tls_certificate("example").unwrap();
        assert!(!certificate.certificate_der.is_empty());
        assert!(!certificate.private_key_pkcs8_der.is_empty());
        assert_eq!(
            Sha256::digest(&certificate.certificate_der).as_slice(),
            certificate.certificate_sha256
        );

        let bundle = local_tls_certificate_bundle("example").unwrap();
        let (cert_der, key_der, fingerprint) = parse_local_tls_bundle(&bundle);
        assert!(!cert_der.is_empty());
        assert!(!key_der.is_empty());
        assert_eq!(Sha256::digest(cert_der).as_slice(), fingerprint);
    }

    #[test]
    fn diagnostics_reports_fail_closed_security() {
        let diagnostics = diagnostics_json();

        assert!(diagnostics.contains(&format!(r#""version":"{}""#, env!("CARGO_PKG_VERSION"))));
        assert!(!diagnostics.contains("__VERSION__"));
        assert!(diagnostics.contains(r#""securityDefault":"fail-closed""#));
    }

    #[test]
    fn diagnostics_reports_resource_decoder() {
        assert!(diagnostics_json().contains(r#""hns-resource-decoder""#));
        assert!(diagnostics_json().contains(r#""hns-authoritative-doh-rfc8484""#));
    }

    #[test]
    fn diagnostics_reports_verified_resource_handoff() {
        assert!(diagnostics_json().contains(r#""header-canonical-height-index""#));
        assert!(diagnostics_json().contains(r#""header-mainnet-difficulty-retarget""#));
        assert!(diagnostics_json().contains(r#""urkel-proof-value-handoff""#));
        assert!(diagnostics_json().contains(r#""hns-resource-provider-adapter""#));
        assert!(diagnostics_json().contains(r#""hns-memory-resource-provider""#));
        assert!(diagnostics_json().contains(r#""hns-sqlite-resource-provider""#));
        assert!(diagnostics_json().contains(r#""hns-negative-cache""#));
        assert!(diagnostics_json().contains(r#""hns-ttl-cache-lru""#));
        assert!(diagnostics_json().contains(r#""hns-resource-cache-stats""#));
        assert!(diagnostics_json().contains(r#""hns-resource-cache-eviction""#));
        assert!(diagnostics_json().contains(r#""hns-resource-cache-cap-enforcement""#));
        assert!(diagnostics_json().contains(r#""hns-resource-cache-chain-anchors""#));
        assert!(diagnostics_json().contains(r#""hns-resource-cache-reorg-invalidation""#));
        assert!(diagnostics_json().contains(r#""hns-resource-cache-current-tip""#));
        assert!(diagnostics_json().contains(r#""hns-delegating-resolver-boundary""#));
        assert!(diagnostics_json().contains(r#""hns-name-state-resource-extraction""#));
        assert!(diagnostics_json().contains(r#""hns-proof-backed-ns-address-hydration""#));
        assert!(diagnostics_json().contains(r#""hns-authoritative-dnssec-delegated-resolver""#));
        assert!(diagnostics_json().contains(r#""dnssec-delegated-no-data-validation""#));
        assert!(diagnostics_json().contains(r#""dnssec-delegated-cname-chain""#));
        assert!(diagnostics_json().contains(r#""dnssec-child-referral-validation""#));
        assert!(diagnostics_json().contains(r#""dnssec-child-cname-chain""#));
        assert!(diagnostics_json().contains(r#""dnssec-child-no-data-validation""#));
        assert!(diagnostics_json().contains(r#""gateway-cname-address-routing""#));
        assert!(diagnostics_json().contains(r#""android-actionable-hns-errors""#));
        assert!(diagnostics_json().contains(r#""hns-name-not-found-error""#));
        assert!(diagnostics_json().contains(r#""gateway-hns-address-required""#));
        assert!(diagnostics_json().contains(r#""gateway-tlsa-service-scope""#));
    }

    #[test]
    fn diagnostics_reports_ed25519_dnssec() {
        assert!(diagnostics_json().contains(r#""dnssec-ed25519-verify""#));
    }

    #[test]
    fn diagnostics_reports_sha384_ds_digest() {
        assert!(diagnostics_json().contains(r#""dnssec-ds-sha1""#));
        assert!(diagnostics_json().contains(r#""dnssec-ds-sha384""#));
        assert!(diagnostics_json().contains(r#""dnssec-rsa-sha1-verify""#));
    }

    #[test]
    fn diagnostics_reports_tcp_peer_connection() {
        assert!(diagnostics_json().contains(r#""p2p-tcp-peer-connection""#));
        assert!(diagnostics_json().contains(r#""p2p-static-peer-source""#));
        assert!(diagnostics_json().contains(r#""p2p-dns-seed-source""#));
        assert!(diagnostics_json().contains(r#""p2p-getaddr-peer-discovery""#));
        assert!(diagnostics_json().contains(r#""p2p-discovery-rotation""#));
        assert!(diagnostics_json().contains(r#""p2p-peer-diversity""#));
        assert!(diagnostics_json().contains(r#""p2p-sqlite-peer-store""#));
    }

    #[test]
    fn diagnostics_reports_sync_proof_scheduler() {
        assert!(diagnostics_json().contains(r#""header-mainnet-checkpoints""#));
        assert!(diagnostics_json().contains(r#""sync-header-runner""#));
        assert!(diagnostics_json().contains(r#""sync-multi-batch-header-runner""#));
        assert!(diagnostics_json().contains(r#""sync-parallel-peer-probing""#));
        assert!(diagnostics_json().contains(r#""sync-ranged-peer-rotation""#));
        assert!(diagnostics_json().contains(r#""sync-checkpoint-prefetch""#));
        assert!(diagnostics_json().contains(r#""sync-proof-scheduler""#));
        assert!(diagnostics_json().contains(r#""android-native-sync-once""#));
        assert!(diagnostics_json().contains(r#""android-sync-status""#));
        assert!(diagnostics_json().contains(r#""android-sync-outcome-status""#));
        assert!(diagnostics_json().contains(r#""android-sync-progress-heights""#));
        assert!(diagnostics_json().contains(r#""android-sync-high-batch-catchup""#));
        assert!(diagnostics_json().contains(r#""android-clear-resolver-cache""#));
        assert!(diagnostics_json().contains(r#""android-persistent-gateway-resolver""#));
        assert!(diagnostics_json().contains(r#""android-gateway-live-proof-fetch""#));
        assert!(diagnostics_json().contains(r#""android-gateway-header-forwarding""#));
        assert!(diagnostics_json().contains(r#""android-gateway-range-forwarding""#));
        assert!(diagnostics_json().contains(r#""android-gateway-body-forwarding""#));
        assert!(diagnostics_json().contains(r#""android-gateway-file-body-stream""#));
        assert!(diagnostics_json().contains(r#""android-webview-hns-intercept""#));
        assert!(diagnostics_json().contains(r#""android-service-worker-hns-intercept""#));
        assert!(diagnostics_json().contains(r#""android-hns-redirect-follow""#));
        assert!(diagnostics_json().contains(r#""android-hns-doh-compat-resolver""#));
        assert!(diagnostics_json().contains(r#""android-random-loopback-proxy-port""#));
    }

    #[test]
    fn diagnostics_reports_websocket_native_tunnel() {
        let diagnostics = diagnostics_json();

        assert!(diagnostics.contains(r#""hns-websocket-native-tunnel""#));
        assert!(diagnostics.contains(r#""http-origin-connection-pooling""#));
        assert!(diagnostics.contains(r#""https-tls-session-resumption""#));
        assert!(diagnostics.contains(r#""https-alt-svc-promotion""#));
    }

    #[test]
    fn diagnostics_reports_origin_transport_framing() {
        assert!(diagnostics_json().contains(r#""http-origin-transport""#));
        assert!(diagnostics_json().contains(r#""http2-origin-transport""#));
        assert!(diagnostics_json().contains(r#""http3-origin-transport""#));
        assert!(diagnostics_json().contains(r#""http-origin-response-framing""#));
        assert!(diagnostics_json().contains(r#""https-rustls-transport""#));
        assert!(diagnostics_json().contains(r#""dane-certificate-chain-policy""#));
        assert!(diagnostics_json().contains(r#""x509-stateless-dane-evidence""#));
        assert!(diagnostics_json().contains(r#""dane-tls-policy""#));
    }

    #[test]
    fn diagnostics_reports_android_connect_certificate_generation() {
        assert!(diagnostics_json().contains(r#""android-local-hns-connect-certs""#));
    }

    #[test]
    fn diagnostics_reports_delegated_gateway_policy() {
        assert!(diagnostics_json().contains(r#""hns-dotted-root-label""#));
        assert!(diagnostics_json().contains(r#""dnssec-delegated-name-error-validation""#));
        assert!(diagnostics_json().contains(r#""dnssec-child-name-error-validation""#));
        assert!(diagnostics_json().contains(r#""dnssec-nxdomain-name-error-validation""#));
        assert!(diagnostics_json().contains(r#""gateway-delegated-origin-address-lookup""#));
        assert!(diagnostics_json().contains(r#""gateway-origin-address-query""#));
        assert!(diagnostics_json().contains(r#""gateway-https-service-query""#));
        assert!(diagnostics_json().contains(r#""gateway-svcb-alpn-policy""#));
        assert!(diagnostics_json().contains(r#""gateway-actionable-nameserver-errors""#));
    }

    #[test]
    fn local_tls_certificate_bundle_contains_cert_key_and_fingerprint() {
        let bundle = local_tls_certificate_bundle("Welcome.").unwrap();
        let (cert_der, key_der, fingerprint) = parse_local_tls_bundle(&bundle);

        assert!(cert_der.len() > 128);
        assert!(key_der.len() > 64);
        assert_eq!(fingerprint, Sha256::digest(cert_der).as_slice());
    }

    #[test]
    fn local_tls_certificate_bundle_rejects_invalid_hosts() {
        assert!(local_tls_certificate_bundle("").is_none());
        assert!(local_tls_certificate_bundle("127.0.0.1").is_none());
        assert!(local_tls_certificate_bundle("[::1]").is_none());
        assert!(local_tls_certificate_bundle("-bad").is_none());
        assert!(local_tls_certificate_bundle("bad_label").is_none());
    }

    fn parse_local_tls_bundle(bundle: &[u8]) -> (&[u8], &[u8], &[u8]) {
        let cert_len = u32::from_be_bytes(bundle[0..4].try_into().unwrap()) as usize;
        let cert_start = 4;
        let cert_end = cert_start + cert_len;
        let key_len =
            u32::from_be_bytes(bundle[cert_end..cert_end + 4].try_into().unwrap()) as usize;
        let key_start = cert_end + 4;
        let key_end = key_start + key_len;
        let fingerprint_end = key_end + LOCAL_TLS_CERT_FINGERPRINT_BYTES;
        assert_eq!(fingerprint_end, bundle.len());
        (
            &bundle[cert_start..cert_end],
            &bundle[key_start..key_end],
            &bundle[key_end..fingerprint_end],
        )
    }

    #[test]
    fn sync_once_initializes_persistent_stores_without_seed_network() {
        let path = temp_dir_path("sync-once");

        let status = sync_once_with_options(
            path.to_str().unwrap(),
            NetworkKind::Mainnet,
            false,
            Duration::from_millis(1),
            DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
        );

        assert_eq!(status.status, "idle");
        assert_eq!(status.attempted, 0);
        assert_eq!(status.successful, 0);
        assert_eq!(status.accepted, 0);
        assert_eq!(status.failed, 0);
        assert!(status.failures.is_empty());
        assert_eq!(status.peer_count, 0);
        assert_eq!(status.peer_groups, 0);
        assert_eq!(status.best_height, Some(0));
        assert_eq!(status.best_peer_height, None);
        assert_eq!(status.resource_cache_entries, 0);
        assert_eq!(status.resource_cache_bytes, 0);
        assert_eq!(status.resource_cache_evicted, 0);
        assert!(path.join("hns/headers.sqlite").exists());
        assert!(path.join("hns/peers.sqlite").exists());

        let json = sync_status(path.to_str().unwrap());
        assert!(json.contains(r#""status":"idle""#));
        assert!(json.contains(r#""failed":0"#));
        assert!(json.contains(r#""failures":[]"#));
        assert!(json.contains(r#""peerCount":0"#));
        assert!(json.contains(r#""peerGroups":0"#));
        assert!(json.contains(r#""bestHeight":0"#));
        assert!(json.contains(r#""resourceCacheEntries":0"#));
        assert!(json.contains(r#""resourceCacheBytes":0"#));
        assert!(json.contains(r#""resourceCacheEvicted":0"#));

        cleanup_dir(&path);
    }

    #[test]
    fn sync_status_initializes_persistent_stores_without_network() {
        let path = temp_dir_path("sync-status");

        let json = sync_status(path.to_str().unwrap());

        assert!(json.contains(r#""status":"idle""#));
        assert!(json.contains(r#""bestHeight":0"#));
        assert!(json.contains(r#""peerCount":0"#));
        assert!(json.contains(r#""failures":[]"#));
        assert!(path.join("hns/headers.sqlite").exists());
        assert!(path.join("hns/peers.sqlite").exists());

        cleanup_dir(&path);
    }

    #[test]
    fn testnet_sync_status_uses_isolated_storage_and_genesis() {
        let path = temp_dir_path("sync-status-testnet");

        let json = sync_status_for_network(path.to_str().unwrap(), NetworkKind::Testnet);

        assert!(json.contains(r#""network":"testnet""#));
        assert!(json.contains(r#""bestHeight":0"#));
        assert!(path.join("hns-testnet/headers.sqlite").exists());
        assert!(path.join("hns-testnet/peers.sqlite").exists());
        assert!(!path.join("hns/headers.sqlite").exists());

        cleanup_dir(&path);
    }

    #[test]
    fn regtest_sync_seeds_loopback_peers() {
        let path = temp_dir_path("sync-once-regtest");

        let status = sync_once_with_options(
            path.to_str().unwrap(),
            NetworkKind::Regtest,
            true,
            Duration::from_millis(1),
            DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
        );

        assert_eq!(status.network, NetworkKind::Regtest);
        assert_eq!(status.best_height, Some(0));
        assert!(status.peer_count >= 1);
        assert!(path.join("hns-regtest/headers.sqlite").exists());

        cleanup_dir(&path);
    }

    #[test]
    fn cached_sync_status_classifier_reports_up_to_date_without_network() {
        assert_eq!(
            classify_cached_sync_status(Some(335_591), Some(335_591)),
            "up_to_date",
        );
        assert_eq!(
            classify_cached_sync_status(Some(335_591), Some(335_590)),
            "up_to_date",
        );
        assert_eq!(
            classify_cached_sync_status(Some(335_590), Some(335_591)),
            "syncing",
        );
        assert_eq!(classify_cached_sync_status(Some(0), Some(0)), "idle");
        assert_eq!(classify_cached_sync_status(Some(10), None), "syncing");
    }

    #[test]
    fn live_proof_peer_selection_ignores_zero_height_failed_peers() {
        let stale: SocketAddr = "1.1.1.2:12038".parse().unwrap();
        let current: SocketAddr = "1.1.1.3:12038".parse().unwrap();
        let private: SocketAddr = "127.0.0.3:12038".parse().unwrap();
        let mut peers = PeerManager::default();
        for _ in 0..32 {
            peers.record_transient_failure(stale);
        }
        peers.record_success(current, Height(336_034), 1_000);
        peers.record_success(private, Height(336_034), 1_000);
        let network = hns_core::network::mainnet();

        let selected = select_live_proof_peers(&peers, &network, 8, 1_100, Height(336_034));

        assert_eq!(selected, vec![current]);
    }

    #[test]
    fn sync_status_json_reports_peer_failures() {
        let status = NativeSyncStatus {
            network: NetworkKind::Mainnet,
            status: "peer_failed",
            attempted: 1,
            successful: 0,
            accepted: 0,
            failed: 1,
            peer_count: 1,
            peer_groups: 1,
            best_height: Some(0),
            best_peer_height: None,
            estimated_tip_height: Some(335_684),
            resource_cache_entries: 0,
            resource_cache_bytes: 0,
            resource_cache_evicted: 0,
            error: Some("all 1 attempted sync peers failed; see failures".to_owned()),
            failures: vec![NativePeerFailure {
                address: "127.0.0.1:12038".to_owned(),
                stage: "connect",
                error: "connection \"closed\"\n".to_owned(),
            }],
        };

        let json = status.to_json();

        assert!(json.contains(r#""status":"peer_failed""#));
        assert!(json.contains(r#""failed":1"#));
        assert!(json.contains(r#""estimatedTipHeight":335684"#));
        assert!(json.contains(r#""error":"all 1 attempted sync peers failed; see failures""#,));
        assert!(json.contains(
            r#""failures":[{"address":"127.0.0.1:12038","stage":"connect","error":"connection \"closed\"\n"}]"#,
        ));
    }

    #[test]
    fn sync_status_classifier_reports_up_to_date_and_peer_failed() {
        assert_eq!(
            classify_sync_status(4, 1, 0, 3, false, Some(335_591), Some(335_591)),
            "up_to_date",
        );
        assert_eq!(
            classify_sync_status(4, 1, 2, 3, false, Some(335_591), Some(335_591)),
            "synced",
        );
        assert_eq!(
            classify_sync_status(4, 1, 2, 3, false, Some(45_000), Some(335_684)),
            "syncing",
        );
        assert_eq!(
            classify_sync_status(4, 1, 2, 3, false, Some(92_000), None),
            "syncing",
        );
        assert_eq!(
            classify_sync_status(4, 1, 0, 3, false, Some(93_344), Some(335_684)),
            "syncing",
        );
        assert_eq!(
            classify_sync_status(4, 0, 0, 4, false, Some(0), Some(335_684)),
            "peer_failed",
        );
        assert_eq!(
            classify_sync_status(4, 0, 0, 2, false, Some(0), Some(335_684)),
            "attempted",
        );
        assert_eq!(
            classify_sync_status(0, 0, 0, 0, true, None, None),
            "seed_failed",
        );
        assert_eq!(classify_sync_status(0, 0, 0, 0, false, None, None), "idle");
    }

    #[test]
    fn sync_once_enforces_resource_cache_limit_and_clear_removes_cache() {
        let path = temp_dir_path("resource-cache-limit");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let alpha_hash = NameHash::from_name("alpha").unwrap();
        let beta_hash = NameHash::from_name("beta").unwrap();
        let anchor_root = Hash::new([3; 32]);
        let anchor_height = store_best_header_with_tree_root(&base, anchor_root);
        resources
            .insert(
                VerifiedResourceValue::inclusion(
                    "alpha".to_owned(),
                    alpha_hash,
                    vec![1, 2, 3, 4, 5, 6],
                )
                .with_anchor(anchor_root, anchor_height),
            )
            .unwrap();
        resources
            .insert(
                VerifiedResourceValue::inclusion("beta".to_owned(), beta_hash, vec![7, 8])
                    .with_anchor(anchor_root, anchor_height),
            )
            .unwrap();

        let status = sync_once_with_options(
            path.to_str().unwrap(),
            NetworkKind::Mainnet,
            false,
            Duration::from_millis(1),
            2,
        );

        assert_eq!(status.resource_cache_evicted, 1);
        assert_eq!(status.resource_cache_entries, 1);
        assert_eq!(status.resource_cache_bytes, 2);

        let clear_json = clear_resolver_cache(path.to_str().unwrap());
        assert!(clear_json.contains(r#""status":"cleared""#));
        assert!(clear_json.contains(r#""resourceCacheEntries":0"#));
        assert!(clear_json.contains(r#""resourceCacheBytes":0"#));

        cleanup_dir(&path);
    }

    #[test]
    fn sync_once_prunes_resource_cache_entries_not_on_best_chain() {
        let path = temp_dir_path("resource-cache-reorg");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let alpha_hash = NameHash::from_name("alpha").unwrap();
        resources
            .insert(
                VerifiedResourceValue::inclusion("alpha".to_owned(), alpha_hash, vec![1, 2])
                    .with_anchor(hns_core::Hash::new([9; 32]), hns_core::Height(0)),
            )
            .unwrap();

        let status = sync_once_with_options(
            path.to_str().unwrap(),
            NetworkKind::Mainnet,
            false,
            Duration::from_millis(1),
            DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
        );

        assert_eq!(status.resource_cache_evicted, 1);
        assert_eq!(status.resource_cache_entries, 0);
        assert_eq!(status.resource_cache_bytes, 0);

        cleanup_dir(&path);
    }

    #[test]
    fn sync_once_keeps_resource_cache_entries_on_recent_canonical_chain() {
        let path = temp_dir_path("resource-cache-recent-canonical");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let older_root = Hash::new([3; 32]);
        let current_root = Hash::new([4; 32]);
        let heights = store_canonical_headers_with_tree_roots(&base, &[older_root, current_root]);
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let alpha_hash = NameHash::from_name("alpha").unwrap();
        let beta_hash = NameHash::from_name("beta").unwrap();
        resources
            .insert(
                VerifiedResourceValue::inclusion("alpha".to_owned(), alpha_hash, vec![1, 2])
                    .with_anchor(older_root, heights[0]),
            )
            .unwrap();
        resources
            .insert(
                VerifiedResourceValue::inclusion("beta".to_owned(), beta_hash, vec![3])
                    .with_anchor(current_root, heights[1]),
            )
            .unwrap();

        let status = sync_once_with_options(
            path.to_str().unwrap(),
            NetworkKind::Mainnet,
            false,
            Duration::from_millis(1),
            DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
        );

        assert_eq!(status.resource_cache_evicted, 0);
        assert_eq!(status.resource_cache_entries, 2);
        assert_eq!(status.resource_cache_bytes, 3);

        cleanup_dir(&path);
    }

    #[test]
    fn sync_once_prunes_resource_cache_entries_not_on_recent_canonical_chain() {
        let path = temp_dir_path("resource-cache-stale-tip");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let current_root = Hash::new([4; 32]);
        let current_height = store_best_header_with_tree_root(&base, current_root);
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let alpha_hash = NameHash::from_name("alpha").unwrap();
        let beta_hash = NameHash::from_name("beta").unwrap();
        resources
            .insert(
                VerifiedResourceValue::inclusion("alpha".to_owned(), alpha_hash, vec![1, 2])
                    .with_anchor(BlockHeader::mainnet_genesis().tree_root, Height(0)),
            )
            .unwrap();
        resources
            .insert(
                VerifiedResourceValue::inclusion("beta".to_owned(), beta_hash, vec![3])
                    .with_anchor(current_root, current_height),
            )
            .unwrap();

        let status = sync_once_with_options(
            path.to_str().unwrap(),
            NetworkKind::Mainnet,
            false,
            Duration::from_millis(1),
            DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
        );

        assert_eq!(status.resource_cache_evicted, 1);
        assert_eq!(status.resource_cache_entries, 1);
        assert_eq!(status.resource_cache_bytes, 1);

        cleanup_dir(&path);
    }

    #[test]
    fn hns_proof_details_reports_cached_resource_anchor_and_records() {
        let path = temp_dir_path("proof-details-cached");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let anchor_root = Hash::new([8; 32]);
        let anchor_height = store_best_header_with_tree_root(&base, anchor_root);
        let resource = owner_glue4_resource(&root_name, [127, 0, 0, 1]);
        resources
            .insert(
                VerifiedResourceValue::inclusion(root_name.clone(), name_hash, resource.clone())
                    .with_anchor(anchor_root, anchor_height),
            )
            .unwrap();

        let json = hns_proof_details(path.to_str().unwrap(), "www.welcome/");

        assert!(json.contains(r#""host":"www.welcome""#));
        assert!(json.contains(r#""name":"welcome""#));
        assert!(json.contains(&format!(r#""nameHash":"{}""#, name_hash.as_hash())));
        assert!(json.contains(r#""proofStatus":"verified""#));
        assert!(json.contains(r#""cacheStatus":"anchored_to_current_tip""#));
        assert!(json.contains(&format!(r#""treeRoot":"{}""#, anchor_root)));
        assert!(json.contains(r#""blockHeight":1"#));
        assert!(json.contains(&format!(r#""resourceValueHex":"{}""#, hex_lower(&resource))));
        assert!(json.contains(r#""recordTypes":["A","NS"]"#));
        assert!(json.contains(r#""type":"NS""#));
        assert!(json.contains(r#""type":"A""#));
        assert!(json.contains(r#""currentTip":{"height":1"#));

        cleanup_dir(&path);
    }

    #[test]
    fn hns_proof_details_reports_missing_resource_cache() {
        let path = temp_dir_path("proof-details-missing-cache");

        let json = hns_proof_details(path.to_str().unwrap(), "missing");

        assert!(json.contains(r#""host":"missing""#));
        assert!(json.contains(r#""name":"missing""#));
        assert!(json.contains(r#""proofStatus":"unavailable""#));
        assert!(json.contains(r#""cacheStatus":"resource_cache_missing""#));
        assert!(json.contains(r#""resourceValueHex":null"#));
        assert!(json.contains(r#""error":"resource cache is not initialized""#));

        cleanup_dir(&path);
    }

    #[test]
    fn sync_status_json_escapes_errors() {
        let json = NativeSyncStatus::error("bad \"path\"\n".to_owned()).to_json();

        assert!(json.contains(r#""status":"error""#));
        assert!(json.contains(r#""error":"bad \"path\"\n""#));
    }

    #[test]
    fn sync_status_error_preserves_the_requested_network() {
        let json = NativeSyncStatus::error_for(NetworkKind::Testnet, "failed".to_owned()).to_json();

        assert!(json.contains(r#""network":"testnet""#));
        assert!(json.contains(r#""status":"error""#));
    }

    #[test]
    fn origin_response_suppresses_spoofed_hns_tls_policy_origin_headers() {
        let response = origin_response(OriginResponse {
            status: 200,
            headers: vec![("X-HNS-TLS-Policy".to_owned(), "origin".to_owned())],
            body: b"ok".to_vec(),
            dane_decision: DaneDecision::WebPkiFallback,
            tls_inspection: None,
        });
        let text = String::from_utf8(response).unwrap();

        assert!(!text.contains("X-HNS-TLS-Policy: origin\r\n"));
        assert!(text.contains("X-HNS-TLS-Policy: webpki-fallback\r\n"));
    }

    #[test]
    fn origin_response_suppresses_the_entire_reserved_hns_header_namespace() {
        let response = origin_response(OriginResponse {
            status: 200,
            headers: vec![(
                "x-hns-future-security-metadata".to_owned(),
                "origin-controlled".to_owned(),
            )],
            body: b"ok".to_vec(),
            dane_decision: DaneDecision::WebPkiFallback,
            tls_inspection: None,
        });
        let text = String::from_utf8(response).unwrap();

        assert!(
            !text
                .to_ascii_lowercase()
                .contains("x-hns-future-security-metadata")
        );
    }

    #[test]
    fn origin_response_suppresses_spoofed_security_path_and_emits_native_value() {
        let response = origin_response_with_resolver_policy_and_trace(
            OriginResponse {
                status: 200,
                headers: vec![(
                    HNS_SECURITY_PATH_HEADER.to_owned(),
                    "stateless-dane".to_owned(),
                )],
                body: b"ok".to_vec(),
                dane_decision: DaneDecision::Matched(TlsaUsage::DaneEe),
                tls_inspection: None,
            },
            None,
            Some("dane-authoritative-doh"),
            "{}",
        );
        let text = String::from_utf8(response).unwrap();

        assert!(!text.contains("X-HNS-Security-Path: stateless-dane\r\n"));
        assert_eq!(
            text.matches("X-HNS-Security-Path: dane-authoritative-doh\r\n")
                .count(),
            1,
        );
    }

    #[test]
    fn upgrade_response_preserves_canonical_websocket_headers_only() {
        let response = upgrade_response_head_with_resolver_policy_and_trace(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Connection: Upgrade, X-Hop\r\n\
              Upgrade: websocket\r\n\
              X-Hop: secret\r\n\
              X-HNS-Security-Path: spoofed\r\n\
              Sec-WebSocket-Accept: accepted\r\n\r\n",
            &DaneDecision::NoTlsa,
            None,
            "{}",
        );
        let text = String::from_utf8(response).unwrap();

        assert_eq!(text.matches("Connection: Upgrade\r\n").count(), 1);
        assert_eq!(text.matches("Upgrade: websocket\r\n").count(), 1);
        assert!(text.contains("Sec-WebSocket-Accept: accepted\r\n"));
        assert!(!text.contains("X-Hop:"));
        assert!(!text.contains("Connection: Upgrade, X-Hop"));
        assert!(!text.contains(HNS_SECURITY_PATH_HEADER));
    }

    #[test]
    fn origin_response_reports_hns_resolver_policy_after_tls_policy() {
        let response = origin_response_with_resolver_policy(
            OriginResponse {
                status: 200,
                headers: Vec::new(),
                body: b"ok".to_vec(),
                dane_decision: DaneDecision::Matched(hns_dane::TlsaUsage::DaneEe),
                tls_inspection: None,
            },
            Some("hns-doh-compat"),
        );
        let text = String::from_utf8(response).unwrap();

        assert!(
            text.contains("X-HNS-TLS-Policy: dane\r\nX-HNS-Resolver-Policy: hns-doh-compat\r\n",)
        );
    }

    #[test]
    fn gateway_headers_strip_internal_control_headers() {
        let parsed = parse_gateway_headers(
            "Accept: text/html\r\n\
             X-HNS-Browser-Strict-Mode: 1\r\n\
             X-HNS-Browser-DoH-Resolver: https://resolver.example/dns-query\r\n\
             X-HNS-Browser-Stateless-DANE: 1\r\n\
             X-HNS-Security-Path: dane-authoritative-doh\r\n",
        )
        .unwrap();

        assert!(parsed.strict_hns_mode);
        assert!(parsed.stateless_dane_certificates);
        assert_eq!(parsed.network, NetworkKind::Mainnet);
        assert_eq!(
            parsed.doh_endpoint,
            HnsDohEndpoint {
                host: "resolver.example".to_owned(),
                port: 443,
                path_and_query: "/dns-query".to_owned(),
            },
        );
        assert_eq!(
            parsed.headers,
            vec![("Accept".to_owned(), "text/html".to_owned())]
        );
    }

    #[test]
    fn stateless_dane_roots_only_use_latest_forty_headers() {
        let base = temp_dir_path("stateless-dane-roots");
        std::fs::create_dir_all(&base).unwrap();
        let roots = (1u8..=41u8)
            .map(|byte| Hash::new([byte; 32]))
            .collect::<Vec<_>>();
        store_canonical_headers_with_tree_roots(&base, &roots);

        let recent = recent_stateless_dane_tree_roots(&base).unwrap();

        assert_eq!(recent.len(), MAX_STATELESS_DANE_ROOTS);
        assert!(!recent.contains(&roots[0].into_bytes()));
        assert!(recent.contains(&roots[1].into_bytes()));
        assert!(recent.contains(&roots[40].into_bytes()));
        cleanup_dir(&base);
    }

    #[test]
    fn default_hns_doh_endpoint_uses_working_zorro_node() {
        let endpoint = HnsDohEndpoint::default();

        assert_eq!(endpoint.host, "zorro.hnsdoh.com");
        assert_eq!(endpoint.port, 443);
        assert_eq!(endpoint.path_and_query, "/dns-query");
    }

    #[test]
    fn authoritative_doh_uses_hns_proof_tlsa_without_webpki_fallback() {
        let record = TlsaRecord {
            usage: TlsaUsage::DaneEe,
            selector: TlsaSelector::SubjectPublicKeyInfo,
            matching: TlsaMatching::Sha256,
            association_data: vec![0x36; 32],
        };
        let endpoint = AuthoritativeDohEndpoint {
            ns: DnsName::from_ascii("ns1.denuoweb").unwrap(),
            host: "denuoweb".to_owned(),
            connect_addr: "35.212.156.128".parse().unwrap(),
            port: 8443,
            path_and_query: "/dns-query".to_owned(),
            tls_authentication: AuthoritativeDohTlsAuthentication::HnsProofTlsa(vec![
                record.clone(),
            ]),
        };

        let validation = authoritative_doh_tls_validation(&endpoint);

        assert_eq!(validation.mode, hns_dane::DomainTrustMode::HnsStrict);
        assert!(validation.dnssec_secure);
        assert_eq!(validation.tlsa_records, vec![record]);
        assert_eq!(validation.tlsa_source, Some(TlsaRecordSource::HnsProofTxt));
        assert_eq!(validation.service_port, 8443);
        assert_eq!(
            authoritative_doh_endpoint_display(&endpoint),
            "https://denuoweb:8443/dns-query via 35.212.156.128 [HNS-proof TLSA]"
        );
    }

    #[test]
    fn authoritative_doh_without_proof_tlsa_keeps_webpki_validation() {
        let endpoint = AuthoritativeDohEndpoint {
            ns: DnsName::from_ascii("ns1.welcome").unwrap(),
            host: "doh.example".to_owned(),
            connect_addr: "203.0.113.53".parse().unwrap(),
            port: 443,
            path_and_query: "/dns-query".to_owned(),
            tls_authentication: AuthoritativeDohTlsAuthentication::WebPki,
        };

        assert_eq!(
            authoritative_doh_tls_validation(&endpoint),
            TlsValidation::default()
        );
    }

    #[test]
    fn gateway_headers_reject_invalid_doh_endpoint() {
        assert!(matches!(
            parse_gateway_headers(
                "X-HNS-Browser-DoH-Resolver: http://resolver.example/dns-query\r\n"
            ),
            Err("DoH resolver must be an HTTPS URL")
        ));
    }

    #[test]
    fn gateway_headers_parse_internal_network() {
        let parsed = parse_gateway_headers("X-HNS-Browser-Network: regtest\r\n").unwrap();

        assert_eq!(parsed.network, NetworkKind::Regtest);
        assert!(parsed.headers.is_empty());
    }

    #[test]
    fn gateway_headers_reject_invalid_network() {
        assert!(matches!(
            parse_gateway_headers("X-HNS-Browser-Network: staging\r\n"),
            Err("Handshake network is invalid")
        ));
    }

    #[test]
    fn gateway_headers_default_doh_path_when_url_has_no_path() {
        let parsed =
            parse_gateway_headers("X-HNS-Browser-DoH-Resolver: https://resolver.example\r\n")
                .unwrap();

        assert_eq!(parsed.doh_endpoint.path_and_query, "/dns-query");
    }

    #[test]
    fn origin_response_includes_resolution_trace_headers() {
        let response = origin_response_with_resolver_policy_and_trace(
            OriginResponse {
                status: 200,
                headers: Vec::new(),
                body: b"ok".to_vec(),
                dane_decision: DaneDecision::NoTlsa,
                tls_inspection: None,
            },
            None,
            None,
            r#"{"mode":"strict","fallback":{"used":false}}"#,
        );
        let text = String::from_utf8(response).unwrap();

        assert!(text.contains("X-HNS-Resolver-Mode: strict\r\n"));
        assert!(text.contains("X-HNS-DoH-Fallback: no\r\n"));
        assert!(text.contains(
            "X-HNS-Resolution-Trace: {\"mode\":\"strict\",\"fallback\":{\"used\":false}}\r\n",
        ));
    }

    #[test]
    fn resolution_trace_reports_authoritative_dns_attempts() {
        let dns_trace = DnsTraceRecorder::default();
        dns_trace.push(DnsTraceEvent {
            protocol: "udp53",
            server: "192.0.2.53:53".to_owned(),
            question_name: Some("nathan.woodburn".to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "timeout".to_owned(),
            elapsed_ms: 901,
            error: Some("operation timed out".to_owned()),
        });
        dns_trace.push(DnsTraceEvent {
            protocol: "tcp53",
            server: "192.0.2.53:53".to_owned(),
            question_name: Some("nathan.woodburn".to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "transport_error".to_owned(),
            elapsed_ms: 12,
            error: Some("connection refused".to_owned()),
        });
        dns_trace.push(DnsTraceEvent {
            protocol: "dns_interception_probe",
            server: "192.0.2.1:53".to_owned(),
            question_name: Some(DNS_INTERCEPTION_PROBE_NAME.to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "detected".to_owned(),
            elapsed_ms: 7,
            error: Some(
                "received a matching DNS reply from a non-routable TEST-NET destination".to_owned(),
            ),
        });
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "https",
                host: "nathan.woodburn",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Strict,
            None,
            TlsTraceInput::default(),
            Some(&GatewayError::Resolver(ResolverError::DnsTransport(
                "operation timed out".to_owned(),
            ))),
            &FallbackMarker::default(),
            &dns_trace,
        );

        assert!(trace.contains(
            r#""authoritativeDns":{"udp53":"timeout","tcp53":"transport_error","doh":"not_attempted"}"#
        ));
        assert!(trace.contains(r#""nameserverCandidates":["192.0.2.53:53"]"#));
        assert!(trace.contains(r#""port53Interception":"detected""#));
        assert!(trace.contains(r#""protocol":"udp53","server":"192.0.2.53:53""#));
        assert!(trace.contains(r#""questionName":"nathan.woodburn","questionType":1"#));
        assert!(trace.contains(r#""status":"timeout""#));
        assert!(trace.contains(r#""elapsedMs":901"#));
    }

    #[test]
    fn security_path_uses_effective_svcb_port_and_last_successful_tlsa_transport() {
        let input = GatewayHttpRequestInput {
            data_dir: "/tmp",
            method: "GET",
            scheme: "https",
            host: "denuoweb",
            port: 443,
            path_and_query: "/",
            header_text: "",
            body: &[],
        };
        let tlsa_owner = "_8443._tcp.denuoweb";
        let events = vec![
            DnsTraceEvent {
                protocol: "authoritative_doh",
                server: "https://denuoweb:8443/dns-query".to_owned(),
                question_name: Some(tlsa_owner.to_owned()),
                question_type: Some(RecordType::Tlsa.code()),
                status: "ok".to_owned(),
                elapsed_ms: 10,
                error: None,
            },
            DnsTraceEvent {
                protocol: "hns_doh",
                server: "https://resolver.example/dns-query".to_owned(),
                question_name: Some("denuoweb".to_owned()),
                question_type: Some(RecordType::A.code()),
                status: "ok".to_owned(),
                elapsed_ms: 11,
                error: None,
            },
            DnsTraceEvent {
                protocol: "tcp53",
                server: "35.212.156.128:53".to_owned(),
                question_name: Some(tlsa_owner.to_owned()),
                question_type: Some(RecordType::Tlsa.code()),
                status: "ok".to_owned(),
                elapsed_ms: 12,
                error: None,
            },
        ];

        assert_eq!(
            security_path_name(
                &input,
                8443,
                &DaneDecision::Matched(TlsaUsage::DaneEe),
                &events,
            ),
            Some("dane-authoritative-dns53"),
        );
    }

    #[test]
    fn security_path_distinguishes_third_party_and_actual_stateless_dane() {
        let input = GatewayHttpRequestInput {
            data_dir: "/tmp",
            method: "GET",
            scheme: "https",
            host: "denuoweb",
            port: 443,
            path_and_query: "/",
            header_text: "",
            body: &[],
        };
        let events = vec![DnsTraceEvent {
            protocol: "hns_doh",
            server: "https://resolver.example/dns-query".to_owned(),
            question_name: Some("_443._tcp.denuoweb".to_owned()),
            question_type: Some(RecordType::Tlsa.code()),
            status: "ok".to_owned(),
            elapsed_ms: 10,
            error: None,
        }];

        assert_eq!(
            security_path_name(
                &input,
                input.port,
                &DaneDecision::Matched(TlsaUsage::DaneEe),
                &events,
            ),
            Some("dane-third-party-doh"),
        );
        assert_eq!(
            security_path_name(
                &input,
                input.port,
                &DaneDecision::StatelessMatched(TlsaUsage::DaneEe),
                &events,
            ),
            Some("stateless-dane"),
        );
    }

    #[test]
    fn http_security_path_uses_later_aaaa_transport_after_empty_a_lookup() {
        let input = GatewayHttpRequestInput {
            data_dir: "/tmp",
            method: "GET",
            scheme: "http",
            host: "denuoweb",
            port: 80,
            path_and_query: "/",
            header_text: "",
            body: &[],
        };
        let events = vec![
            DnsTraceEvent {
                protocol: "authoritative_doh",
                server: "https://denuoweb:8443/dns-query".to_owned(),
                question_name: Some("denuoweb".to_owned()),
                question_type: Some(RecordType::A.code()),
                status: "ok".to_owned(),
                elapsed_ms: 10,
                error: None,
            },
            DnsTraceEvent {
                protocol: "tcp53",
                server: "35.212.156.128:53".to_owned(),
                question_name: Some("denuoweb".to_owned()),
                question_type: Some(RecordType::Aaaa.code()),
                status: "ok".to_owned(),
                elapsed_ms: 12,
                error: None,
            },
        ];

        assert_eq!(
            security_path_name(&input, input.port, &DaneDecision::NoTlsa, &events),
            Some("hns-authoritative-dns53"),
        );
    }

    #[test]
    fn resolution_trace_reports_hns_resource_source() {
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "https",
                host: "crewball",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Strict,
            Some(&ResolutionAnswer {
                name: DnsName::from_ascii("crewball").unwrap(),
                records: vec![address_record("crewball", [35, 212, 156, 128])],
                secure: true,
            }),
            TlsTraceInput::default(),
            None,
            &FallbackMarker::default(),
            &DnsTraceRecorder::default(),
        );

        assert!(trace.contains(r#""resolutionSource":"hns_resource""#));
        assert!(trace.contains(
            r#""authoritativeDns":{"udp53":"not_attempted","tcp53":"not_attempted","doh":"not_attempted"}"#
        ));
    }

    #[test]
    fn resolution_trace_reports_later_selected_aaaa_origin_address() {
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "http",
                host: "crewball",
                port: 80,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Strict,
            Some(&ResolutionAnswer {
                name: DnsName::from_ascii("crewball").unwrap(),
                records: Vec::new(),
                secure: true,
            }),
            TlsTraceInput {
                origin_address: Some("2001:db8::20"),
                ..TlsTraceInput::default()
            },
            None,
            &FallbackMarker::default(),
            &DnsTraceRecorder::default(),
        );

        assert!(trace.contains(r#""originAddress":"found""#));
    }

    #[test]
    fn resolution_trace_reports_authoritative_doh_source() {
        let dns_trace = DnsTraceRecorder::default();
        dns_trace.push(DnsTraceEvent {
            protocol: "authoritative_doh",
            server: "https://ns1.crewball/dns-query via 203.0.113.53".to_owned(),
            question_name: Some("crewball".to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "ok".to_owned(),
            elapsed_ms: 42,
            error: None,
        });
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "https",
                host: "crewball",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Strict,
            Some(&ResolutionAnswer {
                name: DnsName::from_ascii("crewball").unwrap(),
                records: vec![address_record("crewball", [203, 0, 113, 20])],
                secure: true,
            }),
            TlsTraceInput::default(),
            None,
            &FallbackMarker::default(),
            &dns_trace,
        );

        assert!(trace.contains(r#""resolutionSource":"authoritative_doh""#));
        assert!(trace.contains(
            r#""authoritativeDns":{"udp53":"not_attempted","tcp53":"not_attempted","doh":"ok"}"#
        ));
    }

    #[test]
    fn resolution_trace_source_uses_exact_address_question_not_other_doh_success() {
        let dns_trace = DnsTraceRecorder::default();
        dns_trace.push(DnsTraceEvent {
            protocol: "tcp53",
            server: "203.0.113.53:53".to_owned(),
            question_name: Some("crewball".to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "ok".to_owned(),
            elapsed_ms: 42,
            error: None,
        });
        dns_trace.push(DnsTraceEvent {
            protocol: "authoritative_doh",
            server: "https://crewball:8443/dns-query via 203.0.113.53".to_owned(),
            question_name: Some("_443._tcp.crewball".to_owned()),
            question_type: Some(RecordType::Tlsa.code()),
            status: "ok".to_owned(),
            elapsed_ms: 20,
            error: None,
        });
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "https",
                host: "crewball",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Strict,
            Some(&ResolutionAnswer {
                name: DnsName::from_ascii("crewball").unwrap(),
                records: vec![address_record("crewball", [203, 0, 113, 20])],
                secure: true,
            }),
            TlsTraceInput::default(),
            None,
            &FallbackMarker::default(),
            &dns_trace,
        );

        assert!(trace.contains(r#""resolutionSource":"authoritative_dns""#));
    }

    #[test]
    fn resolution_trace_reports_icann_doh_source_without_hns_proof() {
        let dns_trace = DnsTraceRecorder::default();
        dns_trace.push(DnsTraceEvent {
            protocol: "icann_doh",
            server: "https://cloudflare-dns.com/dns-query".to_owned(),
            question_name: Some("dane-test.denuoweb.com".to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "ok".to_owned(),
            elapsed_ms: 42,
            error: None,
        });
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "https",
                host: "dane-test.denuoweb.com",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Compatibility,
            Some(&ResolutionAnswer {
                name: DnsName::from_ascii("dane-test.denuoweb.com").unwrap(),
                records: vec![address_record(
                    "dane-test.denuoweb.com",
                    [35, 212, 156, 128],
                )],
                secure: true,
            }),
            TlsTraceInput::default(),
            None,
            &FallbackMarker::default(),
            &dns_trace,
        );

        assert!(trace.contains(r#""nameClass":"icann""#));
        assert!(trace.contains(r#""hnsProof":"not_applicable""#));
        assert!(trace.contains(r#""resolutionSource":"trusted_icann_doh""#));
        assert!(trace.contains(r#""protocol":"icann_doh""#));
        assert!(!trace.contains(r#""resolutionSource":"authoritative_doh""#));
    }

    #[test]
    fn resolution_trace_reports_cached_hns_proof_when_later_resolution_fails() {
        let path = temp_dir_path("trace-cached-proof-after-resolution-failure");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        resources
            .insert(VerifiedResourceValue::inclusion(
                root_name.clone(),
                name_hash,
                owner_glue4_resource(&root_name, [127, 0, 0, 1]),
            ))
            .unwrap();

        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: path.to_str().unwrap(),
                method: "GET",
                scheme: "https",
                host: "www.welcome",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Strict,
            None,
            TlsTraceInput::default(),
            Some(&GatewayError::Resolver(ResolverError::DnsTransport(
                "operation timed out".to_owned(),
            ))),
            &FallbackMarker::default(),
            &DnsTraceRecorder::default(),
        );

        assert!(trace.contains(r#""root":"welcome""#));
        assert!(trace.contains(r#""hnsProof":"verified""#));
        cleanup_dir(&path);
    }

    #[test]
    fn resolution_trace_reports_stale_chain_fallback_reason_and_heights() {
        let path = temp_dir_path("trace-stale-chain-fallback");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let proof_root = Hash::new([12; 32]);
        let proof_height = store_best_header_with_tree_root(&base, proof_root);
        let target_height = proof_height.0 + LOCAL_CHAIN_CURRENTNESS_ALLOWED_LAG + 2;
        store_peer_height(&base, target_height);
        let marker = FallbackMarker::default();
        marker.mark("local_chain_not_current");

        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: path.to_str().unwrap(),
                method: "GET",
                scheme: "https",
                host: "future",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Compatibility,
            None,
            TlsTraceInput::default(),
            Some(&GatewayError::Resolver(ResolverError::LocalChainNotCurrent)),
            &marker,
            &DnsTraceRecorder::default(),
        );

        assert!(trace.contains(r#""hnsProof":"stale""#));
        assert!(trace.contains(&format!(r#""localBestHeight":{}"#, proof_height.0)));
        assert!(trace.contains(&format!(r#""targetHeight":{}"#, target_height)));
        assert!(trace.contains(r#""estimatedTargetHeight":"#));
        assert!(trace.contains(r#""localChainStale":true"#));
        assert!(trace.contains(
            r#""fallback":{"used":true,"type":"HNS_DOH","reason":"local_chain_not_current"}"#
        ));
        assert!(trace.contains(
            r#""finalError":"resolver error: local HNS chain is not current enough to determine current name state""#
        ));
        cleanup_dir(&path);
    }

    #[test]
    fn resolution_trace_marks_authoritative_dns_as_delegated() {
        let dns_trace = DnsTraceRecorder::default();
        dns_trace.push(DnsTraceEvent {
            protocol: "udp53",
            server: "192.0.2.53:53".to_owned(),
            question_name: Some("denuoweb".to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "ok".to_owned(),
            elapsed_ms: 19,
            error: None,
        });
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "https",
                host: "denuoweb",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Compatibility,
            Some(&ResolutionAnswer {
                name: DnsName::from_ascii("denuoweb").unwrap(),
                records: vec![address_record("denuoweb", [35, 212, 156, 128])],
                secure: true,
            }),
            TlsTraceInput::default(),
            None,
            &FallbackMarker::default(),
            &dns_trace,
        );

        assert!(trace.contains(r#""delegation":true"#));
        assert!(trace.contains(r#""resourceRecords":["A"]"#));
        assert!(trace.contains(r#""fallback":{"used":false"#));
    }

    #[test]
    fn resolution_trace_reports_tlsa_and_dane_details() {
        let tlsa = TlsaRecord {
            usage: TlsaUsage::DaneEe,
            selector: TlsaSelector::SubjectPublicKeyInfo,
            matching: TlsaMatching::Sha256,
            association_data: vec![0xaa, 0xbb],
        };
        let mut tls = TlsValidation::hns_compatibility(true, vec![tlsa]);
        tls.service_port = 8443;
        let inspection = TlsCertificateInspection {
            end_entity_der: b"cert".to_vec(),
            end_entity_spki_der: b"spki".to_vec(),
            intermediate_der: vec![b"issuer".to_vec()],
            webpki_status: hns_dane::WebPkiStatus::Invalid,
        };
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "https",
                host: "nathan.woodburn",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Compatibility,
            None,
            TlsTraceInput {
                validation: Some(&tls),
                decision: Some(&DaneDecision::Matched(TlsaUsage::DaneEe)),
                inspection: Some(&inspection),
                origin_address: None,
            },
            None,
            &FallbackMarker::default(),
            &DnsTraceRecorder::default(),
        );

        assert!(trace.contains(r#""tlsaOwner":"_8443._tcp.nathan.woodburn""#));
        assert!(trace.contains(r#""tlsaEvaluated":true"#));
        assert!(trace.contains(r#""tlsaStatus":"present""#));
        assert!(trace.contains(r#""tlsaBlockedBy":null"#));
        assert!(trace.contains(r#""tlsaFound":true"#));
        assert!(trace.contains(r#""dnssecSecure":true"#));
        assert!(trace.contains(
            r#""usage":"DANE-EE","selector":"SPKI","matching":"SHA-256","associationDataHex":"aabb""#
        ));
        assert!(trace.contains(r#""webPkiStatus":"invalid""#));
        assert!(trace.contains(&format!(r#""spkiSha256":"{}""#, sha256_hex(b"spki"))));
        assert!(trace.contains(r#""spkiDerHex":"73706b69""#));
        assert!(trace.contains(r#""intermediateCount":1"#));
        assert!(trace.contains(
            r#""dane":{"decision":"verified","matchedUsage":"DANE-EE","certificateMatch":"pass","webPkiFallback":false}"#
        ));
    }

    #[test]
    fn resolution_trace_marks_tlsa_not_evaluated_when_dnssec_fails_first() {
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "https",
                host: "namecity",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Compatibility,
            None,
            TlsTraceInput::default(),
            Some(&GatewayError::Resolver(ResolverError::DnssecFailed)),
            &FallbackMarker::default(),
            &DnsTraceRecorder::default(),
        );

        assert!(trace.contains(r#""tlsaOwner":"_443._tcp.namecity""#));
        assert!(trace.contains(r#""tlsaEvaluated":false"#));
        assert!(trace.contains(r#""tlsaStatus":"not_evaluated""#));
        assert!(trace.contains(r#""tlsaBlockedBy":"delegated_dnssec_validation_failed""#));
        assert!(trace.contains(r#""tlsaFound":false"#));
        assert!(trace.contains(r#""dane":{"decision":"not_evaluated""#));
    }

    #[test]
    fn resolution_trace_marks_expired_origin_certificate() {
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "https",
                host: "mercenary",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Compatibility,
            None,
            TlsTraceInput::default(),
            Some(&GatewayError::Transport(TransportError::Io(
                "invalid peer certificate: certificate expired: verification time 1783324451, but certificate is not valid after 1680922072".to_owned(),
            ))),
            &FallbackMarker::default(),
            &DnsTraceRecorder::default(),
        );

        assert!(trace.contains(r#""tlsaStatus":"not_evaluated""#));
        assert!(trace.contains(r#""tlsaBlockedBy":"origin_certificate_expired""#));
        assert!(trace.contains(
            r#""finalError":"transport error: origin I/O error: invalid peer certificate: certificate expired:"#
        ));
    }

    #[test]
    fn fallback_delegated_resolver_uses_doh_transport_on_nameserver_transport_error() {
        let answer = ResolutionAnswer {
            name: DnsName::from_ascii("nathan.woodburn").unwrap(),
            records: vec![address_record("nathan.woodburn", [103, 152, 197, 116])],
            secure: true,
        };
        let marker = FallbackMarker::default();
        let resolver = FallbackDelegatedResolver::new(
            TestDelegatedResolver::error(|| ResolverError::DnsTransport("closed".to_owned())),
            TestDelegatedResolver::answer(answer.clone()),
            marker.clone(),
        );

        let resolved = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "nathan.woodburn".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &test_delegation("woodburn"),
            )
            .unwrap();

        assert_eq!(resolved, answer);
        assert_eq!(
            marker.reason(),
            Some("authoritative_nameserver_transport_failed")
        );
    }

    #[test]
    fn fallback_delegated_resolver_skips_primary_after_root_fallback() {
        use std::sync::atomic::AtomicUsize;

        let primary_calls = Arc::new(AtomicUsize::new(0));
        let answer = ResolutionAnswer {
            name: DnsName::from_ascii("shakeshift").unwrap(),
            records: vec![address_record("shakeshift", [203, 0, 113, 10])],
            secure: true,
        };
        let resolver = FallbackDelegatedResolver::new(
            CountingErrorDelegatedResolver {
                calls: primary_calls.clone(),
                error: || ResolverError::DnsTransport("closed".to_owned()),
            },
            TestDelegatedResolver::answer(answer),
            FallbackMarker::default(),
        );

        resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "shakeshift".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &test_delegation("shakeshift"),
            )
            .unwrap();
        resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "_443._tcp.shakeshift".to_owned(),
                    qtype: RecordType::Tlsa.code(),
                },
                &test_delegation("shakeshift"),
            )
            .unwrap();

        assert_eq!(primary_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn fallback_resolver_uses_doh_on_proof_unavailable_in_compatibility_mode() {
        let marker = FallbackMarker::default();
        let answer = ResolutionAnswer {
            name: DnsName::from_ascii("welcome").unwrap(),
            records: vec![address_record("welcome", [127, 0, 0, 1])],
            secure: true,
        };
        let resolver = FallbackResolver::with_marker(
            TestResolver::error(|| ResolverError::ProofUnavailable),
            TestResolver::answer(answer.clone()),
            marker.clone(),
        );

        assert_eq!(
            resolver
                .resolve(&ResolutionRequest {
                    qname: "welcome".to_owned(),
                    qtype: RecordType::A.code(),
                })
                .unwrap(),
            answer,
        );
        assert_eq!(marker.reason(), Some("local_hns_proof_unavailable"));
    }

    #[test]
    fn compatibility_fallback_uses_doh_on_stale_cached_non_inclusion() {
        let path = temp_dir_path("stale-negative-compat-fallback");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "future".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let proof_root = Hash::new([9; 32]);
        let proof_height = store_best_header_with_tree_root(&base, proof_root);
        let target_height = proof_height.0 + LOCAL_CHAIN_CURRENTNESS_ALLOWED_LAG + 1;
        store_peer_height(&base, target_height);
        resources
            .insert(
                VerifiedResourceValue::non_inclusion(root_name.clone(), name_hash)
                    .with_anchor(proof_root, proof_height),
            )
            .unwrap();
        let marker = FallbackMarker::default();
        let fallback_answer = ResolutionAnswer {
            name: DnsName::from_ascii(&root_name).unwrap(),
            records: vec![address_record(&root_name, [203, 0, 113, 8])],
            secure: true,
        };
        let primary = DelegatingResolver::new(
            GatewayProofProvider::new(base.clone(), resources, NetworkKind::Mainnet),
            TestResolver::error(|| ResolverError::ProofUnavailable),
        );
        let resolver = FallbackResolver::with_marker(
            primary,
            TestResolver::answer(fallback_answer.clone()),
            marker.clone(),
        );

        let resolved = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: RecordType::A.code(),
            })
            .unwrap();

        assert_eq!(resolved, fallback_answer);
        assert_eq!(marker.reason(), Some("local_chain_not_current"));
        cleanup_dir(&path);
    }

    #[test]
    fn compatibility_fallback_keeps_current_non_inclusion_as_name_not_found() {
        let path = temp_dir_path("current-negative-no-fallback");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "missing".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let proof_root = Hash::new([10; 32]);
        let proof_height = store_best_header_with_tree_root(&base, proof_root);
        store_peer_height(&base, proof_height.0 + LOCAL_CHAIN_CURRENTNESS_ALLOWED_LAG);
        resources
            .insert(
                VerifiedResourceValue::non_inclusion(root_name.clone(), name_hash)
                    .with_anchor(proof_root, proof_height),
            )
            .unwrap();
        let marker = FallbackMarker::default();
        let fallback_answer = ResolutionAnswer {
            name: DnsName::from_ascii(&root_name).unwrap(),
            records: vec![address_record(&root_name, [203, 0, 113, 9])],
            secure: true,
        };
        let primary = DelegatingResolver::new(
            GatewayProofProvider::new(base.clone(), resources, NetworkKind::Mainnet),
            TestResolver::error(|| ResolverError::ProofUnavailable),
        );
        let resolver = FallbackResolver::with_marker(
            primary,
            TestResolver::answer(fallback_answer),
            marker.clone(),
        );

        let error = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: RecordType::A.code(),
            })
            .unwrap_err();

        assert_eq!(error, ResolverError::NameNotFound);
        assert!(!marker.used());
        assert_eq!(marker.reason(), None);
        cleanup_dir(&path);
    }

    #[test]
    fn strict_resolver_reports_stale_cached_non_inclusion_without_fallback() {
        let path = temp_dir_path("stale-negative-strict");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "future-strict".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let proof_root = Hash::new([11; 32]);
        let proof_height = store_best_header_with_tree_root(&base, proof_root);
        store_peer_height(
            &base,
            proof_height.0 + LOCAL_CHAIN_CURRENTNESS_ALLOWED_LAG + 25,
        );
        resources
            .insert(
                VerifiedResourceValue::non_inclusion(root_name.clone(), name_hash)
                    .with_anchor(proof_root, proof_height),
            )
            .unwrap();
        let resolver = DelegatingResolver::new(
            GatewayProofProvider::new(base.clone(), resources, NetworkKind::Mainnet),
            TestResolver::error(|| ResolverError::ProofUnavailable),
        );

        let error = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: RecordType::A.code(),
            })
            .unwrap_err();

        assert_eq!(error, ResolverError::LocalChainNotCurrent);
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(error)),
            (
                503,
                "HNS Sync Incomplete",
                "The local HNS chain is not current enough to determine this name's current state.",
            ),
        );
        cleanup_dir(&path);
    }

    #[test]
    fn fallback_resolver_does_not_use_doh_on_name_not_found() {
        let marker = FallbackMarker::default();
        let answer = ResolutionAnswer {
            name: DnsName::from_ascii("missing").unwrap(),
            records: vec![address_record("missing", [203, 0, 113, 10])],
            secure: true,
        };
        let resolver = FallbackResolver::with_marker(
            TestResolver::error(|| ResolverError::NameNotFound),
            TestResolver::answer(answer),
            marker.clone(),
        );

        let error = resolver
            .resolve(&ResolutionRequest {
                qname: "missing".to_owned(),
                qtype: RecordType::A.code(),
            })
            .unwrap_err();

        assert_eq!(error, ResolverError::NameNotFound);
        assert!(!marker.used());
    }

    #[test]
    fn strict_resolver_keeps_proof_errors_fail_closed() {
        let resolver = TestResolver::error(|| ResolverError::ProofUnavailable);

        assert_eq!(
            resolver
                .resolve(&ResolutionRequest {
                    qname: "welcome".to_owned(),
                    qtype: RecordType::A.code(),
                })
                .unwrap_err(),
            ResolverError::ProofUnavailable,
        );
    }

    #[test]
    fn doh_response_parser_uses_ad_bit_for_secure_answers() {
        let qname = DnsName::from_ascii("nathan.woodburn").unwrap();
        let answer_record = address_record("nathan.woodburn", [103, 152, 197, 116]);
        let message = DnsMessage {
            header: DnsHeader {
                id: 0x1234,
                flags: DnsFlags::new(0x81a0),
                question_count: 1,
                answer_count: 1,
                authority_count: 0,
                additional_count: 2,
            },
            questions: vec![DnsQuestion {
                name: qname.clone(),
                record_type: RecordType::A,
                class: DNS_CLASS_IN,
            }],
            answers: vec![answer_record.clone()],
            authorities: Vec::new(),
            additionals: vec![
                ResourceRecord {
                    name: DnsName::root(),
                    record_type: RecordType::Unknown(DNS_OPT_RECORD_TYPE),
                    class: DEFAULT_DNS_UDP_PAYLOAD as u16,
                    ttl: DNSSEC_DO_FLAG,
                    rdata: vec![0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8],
                },
                ResourceRecord {
                    name: DnsName::root(),
                    record_type: RecordType::Unknown(24),
                    class: 255,
                    ttl: 0,
                    rdata: vec![0, 253, 0, 0, 0, 0, 0, 0],
                },
            ],
        };
        let body = message
            .encode(&DnsEncodeConfig {
                max_message_len: 4096,
            })
            .unwrap();

        let answer = doh_answer_from_body(0x1234, &qname, RecordType::A, &body).unwrap();

        assert!(answer.secure);
        assert_eq!(answer.records, vec![answer_record]);
    }

    #[test]
    fn doh_response_parser_returns_response_code_for_servfail() {
        let qname = DnsName::from_ascii("servfail.example").unwrap();
        let message = DnsMessage {
            header: DnsHeader {
                id: DOH_DNS_ID,
                flags: DnsFlags::new(0x8182),
                question_count: 1,
                answer_count: 0,
                authority_count: 0,
                additional_count: 0,
            },
            questions: vec![DnsQuestion {
                name: qname.clone(),
                record_type: RecordType::A,
                class: DNS_CLASS_IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        let body = message
            .encode(&DnsEncodeConfig {
                max_message_len: 4096,
            })
            .unwrap();

        assert_eq!(
            doh_answer_from_body(DOH_DNS_ID, &qname, RecordType::A, &body).unwrap_err(),
            ResolverError::DnsResponseCode(2),
        );
    }

    #[test]
    fn doh_http_status_allows_any_successful_2xx() {
        assert!(!doh_http_status_success(199));
        assert!(doh_http_status_success(200));
        assert!(doh_http_status_success(204));
        assert!(doh_http_status_success(299));
        assert!(!doh_http_status_success(300));
    }

    #[test]
    fn doh_response_requires_dns_message_content_type() {
        let mut response = OriginResponse {
            status: 200,
            headers: vec![(
                "Content-Type".to_owned(),
                "Application/DNS-Message".to_owned(),
            )],
            body: Vec::new(),
            dane_decision: DaneDecision::NoTlsa,
            tls_inspection: None,
        };

        assert!(doh_response_has_dns_message_content_type(&response));

        response.headers = vec![("Content-Type".to_owned(), "application/json".to_owned())];
        assert!(!doh_response_has_dns_message_content_type(&response));

        response.headers.clear();
        assert!(!doh_response_has_dns_message_content_type(&response));
    }

    #[test]
    fn doh_trace_requires_a_matching_dns_message_and_accepts_valid_2xx() {
        let qname = DnsName::from_ascii("denuoweb").unwrap();
        let query = build_doh_query(DOH_DNS_ID, &qname, RecordType::A).unwrap();
        let question = DnsMessage::parse(&query).unwrap().questions[0].clone();
        let body = DnsMessage {
            header: DnsHeader {
                id: DOH_DNS_ID,
                flags: DnsFlags::new(0x8180),
                question_count: 1,
                answer_count: 0,
                authority_count: 0,
                additional_count: 0,
            },
            questions: vec![question],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
        .encode(&DnsEncodeConfig {
            max_message_len: 4096,
        })
        .unwrap();
        let response = OriginResponse {
            status: 201,
            headers: vec![(
                "Content-Type".to_owned(),
                "application/dns-message".to_owned(),
            )],
            body,
            dane_decision: DaneDecision::NoTlsa,
            tls_inspection: None,
        };

        let valid = doh_trace_event(
            "authoritative_doh",
            "https://denuoweb:8443/dns-query".to_owned(),
            &query,
            1,
            &Ok(response.clone()),
        );
        assert_eq!(valid.status, "ok");

        let mut servfail_response = response.clone();
        servfail_response.body[3] = (servfail_response.body[3] & 0xf0) | 2;
        let servfail = doh_trace_event(
            "authoritative_doh",
            "https://denuoweb:8443/dns-query".to_owned(),
            &query,
            1,
            &Ok(servfail_response),
        );
        assert_eq!(servfail.status, "invalid_response");

        let invalid = doh_trace_event(
            "authoritative_doh",
            "https://denuoweb:8443/dns-query".to_owned(),
            &query,
            1,
            &Ok(OriginResponse {
                body: Vec::new(),
                ..response
            }),
        );
        assert_eq!(invalid.status, "invalid_response");
    }

    #[test]
    fn recursive_doh_query_uses_zero_dns_id_on_wire() {
        let qname = DnsName::from_ascii("dane-test.denuoweb.com").unwrap();
        let query = build_doh_query(0x1234, &qname, RecordType::A).unwrap();

        let (wire_query, original_id) = recursive_doh_query(&query).unwrap();
        let wire_message = DnsMessage::parse(&wire_query).unwrap();

        assert_eq!(original_id, 0x1234);
        assert_eq!(wire_message.header.id, DOH_DNS_ID);
        assert!(wire_message.header.flags.recursion_desired());

        let response = DnsMessage {
            header: DnsHeader {
                id: DOH_DNS_ID,
                flags: DnsFlags::new(0x8180),
                question_count: 1,
                answer_count: 0,
                authority_count: 0,
                additional_count: 0,
            },
            questions: wire_message.questions,
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
        .encode(&DnsEncodeConfig {
            max_message_len: 4096,
        })
        .unwrap();

        let restored = restore_doh_response_id(&response, original_id).unwrap();
        let restored_message = DnsMessage::parse(&restored).unwrap();
        assert_eq!(restored_message.header.id, 0x1234);
    }

    #[test]
    fn doh_query_requests_authentic_data_and_dnssec_records() {
        let qname = DnsName::from_ascii("dane-test.denuoweb.com").unwrap();
        let query = build_doh_query(0x1234, &qname, RecordType::A).unwrap();
        let message = DnsMessage::parse(&query).unwrap();

        assert_eq!(message.header.id, 0x1234);
        assert!(message.header.flags.recursion_desired());
        assert_ne!(message.header.flags.bits() & DNS_AUTHENTIC_DATA_FLAG, 0);
        assert_eq!(message.questions[0].name, qname);
        assert_eq!(message.questions[0].record_type, RecordType::A);
        assert_eq!(message.additionals.len(), 1);
        assert_eq!(
            message.additionals[0].record_type,
            RecordType::Unknown(DNS_OPT_RECORD_TYPE)
        );
        assert_ne!(message.additionals[0].ttl & DNSSEC_DO_FLAG, 0);
    }

    #[test]
    fn gateway_response_fails_closed_without_resolver_backend() {
        let path = temp_dir_path("gateway-empty");
        let response = gateway_http_response(GatewayHttpRequestInput {
            data_dir: path.to_str().unwrap(),
            method: "GET",
            scheme: "http",
            host: "welcome",
            port: 80,
            path_and_query: "/",
            header_text: "X-HNS-Browser-Strict-Mode: 1\r\n",
            body: &[],
        });
        let text = String::from_utf8(response).unwrap();

        assert!(text.starts_with("HTTP/1.1 503 HNS Proof Unavailable\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        cleanup_dir(&path);
    }

    #[test]
    fn gateway_response_rejects_malformed_forwarded_headers() {
        let path = temp_dir_path("gateway-bad-headers");
        let response = gateway_http_response(GatewayHttpRequestInput {
            data_dir: path.to_str().unwrap(),
            method: "GET",
            scheme: "http",
            host: "welcome",
            port: 80,
            path_and_query: "/",
            header_text: "not-a-header\r\n",
            body: &[],
        });
        let text = String::from_utf8(response).unwrap();

        assert!(text.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(text.ends_with("http://welcome/\n400 Bad Request\nrequest header is malformed\n"));
        assert!(matches!(
            parse_gateway_headers("X-Test: bad\0value\r\n"),
            Err("request header is invalid")
        ));
        cleanup_dir(&path);
    }

    #[test]
    fn gateway_errors_are_mapped_to_actionable_hns_stages() {
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(ResolverError::ProofUnavailable)),
            (
                503,
                "HNS Proof Unavailable",
                "No current verified HNS proof is available for this name.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(ResolverError::NameNotFound)),
            (
                404,
                "HNS Name Not Found",
                "A verified HNS non-inclusion proof says this name does not exist.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(ResolverError::NoNameserverAddress)),
            (
                502,
                "HNS Nameserver Unavailable",
                "No verified nameserver address is available for this HNS delegation.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(ResolverError::DnsTransport(
                "timeout".to_owned(),
            ))),
            (
                502,
                "HNS Nameserver Unavailable",
                "Delegated HNS nameserver transport failed closed.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(ResolverError::InvalidDnsResponse)),
            (
                502,
                "HNS Nameserver Response Invalid",
                "Delegated HNS nameserver response was invalid or lacked required secure denial data.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(ResolverError::DnssecFailed)),
            (
                502,
                "HNS DNSSEC Validation Failed",
                "Delegated HNS DNSSEC validation failed closed.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(ResolverError::InvalidResource(
                ResourceError::Malformed,
            ))),
            (
                502,
                "HNS Resource Invalid",
                "Verified HNS resource data is malformed or unsupported.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::InsecureResolution),
            (
                502,
                "HNS DNSSEC Validation Failed",
                "Secure HNS resolution was required but the resolver returned an insecure result.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::NoResolvedAddress),
            (
                502,
                "HNS Origin Address Missing",
                "Secure HNS resolution did not produce an origin A or AAAA address.",
            ),
        );
        assert_eq!(
            map_gateway_error_for_host("dane-test.denuoweb.com", &GatewayError::NoResolvedAddress),
            (
                502,
                "ICANN Origin Address Missing",
                "Secure ICANN DNS resolution did not produce an origin A or AAAA address.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Transport(TransportError::DaneFailed)),
            (
                502,
                "HNS DANE Validation Failed",
                "DANE/TLSA validation failed closed.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::UnsupportedSvcb),
            (
                502,
                "HNS HTTPS Service Unsupported",
                "HTTPS/SVCB service binding is malformed or requires unsupported transport policy.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Transport(TransportError::Io(
                "refused".to_owned(),
            ))),
            (
                502,
                "HNS Origin Transport Failed",
                "Origin connection failed closed.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Transport(TransportError::Io(
                "invalid peer certificate: certificate expired: verification time 1783324451, but certificate is not valid after 1680922072".to_owned(),
            ))),
            (
                502,
                "HNS Origin Certificate Expired",
                "Origin HTTPS certificate is expired; renew the certificate and retry.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Transport(TransportError::Http3(
                "frame error".to_owned(),
            ))),
            (
                502,
                "HNS HTTP/3 Transport Failed",
                "Origin HTTP/3 exchange failed closed.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Transport(TransportError::Quic(
                "handshake failed".to_owned(),
            ))),
            (
                502,
                "HNS QUIC Transport Failed",
                "Origin QUIC connection failed closed.",
            ),
        );
    }

    #[test]
    fn gateway_response_fetches_hns_http_from_persistent_resource_cache() {
        let path = temp_dir_path("gateway-http");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let anchor_root = Hash::new([5; 32]);
        let anchor_height = store_best_header_with_tree_root(&base, anchor_root);
        resources
            .insert(
                VerifiedResourceValue::inclusion(
                    root_name.clone(),
                    name_hash,
                    owner_glue4_resource(&root_name, [127, 0, 0, 1]),
                )
                .with_anchor(anchor_root, anchor_height),
            )
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 512];
            loop {
                let count = stream.read(&mut chunk).unwrap();
                request.extend_from_slice(&chunk[..count]);
                if String::from_utf8_lossy(&request).contains("\r\n\r\nhi") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request);
            assert!(request.starts_with("POST /path HTTP/1.1\r\n"));
            assert!(request.contains("Content-Type: text/plain\r\n"));
            assert!(request.contains("X-Test: yes\r\n"));
            assert!(request.contains("Content-Length: 2\r\n"));
            assert!(request.ends_with("\r\n\r\nhi"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
        });

        let response = gateway_http_response(GatewayHttpRequestInput {
            data_dir: path.to_str().unwrap(),
            method: "POST",
            scheme: "http",
            host: &root_name,
            port,
            path_and_query: "/path",
            header_text: "Content-Type: text/plain\r\nX-Test: yes\r\n",
            body: b"hi",
        });
        let text = String::from_utf8(response).unwrap();

        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.ends_with("\r\n\r\nok"));
        server.join().unwrap();
        cleanup_dir(&path);
    }

    #[test]
    fn gateway_response_rejects_non_tip_cached_resource_proof() {
        let path = temp_dir_path("gateway-http-recent-proof");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let proof_root = Hash::new([5; 32]);
        let newer_root = Hash::new([6; 32]);
        let heights = store_canonical_headers_with_tree_roots(&base, &[proof_root, newer_root]);
        resources
            .insert(
                VerifiedResourceValue::inclusion(
                    root_name.clone(),
                    name_hash,
                    owner_glue4_resource(&root_name, [127, 0, 0, 1]),
                )
                .with_anchor(proof_root, heights[0]),
            )
            .unwrap();

        let response = gateway_http_response(GatewayHttpRequestInput {
            data_dir: path.to_str().unwrap(),
            method: "GET",
            scheme: "http",
            host: &root_name,
            port: 80,
            path_and_query: "/recent",
            header_text: "X-HNS-Browser-Strict-Mode: 1\r\n",
            body: &[],
        });
        let text = String::from_utf8(response).unwrap();

        assert!(text.starts_with("HTTP/1.1 503 HNS Proof Unavailable\r\n"));
        cleanup_dir(&path);
    }

    #[test]
    fn gateway_response_streams_body_to_file_with_fixed_length_head() {
        let path = temp_dir_path("gateway-file-body");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let anchor_root = Hash::new([5; 32]);
        let anchor_height = store_best_header_with_tree_root(&base, anchor_root);
        resources
            .insert(
                VerifiedResourceValue::inclusion(
                    root_name.clone(),
                    name_hash,
                    owner_glue4_resource(&root_name, [127, 0, 0, 1]),
                )
                .with_anchor(anchor_root, anchor_height),
            )
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 512];
            loop {
                let count = stream.read(&mut chunk).unwrap();
                request.extend_from_slice(&chunk[..count]);
                if String::from_utf8_lossy(&request).contains("\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n4\r\nlive\r\n0\r\n\r\n",
                )
                .unwrap();
        });

        let body_path = path.join("response.body");
        let head = gateway_http_response_body_to_file(
            GatewayHttpRequestInput {
                data_dir: path.to_str().unwrap(),
                method: "GET",
                scheme: "http",
                host: &root_name,
                port,
                path_and_query: "/stream",
                header_text: "",
                body: &[],
            },
            &body_path,
        )
        .unwrap();
        let text = String::from_utf8(head).unwrap();

        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Length: 4\r\n"));
        assert!(text.contains("Content-Type: text/plain\r\n"));
        assert!(!text.contains("Transfer-Encoding"));
        assert_eq!(std::fs::read(&body_path).unwrap(), b"live");
        server.join().unwrap();
        cleanup_dir(&path);
    }

    #[test]
    fn gateway_response_fetches_live_proof_on_resource_cache_miss() {
        let path = temp_dir_path("gateway-live-proof");
        let base = path.join("hns-regtest");
        std::fs::create_dir_all(&base).unwrap();

        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let value = owner_glue4_resource(&root_name, [127, 0, 0, 1]);
        let name_state_value = name_state_value(&root_name, &value);
        let proof_root = urkel_value_root(name_hash.as_hash(), &name_state_value);
        let proof_height =
            store_best_header_for_network_with_tree_root(&base, NetworkKind::Regtest, proof_root);
        let remote_height = Height(proof_height.0 + 10);

        let proof_payload = urkel_exists_payload(&name_state_value);
        let proof_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proof_address = proof_listener.local_addr().unwrap();
        let proof_server = thread::spawn(move || {
            let (stream, _) = proof_listener.accept().unwrap();
            let mut peer = PeerConnection::new(stream, hns_core::network::regtest());
            assert!(matches!(peer.receive_packet().unwrap(), Packet::Version(_)));
            let version = VersionPacket {
                height: remote_height,
                ..VersionPacket::default()
            };
            peer.send_packet(&Packet::Version(version)).unwrap();
            assert_eq!(peer.receive_packet().unwrap(), Packet::Verack);
            peer.send_packet(&Packet::Verack).unwrap();
            match peer.receive_packet().unwrap() {
                Packet::GetProof(request) => {
                    assert_eq!(request.root, proof_root);
                    assert_eq!(request.key, name_hash.as_hash());
                    peer.send_packet(&Packet::Proof(ProofPacket {
                        root: request.root,
                        key: request.key,
                        proof: proof_payload,
                    }))
                    .unwrap();
                }
                other => panic!("unexpected proof peer packet: {other:?}"),
            }
        });

        let peer_store = SqlitePeerStore::open(base.join("peers.sqlite")).unwrap();
        let mut peers = PeerManager::default();
        peers.seed([proof_address]);
        peers.record_observed_height(proof_address, remote_height, now_unix_seconds());
        peer_store.save_manager(&peers).unwrap();

        let origin_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_port = origin_listener.local_addr().unwrap().port();
        let origin_server = thread::spawn(move || {
            let (mut stream, _) = origin_listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = [0_u8; 512];
            let count = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..count]);
            assert!(request.starts_with("GET /live HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nlive")
                .unwrap();
        });

        let response = gateway_http_response(GatewayHttpRequestInput {
            data_dir: path.to_str().unwrap(),
            method: "GET",
            scheme: "http",
            host: &root_name,
            port: origin_port,
            path_and_query: "/live",
            header_text: "X-HNS-Browser-Network: regtest\r\n",
            body: &[],
        });
        let text = String::from_utf8(response).unwrap();

        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.ends_with("\r\n\r\nlive"));
        let cached = SqliteResourceValueProvider::open(base.join("resources.sqlite"))
            .unwrap()
            .prove_resource_value(&root_name, name_hash)
            .unwrap();
        assert_eq!(cached.value, Some(value));
        assert_eq!(
            cached.anchor,
            Some(ResourceValueAnchor {
                tree_root: proof_root,
                height: proof_height,
            }),
        );
        let peer = peer_store.load_peer(proof_address).unwrap().unwrap();
        assert_eq!(peer.last_height, remote_height);
        proof_server.join().unwrap();
        origin_server.join().unwrap();
        cleanup_dir(&path);
    }

    struct TestResolver {
        outcome: TestResolverOutcome,
    }

    struct TestDelegatedResolver {
        outcome: TestResolverOutcome,
    }

    struct CountingErrorDelegatedResolver {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        error: fn() -> ResolverError,
    }

    enum TestResolverOutcome {
        Answer(ResolutionAnswer),
        Error(fn() -> ResolverError),
    }

    impl TestResolver {
        fn answer(answer: ResolutionAnswer) -> Self {
            Self {
                outcome: TestResolverOutcome::Answer(answer),
            }
        }

        fn error(error: fn() -> ResolverError) -> Self {
            Self {
                outcome: TestResolverOutcome::Error(error),
            }
        }
    }

    impl TestDelegatedResolver {
        fn answer(answer: ResolutionAnswer) -> Self {
            Self {
                outcome: TestResolverOutcome::Answer(answer),
            }
        }

        fn error(error: fn() -> ResolverError) -> Self {
            Self {
                outcome: TestResolverOutcome::Error(error),
            }
        }
    }

    impl Resolver for TestResolver {
        fn resolve(&self, _request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
            match &self.outcome {
                TestResolverOutcome::Answer(answer) => Ok(answer.clone()),
                TestResolverOutcome::Error(error) => Err(error()),
            }
        }
    }

    impl DelegatedResolver for TestDelegatedResolver {
        fn resolve_delegated(
            &self,
            _request: &ResolutionRequest,
            _delegation: &HnsDelegation,
        ) -> Result<ResolutionAnswer, ResolverError> {
            match &self.outcome {
                TestResolverOutcome::Answer(answer) => Ok(answer.clone()),
                TestResolverOutcome::Error(error) => Err(error()),
            }
        }
    }

    impl DelegatedResolver for CountingErrorDelegatedResolver {
        fn resolve_delegated(
            &self,
            _request: &ResolutionRequest,
            _delegation: &HnsDelegation,
        ) -> Result<ResolutionAnswer, ResolverError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Err((self.error)())
        }
    }

    fn test_delegation(root_name: &str) -> HnsDelegation {
        HnsDelegation {
            root_name: root_name.to_owned(),
            owner: DnsName::from_ascii(root_name).unwrap(),
            records: Vec::new(),
        }
    }

    fn address_record(owner: &str, address: [u8; 4]) -> ResourceRecord {
        ResourceRecord {
            name: DnsName::from_ascii(owner).unwrap(),
            record_type: RecordType::A,
            class: DNS_CLASS_IN,
            ttl: 20,
            rdata: address.to_vec(),
        }
    }

    fn store_best_header_with_tree_root(base: &std::path::Path, tree_root: Hash) -> Height {
        store_canonical_headers_with_tree_roots(base, &[tree_root])
            .last()
            .copied()
            .unwrap()
    }

    fn store_best_header_for_network_with_tree_root(
        base: &std::path::Path,
        network: NetworkKind,
        tree_root: Hash,
    ) -> Height {
        store_canonical_headers_for_network_with_tree_roots(base, network, &[tree_root])
            .last()
            .copied()
            .unwrap()
    }

    fn store_peer_height(base: &std::path::Path, height: u32) {
        let address = "1.1.1.1:12038".parse().unwrap();
        let peer_store = SqlitePeerStore::open(base.join("peers.sqlite")).unwrap();
        let mut peers = PeerManager::default();
        peers.seed([address]);
        peers.record_observed_height(address, Height(height), now_unix_seconds());
        peer_store.save_manager(&peers).unwrap();
    }

    fn store_canonical_headers_with_tree_roots(
        base: &std::path::Path,
        tree_roots: &[Hash],
    ) -> Vec<Height> {
        store_canonical_headers_for_network_with_tree_roots(base, NetworkKind::Mainnet, tree_roots)
    }

    fn store_canonical_headers_for_network_with_tree_roots(
        base: &std::path::Path,
        network: NetworkKind,
        tree_roots: &[Hash],
    ) -> Vec<Height> {
        let genesis_header = BlockHeader::genesis_for_network(network);
        let genesis = StoredHeader {
            hash: genesis_header.hash(),
            chainwork: Chainwork::from_bits(genesis_header.bits).unwrap(),
            header: genesis_header,
            height: Height(0),
        };
        let mut headers = vec![genesis.clone()];
        let mut previous = genesis;
        let mut heights = Vec::new();
        for (index, tree_root) in tree_roots.iter().copied().enumerate() {
            let mut header = BlockHeader::genesis_for_network(network);
            header.prev_block = previous.hash;
            header.tree_root = tree_root;
            header.time = header.time.saturating_add((index as u64) + 1);
            header.extra_nonce[..4].copy_from_slice(&((index as u32) + 1).to_le_bytes());
            let header_work = Chainwork::from_bits(header.bits).unwrap();
            let stored = StoredHeader {
                hash: header.hash(),
                chainwork: previous.chainwork.checked_add(&header_work),
                header,
                height: Height(previous.height.0 + 1),
            };
            heights.push(stored.height);
            headers.push(stored.clone());
            previous = stored;
        }
        let mut store = SqliteHeaderStore::open(base.join("headers.sqlite")).unwrap();
        for header in &headers {
            store.put_header(header.clone()).unwrap();
        }
        store.replace_canonical_chain(&headers).unwrap();
        heights
    }

    fn urkel_exists_payload(value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_u16_le(&mut out, 3 << 14);
        write_u16_le(&mut out, 0);
        write_u16_le(&mut out, value.len() as u16);
        out.extend(value);
        out
    }

    fn urkel_value_root(key: Hash, value: &[u8]) -> Hash {
        let value_hash = blake2b_256(&[value]);
        blake2b_256(&[&[0x00], key.as_bytes(), value_hash.as_bytes()])
    }

    fn owner_glue4_resource(owner: &str, address: [u8; 4]) -> Vec<u8> {
        let mut value = vec![0, 2];
        DnsName::from_ascii(owner)
            .unwrap()
            .encode_wire(&mut value)
            .unwrap();
        value.extend(address);
        value
    }

    fn name_state_value(name: &str, data: &[u8]) -> Vec<u8> {
        let mut value = Vec::new();
        value.push(name.len() as u8);
        value.extend(name.as_bytes());
        write_u16_le(&mut value, data.len() as u16);
        value.extend(data);
        value.extend(7_u32.to_le_bytes());
        value.extend(7_u32.to_le_bytes());
        value.extend(0_u16.to_le_bytes());
        value
    }

    fn write_u16_le(out: &mut Vec<u8>, value: u16) {
        out.extend(value.to_le_bytes());
    }

    fn temp_dir_path(label: &str) -> std::path::PathBuf {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("android-ffi-{label}-{}-{now}", std::process::id()))
    }

    fn cleanup_dir(path: &std::path::Path) {
        let _ = std::fs::remove_dir_all(path);
    }
}
