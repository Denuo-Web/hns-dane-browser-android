//! Android JNI adapter for the platform-neutral browser runtime.

#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use hns_browser_runtime::*;
use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring};
use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

const MAX_LOCAL_CERTIFICATE_DER_BYTES: usize = 64 * 1024;
const PROXY_ENDPOINT_BUNDLE_MAGIC: &[u8; 4] = b"HNSP";
const PROXY_ENDPOINT_BUNDLE_VERSION: u8 = 1;
const PROXY_STATUS_BUNDLE_MAGIC: &[u8; 4] = b"HNSS";
const PROXY_STATUS_BUNDLE_VERSION: u8 = 1;
const MAX_PROXY_STATUS_BUNDLE_BYTES: usize = 64 * 1024;
const MAX_PROXY_STATUS_HOSTS: usize = 8;
const MAX_PROXY_STATUS_RETAINED_TRACE_BYTES: usize = 64 * 1024;
const MAX_ANDROID_PROXY_HANDLES: usize = 8;
static NEXT_PROXY_HANDLE: AtomicU64 = AtomicU64::new(1);
static PROXY_HANDLES: OnceLock<Mutex<HashMap<jlong, Arc<AndroidProxyRecord>>>> = OnceLock::new();

struct AndroidRuntimeRecord {
    runtime: BrowserRuntime,
    gateway_lock: Arc<Mutex<()>>,
}

struct AndroidProxyRecord {
    proxy: BrowserProxy,
    statuses: Arc<AndroidProxyStatusMailbox>,
}

#[derive(Clone, Eq, PartialEq)]
struct AndroidProxyStatus {
    generation: u64,
    host: String,
    status_code: u16,
    likely_main_frame: bool,
    tls_policy: Option<BrowserProxyTlsPolicy>,
    resolver_policy: Option<BrowserProxyResolverPolicy>,
    security_path: Option<BrowserProxySecurityPath>,
    resolution_trace_json: Option<String>,
}

impl From<&BrowserProxyStatus> for AndroidProxyStatus {
    fn from(status: &BrowserProxyStatus) -> Self {
        Self {
            generation: status.generation(),
            host: status.host().to_owned(),
            status_code: status.status_code(),
            likely_main_frame: status.is_likely_main_frame(),
            tls_policy: status.tls_policy(),
            resolver_policy: status.resolver_policy(),
            security_path: status.security_path(),
            resolution_trace_json: status.resolution_trace_json().map(str::to_owned),
        }
    }
}

impl std::fmt::Debug for AndroidProxyStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AndroidProxyStatus")
            .field("generation", &self.generation)
            .field("host", &self.host)
            .field("status_code", &self.status_code)
            .field("likely_main_frame", &self.likely_main_frame)
            .field("tls_policy", &self.tls_policy)
            .field("resolver_policy", &self.resolver_policy)
            .field("security_path", &self.security_path)
            .field(
                "resolution_trace_bytes",
                &self.resolution_trace_json.as_ref().map(String::len),
            )
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
struct PendingAndroidProxyStatus {
    sequence: u64,
    status: AndroidProxyStatus,
}

struct AndroidProxyStatusMailboxState {
    active: bool,
    next_sequence: u64,
    retained_trace_bytes: usize,
    latest_by_host: HashMap<String, PendingAndroidProxyStatus>,
}

struct AndroidProxyStatusMailbox {
    state: Mutex<AndroidProxyStatusMailboxState>,
}

impl AndroidProxyStatusMailbox {
    fn new() -> Self {
        Self {
            state: Mutex::new(AndroidProxyStatusMailboxState {
                active: true,
                next_sequence: 0,
                retained_trace_bytes: 0,
                latest_by_host: HashMap::new(),
            }),
        }
    }

    fn deactivate(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.active = false;
        state.retained_trace_bytes = 0;
        state.latest_by_host.clear();
    }

    fn peek_matching(&self, generation: u64, host: &str) -> Option<PendingAndroidProxyStatus> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.active {
            return None;
        }
        state
            .latest_by_host
            .get(host)
            .filter(|pending| pending.status.generation == generation)
            .cloned()
    }

    fn acknowledge_matching(&self, generation: u64, host: &str, sequence: u64) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.active
            || !state.latest_by_host.get(host).is_some_and(|pending| {
                pending.sequence == sequence && pending.status.generation == generation
            })
        {
            return false;
        }
        if let Some(removed) = state.latest_by_host.remove(host) {
            state.retained_trace_bytes = state
                .retained_trace_bytes
                .saturating_sub(proxy_status_trace_bytes(&removed.status));
        }
        true
    }

    fn discard_matching(&self, generation: u64, host: &str) -> bool {
        let pending = self.peek_matching(generation, host);
        pending.is_some_and(|pending| self.acknowledge_matching(generation, host, pending.sequence))
    }

    fn record_status(&self, mut status: AndroidProxyStatus) {
        if !status.likely_main_frame {
            return;
        }
        if proxy_status_trace_bytes(&status) > MAX_PROXY_STATUS_RETAINED_TRACE_BYTES {
            status.resolution_trace_json = None;
        }
        let host = status.host.clone();
        let trace_bytes = proxy_status_trace_bytes(&status);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.active {
            return;
        }
        if state.next_sequence == u64::MAX {
            state.next_sequence = 0;
            state.retained_trace_bytes = 0;
            state.latest_by_host.clear();
        }
        state.next_sequence += 1;
        let sequence = state.next_sequence;

        if let Some(previous) = state.latest_by_host.remove(&host) {
            state.retained_trace_bytes = state
                .retained_trace_bytes
                .saturating_sub(proxy_status_trace_bytes(&previous.status));
        }
        while state.latest_by_host.len() >= MAX_PROXY_STATUS_HOSTS
            || state.retained_trace_bytes.saturating_add(trace_bytes)
                > MAX_PROXY_STATUS_RETAINED_TRACE_BYTES
        {
            let Some(oldest_host) = state
                .latest_by_host
                .iter()
                .min_by_key(|(_, pending)| pending.sequence)
                .map(|(candidate, _)| candidate.clone())
            else {
                break;
            };
            if let Some(removed) = state.latest_by_host.remove(&oldest_host) {
                state.retained_trace_bytes = state
                    .retained_trace_bytes
                    .saturating_sub(proxy_status_trace_bytes(&removed.status));
            }
        }
        state.retained_trace_bytes = state.retained_trace_bytes.saturating_add(trace_bytes);
        state
            .latest_by_host
            .insert(host, PendingAndroidProxyStatus { sequence, status });
    }
}

impl BrowserProxyStatusObserver for AndroidProxyStatusMailbox {
    fn observe_status(&self, status: &BrowserProxyStatus) {
        self.record_status(AndroidProxyStatus::from(status));
    }
}

fn proxy_status_trace_bytes(status: &AndroidProxyStatus) -> usize {
    status.resolution_trace_json.as_ref().map_or(0, String::len)
}

fn runtime_error_message(error: RuntimeError) -> String {
    match error {
        RuntimeError::InvalidConfiguration(message) | RuntimeError::Operation(message) => message,
        error @ RuntimeError::Synchronization(_) => error.to_string(),
    }
}

fn runtime_status_json(network: NetworkKind, result: Result<SyncStatus, RuntimeError>) -> String {
    result
        .unwrap_or_else(|error| NativeSyncStatus::error_for(network, runtime_error_message(error)))
        .to_json()
}

fn runtime_from_handle(handle: jlong) -> Option<BrowserRuntime> {
    if handle == 0 {
        return None;
    }
    let record = handle as usize as *const AndroidRuntimeRecord;
    // SAFETY: handles are created from Box<AndroidRuntimeRecord> below. Platform callers serialize
    // destroy against calls, and cloning only retains the Arc-backed runtime inner state.
    unsafe { record.as_ref().map(|record| record.runtime.clone()) }
}

fn runtime_gateway_from_handle(handle: jlong) -> Option<(BrowserRuntime, Arc<Mutex<()>>)> {
    if handle == 0 {
        return None;
    }
    let record = handle as usize as *const AndroidRuntimeRecord;
    // SAFETY: the platform lifecycle lock keeps the AndroidRuntimeRecord alive while its
    // Arc-backed runtime and gateway lock are cloned for this call.
    unsafe {
        record
            .as_ref()
            .map(|record| (record.runtime.clone(), Arc::clone(&record.gateway_lock)))
    }
}

fn proxy_registry() -> &'static Mutex<HashMap<jlong, Arc<AndroidProxyRecord>>> {
    PROXY_HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_proxy_handle() -> Option<jlong> {
    let handle = NEXT_PROXY_HANDLE
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current <= i64::MAX as u64).then_some(current + 1)
        })
        .ok()?;
    jlong::try_from(handle).ok().filter(|handle| *handle != 0)
}

fn register_proxy(
    proxy: BrowserProxy,
    statuses: Arc<AndroidProxyStatusMailbox>,
) -> Option<(jlong, Arc<AndroidProxyRecord>)> {
    let handle = next_proxy_handle()?;
    let record = Arc::new(AndroidProxyRecord { proxy, statuses });
    let mut registry = proxy_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if registry.len() >= MAX_ANDROID_PROXY_HANDLES {
        return None;
    }
    match registry.entry(handle) {
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(Arc::clone(&record));
        }
        std::collections::hash_map::Entry::Occupied(_) => return None,
    }
    Some((handle, record))
}

fn proxy_from_handle(handle: jlong) -> Option<Arc<AndroidProxyRecord>> {
    if handle <= 0 {
        return None;
    }
    proxy_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&handle)
        .cloned()
}

fn remove_proxy(handle: jlong) -> Option<Arc<AndroidProxyRecord>> {
    if handle <= 0 {
        return None;
    }
    proxy_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&handle)
}

fn destroy_proxy(handle: jlong) -> bool {
    let Some(record) = proxy_from_handle(handle) else {
        return false;
    };
    record.statuses.deactivate();
    record.proxy.request_stop();
    let Some(record) = remove_proxy(handle) else {
        return false;
    };
    record.proxy.stop();
    true
}

fn destroy_all_proxies() {
    let proxies: Vec<_> = proxy_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .drain()
        .map(|(_, proxy)| proxy)
        .collect();
    for record in &proxies {
        record.statuses.deactivate();
        record.proxy.request_stop();
    }
    for record in proxies {
        record.proxy.stop();
    }
}

fn proxy_endpoint_bundle(handle: jlong, proxy: &BrowserProxy) -> Option<Vec<u8>> {
    let mut bundle = Vec::with_capacity(128);
    bundle.extend_from_slice(PROXY_ENDPOINT_BUNDLE_MAGIC);
    bundle.push(PROXY_ENDPOINT_BUNDLE_VERSION);
    bundle.extend_from_slice(&handle.to_be_bytes());
    bundle.extend_from_slice(&proxy.port().to_be_bytes());
    bundle.extend_from_slice(&proxy.generation().to_be_bytes());
    for value in [
        proxy.session_id(),
        proxy.authorization_realm(),
        proxy.authorization_username(),
        proxy.authorization_password(),
    ] {
        let length = u16::try_from(value.len()).ok()?;
        bundle.extend_from_slice(&length.to_be_bytes());
        bundle.extend_from_slice(value.as_bytes());
    }
    Some(bundle)
}

fn canonical_proxy_status_host(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return None;
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        let bytes = label.as_bytes();
        if !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return None;
        }
    }
    Some(host.to_ascii_lowercase())
}

fn proxy_tls_policy_code(policy: Option<BrowserProxyTlsPolicy>) -> Option<u8> {
    match policy {
        None => Some(0),
        Some(BrowserProxyTlsPolicy::Dane) => Some(1),
        Some(BrowserProxyTlsPolicy::WebPkiFallback) => Some(2),
        Some(_) => None,
    }
}

fn proxy_resolver_policy_code(policy: Option<BrowserProxyResolverPolicy>) -> Option<u8> {
    match policy {
        None => Some(0),
        Some(BrowserProxyResolverPolicy::HnsDohCompatibility) => Some(1),
        Some(_) => None,
    }
}

fn proxy_security_path_code(path: Option<BrowserProxySecurityPath>) -> Option<u8> {
    match path {
        None => Some(0),
        Some(BrowserProxySecurityPath::DaneAuthoritativeDoh) => Some(1),
        Some(BrowserProxySecurityPath::DaneAuthoritativeDns53) => Some(2),
        Some(BrowserProxySecurityPath::DaneThirdPartyDoh) => Some(3),
        Some(BrowserProxySecurityPath::StatelessDane) => Some(4),
        Some(BrowserProxySecurityPath::DaneIcannDoh) => Some(5),
        Some(BrowserProxySecurityPath::HnsAuthoritativeDoh) => Some(6),
        Some(BrowserProxySecurityPath::HnsAuthoritativeDns53) => Some(7),
        Some(BrowserProxySecurityPath::HnsThirdPartyDoh) => Some(8),
        Some(_) => None,
    }
}

fn proxy_status_bundle(pending: &PendingAndroidProxyStatus) -> Option<Vec<u8>> {
    let status = &pending.status;
    if pending.sequence == 0 || status.generation == 0 || !(100..=599).contains(&status.status_code)
    {
        return None;
    }
    let host = canonical_proxy_status_host(&status.host)?;
    if host != status.host {
        return None;
    }
    let host_length = u16::try_from(host.len()).ok()?;
    let fixed_length = PROXY_STATUS_BUNDLE_MAGIC.len()
        + 1
        + std::mem::size_of::<u64>()
        + std::mem::size_of::<u64>()
        + std::mem::size_of::<u16>()
        + 4
        + std::mem::size_of::<u16>()
        + host.len()
        + std::mem::size_of::<u32>();
    let trace = status
        .resolution_trace_json
        .as_deref()
        .filter(|trace| fixed_length.saturating_add(trace.len()) <= MAX_PROXY_STATUS_BUNDLE_BYTES);
    let trace_length = u32::try_from(trace.map_or(0, str::len)).ok()?;

    let mut bundle = Vec::with_capacity(fixed_length + trace.map_or(0, str::len));
    bundle.extend_from_slice(PROXY_STATUS_BUNDLE_MAGIC);
    bundle.push(PROXY_STATUS_BUNDLE_VERSION);
    bundle.extend_from_slice(&status.generation.to_be_bytes());
    bundle.extend_from_slice(&pending.sequence.to_be_bytes());
    bundle.extend_from_slice(&status.status_code.to_be_bytes());
    bundle.push(u8::from(status.likely_main_frame));
    bundle.push(proxy_tls_policy_code(status.tls_policy)?);
    bundle.push(proxy_resolver_policy_code(status.resolver_policy)?);
    bundle.push(proxy_security_path_code(status.security_path)?);
    bundle.extend_from_slice(&host_length.to_be_bytes());
    bundle.extend_from_slice(host.as_bytes());
    bundle.extend_from_slice(&trace_length.to_be_bytes());
    if let Some(trace) = trace {
        bundle.extend_from_slice(trace.as_bytes());
    }
    (bundle.len() <= MAX_PROXY_STATUS_BUNDLE_BYTES).then_some(bundle)
}

struct JniRuntimeGatewayHttpRequest<'local> {
    method: JString<'local>,
    scheme: JString<'local>,
    host: JString<'local>,
    port: jint,
    path_and_query: JString<'local>,
    header_text: JString<'local>,
    body: JByteArray<'local>,
}

struct RuntimeGatewayPolicyInput<'local> {
    network: JString<'local>,
    strict_hns_mode: jboolean,
    doh_resolver_url: JString<'local>,
    stateless_dane_certificates: jboolean,
}

struct PreparedRuntimeGatewayRequest {
    request: GatewayHttpRequest,
    address: String,
}

struct RuntimeGatewayRequestRejection {
    status: u16,
    reason: &'static str,
    detail: &'static str,
    address: String,
}

enum RuntimeGatewayRequestInput {
    Prepared(PreparedRuntimeGatewayRequest),
    Rejected(RuntimeGatewayRequestRejection),
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeVersion(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    env.new_string(core_version())
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn jni_runtime_gateway_request(
    env: &mut JNIEnv<'_>,
    input: JniRuntimeGatewayHttpRequest<'_>,
) -> Option<RuntimeGatewayRequestInput> {
    let method = env
        .get_string(&input.method)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let scheme = env
        .get_string(&input.scheme)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let host = env
        .get_string(&input.host)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let path_and_query = env
        .get_string(&input.path_and_query)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let header_text = env
        .get_string(&input.header_text)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let port = u16::try_from(input.port).ok()?;
    let address = runtime_gateway_request_address(&scheme, &host, port, &path_and_query);
    let body_len = usize::try_from(env.get_array_length(&input.body).ok()?).ok()?;
    if body_len > DEFAULT_MAX_REQUEST_BODY_BYTES {
        return Some(RuntimeGatewayRequestInput::Rejected(
            RuntimeGatewayRequestRejection {
                status: 413,
                reason: "Origin Request Too Large",
                detail: "Origin request body exceeds the configured gateway limit.",
                address,
            },
        ));
    }
    let headers = match parse_runtime_gateway_headers(&header_text) {
        Ok(headers) => headers,
        Err(detail) => {
            return Some(RuntimeGatewayRequestInput::Rejected(
                RuntimeGatewayRequestRejection {
                    status: 400,
                    reason: "Bad Request",
                    detail,
                    address,
                },
            ));
        }
    };
    let body = env.convert_byte_array(&input.body).ok()?;
    Some(RuntimeGatewayRequestInput::Prepared(
        PreparedRuntimeGatewayRequest {
            request: GatewayHttpRequest {
                method,
                scheme,
                host,
                port,
                path_and_query,
                headers,
                body,
            },
            address,
        },
    ))
}

fn parse_runtime_gateway_headers(header_text: &str) -> Result<Vec<(String, String)>, &'static str> {
    if header_text.len() > MAX_GATEWAY_HEADER_TEXT_BYTES {
        return Err("request headers are too large");
    }
    let mut headers = Vec::new();
    for line in header_text.split("\r\n").filter(|line| !line.is_empty()) {
        let Some(separator) = line.find(':') else {
            return Err("request header is malformed");
        };
        let name = line[..separator].trim();
        let value = line[separator + 1..].trim();
        if !is_valid_runtime_gateway_header_name(name)
            || !is_valid_runtime_gateway_header_value(value)
        {
            return Err("request header is invalid");
        }
        if !name
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("X-HNS-"))
        {
            headers.push((name.to_owned(), value.to_owned()));
        }
    }
    Ok(headers)
}

fn is_valid_runtime_gateway_header_name(name: &str) -> bool {
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

fn is_valid_runtime_gateway_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte == b'\t' || (byte >= b' ' && byte != 0x7f))
}

fn runtime_gateway_request_address(
    scheme: &str,
    host: &str,
    port: u16,
    path_and_query: &str,
) -> String {
    let normalized_scheme = scheme.to_ascii_lowercase();
    let port = match (normalized_scheme.as_str(), port) {
        ("http" | "ws", 80) | ("https" | "wss", 443) => String::new(),
        (_, port) => format!(":{port}"),
    };
    let path = if path_and_query.is_empty() {
        "/"
    } else {
        path_and_query
    };
    format!("{normalized_scheme}://{host}{port}{path}")
}

fn runtime_gateway_policy(
    env: &mut JNIEnv<'_>,
    input: RuntimeGatewayPolicyInput<'_>,
) -> Option<(String, RuntimePolicy)> {
    let network = env
        .get_string(&input.network)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let doh_resolver_url = env
        .get_string(&input.doh_resolver_url)
        .ok()?
        .to_string_lossy()
        .trim()
        .to_owned();
    Some((
        network,
        RuntimePolicy {
            resolution_mode: if input.strict_hns_mode == 0 {
                ResolutionMode::Compatibility
            } else {
                ResolutionMode::Strict
            },
            hns_doh_resolver: (!doh_resolver_url.is_empty()).then_some(doh_resolver_url),
            stateless_dane_certificates: input.stateless_dane_certificates != 0,
        },
    ))
}

fn with_configured_runtime_gateway<T>(
    runtime: BrowserRuntime,
    gateway_lock: Arc<Mutex<()>>,
    expected_network: &str,
    policy: RuntimePolicy,
    operation: impl FnOnce(&BrowserRuntime) -> Result<T, RuntimeError>,
) -> Result<T, RuntimeError> {
    let _gateway = match gateway_lock.lock() {
        Ok(gateway) => gateway,
        Err(_) => {
            return Err(RuntimeError::Synchronization(
                "Android runtime gateway lock",
            ));
        }
    };
    let expected_network = match parse_network_kind(expected_network) {
        Ok(network) => network,
        Err(error) => return Err(RuntimeError::InvalidConfiguration(error)),
    };
    if runtime.network() != expected_network {
        return Err(RuntimeError::InvalidConfiguration(
            "gateway network does not match the runtime handle".to_owned(),
        ));
    }
    match runtime.policy() {
        Ok(current) if current == policy => {}
        Ok(_) => {
            runtime.set_policy(policy)?;
        }
        Err(error) => return Err(error),
    }
    operation(&runtime)
}

fn runtime_gateway_error_parts(error: RuntimeError) -> (u16, &'static str, String) {
    match error {
        RuntimeError::InvalidConfiguration(detail) => (400, "Bad Request", detail),
        RuntimeError::Operation(detail) => (500, "Gateway Runtime Error", detail),
        error @ RuntimeError::Synchronization(_) => {
            (500, "Gateway Runtime Error", error.to_string())
        }
    }
}

fn runtime_gateway_error_response(error: RuntimeError, address: &str) -> Vec<u8> {
    let (status, reason, detail) = runtime_gateway_error_parts(error);
    plain_response_with_address(status, reason, &detail, Some(address))
}

fn runtime_gateway_error_response_to_file(
    error: RuntimeError,
    address: &str,
    body_path: &Path,
) -> Option<Vec<u8>> {
    let (status, reason, detail) = runtime_gateway_error_parts(error);
    plain_response_to_file_with_address(status, reason, &detail, Some(address), body_path).ok()
}

fn jni_runtime_gateway_http_response(
    env: &mut JNIEnv<'_>,
    handle: jlong,
    policy_input: RuntimeGatewayPolicyInput<'_>,
    request_input: JniRuntimeGatewayHttpRequest<'_>,
) -> Option<Vec<u8>> {
    let (runtime, gateway_lock) = runtime_gateway_from_handle(handle)?;
    let (network, policy) = runtime_gateway_policy(env, policy_input)?;
    match jni_runtime_gateway_request(env, request_input)? {
        RuntimeGatewayRequestInput::Rejected(rejection) => Some(plain_response_with_address(
            rejection.status,
            rejection.reason,
            rejection.detail,
            Some(&rejection.address),
        )),
        RuntimeGatewayRequestInput::Prepared(prepared) => {
            let address = prepared.address;
            match with_configured_runtime_gateway(
                runtime,
                gateway_lock,
                &network,
                policy,
                |runtime| runtime.gateway_request(prepared.request),
            ) {
                Ok(response) => Some(response.into_bytes()),
                Err(error) => Some(runtime_gateway_error_response(error, &address)),
            }
        }
    }
}

fn jni_runtime_gateway_http_response_body_to_file(
    env: &mut JNIEnv<'_>,
    handle: jlong,
    policy_input: RuntimeGatewayPolicyInput<'_>,
    request_input: JniRuntimeGatewayHttpRequest<'_>,
    body_path: JString<'_>,
) -> Option<Vec<u8>> {
    let (runtime, gateway_lock) = runtime_gateway_from_handle(handle)?;
    let body_path = env
        .get_string(&body_path)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let body_path = Path::new(&body_path);
    let (network, policy) = runtime_gateway_policy(env, policy_input)?;
    match jni_runtime_gateway_request(env, request_input)? {
        RuntimeGatewayRequestInput::Rejected(rejection) => plain_response_to_file_with_address(
            rejection.status,
            rejection.reason,
            rejection.detail,
            Some(&rejection.address),
            body_path,
        )
        .ok(),
        RuntimeGatewayRequestInput::Prepared(prepared) => {
            let address = prepared.address;
            match with_configured_runtime_gateway(
                runtime,
                gateway_lock,
                &network,
                policy,
                |runtime| runtime.gateway_request_body_to_file(prepared.request, body_path),
            ) {
                Ok(head) => Some(head),
                Err(error) => runtime_gateway_error_response_to_file(error, &address, body_path),
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeRuntimeCreate(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    data_dir: JString<'_>,
    network: JString<'_>,
) -> jlong {
    let (Ok(data_dir), Ok(network)) = (env.get_string(&data_dir), env.get_string(&network)) else {
        return 0;
    };
    let Ok(network) = parse_network_kind(&network.to_string_lossy()) else {
        return 0;
    };
    let Ok(runtime) = BrowserRuntime::open(RuntimeConfiguration::new(
        data_dir.to_string_lossy().into_owned(),
        network,
    )) else {
        return 0;
    };
    Box::into_raw(Box::new(AndroidRuntimeRecord {
        runtime,
        gateway_lock: Arc::new(Mutex::new(())),
    })) as usize as jlong
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeRuntimeDestroy(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    let runtime = handle as usize as *mut AndroidRuntimeRecord;
    // SAFETY: the pointer was returned by nativeRuntimeCreate and the platform lifecycle lock
    // guarantees exactly one destroy after all calls have released their cloned runtime.
    unsafe { drop(Box::from_raw(runtime)) };
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeRuntimeSyncOnce(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jstring {
    let status = runtime_from_handle(handle)
        .map(|runtime| runtime_status_json(runtime.network(), runtime.sync_once()))
        .unwrap_or_else(|| NativeSyncStatus::error("invalid runtime handle".to_owned()).to_json());
    env.new_string(status)
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeRuntimeSyncStatus(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jstring {
    let status = runtime_from_handle(handle)
        .map(|runtime| runtime_status_json(runtime.network(), runtime.sync_status()))
        .unwrap_or_else(|| NativeSyncStatus::error("invalid runtime handle".to_owned()).to_json());
    env.new_string(status)
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeRuntimeClearResolverCache(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jstring {
    let status = runtime_from_handle(handle)
        .map(|runtime| runtime_status_json(runtime.network(), runtime.clear_resolver_cache()))
        .unwrap_or_else(|| NativeSyncStatus::error("invalid runtime handle".to_owned()).to_json());
    env.new_string(status)
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeRuntimeInstallHeaderSnapshot(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    snapshot_path: JString<'_>,
) -> jstring {
    let status = match (runtime_from_handle(handle), env.get_string(&snapshot_path)) {
        (Some(runtime), Ok(snapshot_path)) => runtime_status_json(
            runtime.network(),
            runtime.install_header_snapshot(snapshot_path.to_string_lossy().as_ref()),
        ),
        _ => NativeSyncStatus::error("invalid runtime snapshot input".to_owned()).to_json(),
    };
    env.new_string(status)
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeRuntimeResetHeadersFromPeers(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jstring {
    let status = runtime_from_handle(handle)
        .map(|runtime| runtime_status_json(runtime.network(), runtime.reset_headers_from_peers()))
        .unwrap_or_else(|| NativeSyncStatus::error("invalid runtime handle".to_owned()).to_json());
    env.new_string(status)
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeRuntimeHnsProofDetails(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    host: JString<'_>,
) -> jstring {
    let details = match (runtime_from_handle(handle), env.get_string(&host)) {
        (Some(runtime), Ok(host)) => {
            let host = host.to_string_lossy();
            runtime.proof_details(&host).unwrap_or_else(|error| {
                hns_proof_details_error_json(&host, &runtime_error_message(error))
            })
        }
        _ => hns_proof_details_error_json("", "invalid runtime proof detail input"),
    };
    env.new_string(details)
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeRuntimeStartProxy(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    network: JString<'_>,
    strict_hns_mode: jboolean,
    doh_resolver_url: JString<'_>,
    stateless_dane_certificates: jboolean,
    scope_root: JString<'_>,
) -> jbyteArray {
    catch_unwind(AssertUnwindSafe(|| {
        let result = runtime_gateway_from_handle(handle)
            .zip(runtime_gateway_policy(
                &mut env,
                RuntimeGatewayPolicyInput {
                    network,
                    strict_hns_mode,
                    doh_resolver_url,
                    stateless_dane_certificates,
                },
            ))
            .zip(env.get_string(&scope_root).ok())
            .and_then(
                |(((runtime, gateway_lock), (network, policy)), scope_root)| {
                    let scope_root = scope_root.to_string_lossy();
                    let statuses = Arc::new(AndroidProxyStatusMailbox::new());
                    with_configured_runtime_gateway(
                        runtime,
                        gateway_lock,
                        &network,
                        policy,
                        |runtime| {
                            runtime
                                .start_proxy_with_observer(&scope_root, statuses.clone())
                                .map_err(|error| RuntimeError::Operation(error.to_string()))
                        },
                    )
                    .ok()
                    .map(|proxy| (proxy, statuses))
                },
            )
            .and_then(|(proxy, statuses)| register_proxy(proxy, statuses));
        let Some((proxy_handle, record)) = result else {
            return std::ptr::null_mut();
        };
        let Some(bundle) = proxy_endpoint_bundle(proxy_handle, &record.proxy) else {
            let _destroyed = destroy_proxy(proxy_handle);
            return std::ptr::null_mut();
        };
        match env.byte_array_from_slice(&bundle) {
            Ok(array) => array.into_raw(),
            Err(_) => {
                let _destroyed = destroy_proxy(proxy_handle);
                std::ptr::null_mut()
            }
        }
    }))
    .unwrap_or(std::ptr::null_mut())
}

#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeRuntimeGatewayHttpResponse(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    network: JString<'_>,
    strict_hns_mode: jboolean,
    doh_resolver_url: JString<'_>,
    stateless_dane_certificates: jboolean,
    method: JString<'_>,
    scheme: JString<'_>,
    host: JString<'_>,
    port: jint,
    path_and_query: JString<'_>,
    header_text: JString<'_>,
    body: JByteArray<'_>,
) -> jbyteArray {
    catch_unwind(AssertUnwindSafe(|| {
        let response = jni_runtime_gateway_http_response(
            &mut env,
            handle,
            RuntimeGatewayPolicyInput {
                network,
                strict_hns_mode,
                doh_resolver_url,
                stateless_dane_certificates,
            },
            JniRuntimeGatewayHttpRequest {
                method,
                scheme,
                host,
                port,
                path_and_query,
                header_text,
                body,
            },
        );
        match response.and_then(|bytes| env.byte_array_from_slice(&bytes).ok()) {
            Some(array) => array.into_raw(),
            None => std::ptr::null_mut(),
        }
    }))
    .unwrap_or(std::ptr::null_mut())
}

#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeRuntimeGatewayHttpResponseBodyToFile(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    network: JString<'_>,
    strict_hns_mode: jboolean,
    doh_resolver_url: JString<'_>,
    stateless_dane_certificates: jboolean,
    method: JString<'_>,
    scheme: JString<'_>,
    host: JString<'_>,
    port: jint,
    path_and_query: JString<'_>,
    header_text: JString<'_>,
    body: JByteArray<'_>,
    body_path: JString<'_>,
) -> jbyteArray {
    catch_unwind(AssertUnwindSafe(|| {
        let response = jni_runtime_gateway_http_response_body_to_file(
            &mut env,
            handle,
            RuntimeGatewayPolicyInput {
                network,
                strict_hns_mode,
                doh_resolver_url,
                stateless_dane_certificates,
            },
            JniRuntimeGatewayHttpRequest {
                method,
                scheme,
                host,
                port,
                path_and_query,
                header_text,
                body,
            },
            body_path,
        );
        match response.and_then(|bytes| env.byte_array_from_slice(&bytes).ok()) {
            Some(array) => array.into_raw(),
            None => std::ptr::null_mut(),
        }
    }))
    .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeProxyRequestStop(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    session_id: JString<'_>,
    generation: jlong,
) -> jboolean {
    let Some(record) = proxy_from_handle(handle) else {
        return 0;
    };
    let (Ok(session_id), Ok(generation)) = (env.get_string(&session_id), u64::try_from(generation))
    else {
        return 0;
    };
    if !record
        .proxy
        .matches_instance(&session_id.to_string_lossy(), generation)
    {
        return 0;
    }
    record.statuses.deactivate();
    record.proxy.request_stop();
    1
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeProxyDestroy(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    let _destroyed = destroy_proxy(handle);
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeProxyDestroyAll(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) {
    destroy_all_proxies();
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeProxyTakeMainFrameStatus(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    session_id: JString<'_>,
    generation: jlong,
    host: JString<'_>,
) -> jbyteArray {
    let Some(record) = proxy_from_handle(handle) else {
        return std::ptr::null_mut();
    };
    let (Ok(session_id), Ok(generation), Ok(host)) = (
        env.get_string(&session_id),
        u64::try_from(generation),
        env.get_string(&host),
    ) else {
        return std::ptr::null_mut();
    };
    if !record
        .proxy
        .matches_instance(&session_id.to_string_lossy(), generation)
    {
        return std::ptr::null_mut();
    }
    let Some(host) = canonical_proxy_status_host(&host.to_string_lossy()) else {
        return std::ptr::null_mut();
    };
    let Some(pending) = record.statuses.peek_matching(generation, &host) else {
        return std::ptr::null_mut();
    };
    let Some(bundle) = proxy_status_bundle(&pending) else {
        return std::ptr::null_mut();
    };
    let Ok(array) = env.byte_array_from_slice(&bundle) else {
        return std::ptr::null_mut();
    };
    if !record
        .statuses
        .acknowledge_matching(generation, &host, pending.sequence)
    {
        return std::ptr::null_mut();
    }
    array.into_raw()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeProxyDiscardMainFrameStatus(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    session_id: JString<'_>,
    generation: jlong,
    host: JString<'_>,
) -> jboolean {
    let Some(record) = proxy_from_handle(handle) else {
        return 0;
    };
    let (Ok(session_id), Ok(generation), Ok(host)) = (
        env.get_string(&session_id),
        u64::try_from(generation),
        env.get_string(&host),
    ) else {
        return 0;
    };
    if !record
        .proxy
        .matches_instance(&session_id.to_string_lossy(), generation)
    {
        return 0;
    }
    let Some(host) = canonical_proxy_status_host(&host.to_string_lossy()) else {
        return 0;
    };
    if record.statuses.discard_matching(generation, &host) {
        1
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeProxyMatchesLocalCertificate(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    session_id: JString<'_>,
    generation: jlong,
    host: JString<'_>,
    certificate_der: JByteArray<'_>,
) -> jboolean {
    let Some(record) = proxy_from_handle(handle) else {
        return 0;
    };
    let (Ok(session_id), Ok(generation)) = (env.get_string(&session_id), u64::try_from(generation))
    else {
        return 0;
    };
    if !record
        .proxy
        .matches_instance(&session_id.to_string_lossy(), generation)
    {
        return 0;
    }
    let Ok(length) = env.get_array_length(&certificate_der) else {
        return 0;
    };
    let Ok(length) = usize::try_from(length) else {
        return 0;
    };
    if length == 0 || length > MAX_LOCAL_CERTIFICATE_DER_BYTES {
        return 0;
    }
    let (Ok(host), Ok(certificate_der)) = (
        env.get_string(&host),
        env.convert_byte_array(&certificate_der),
    ) else {
        return 0;
    };
    let host = host.to_string_lossy();
    if host.len() > 253 {
        return 0;
    }
    if record
        .proxy
        .matches_local_certificate(&host, &certificate_der)
    {
        1
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeDiagnostics(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    env.new_string(diagnostics_json())
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeSyncOnce(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    data_dir: JString<'_>,
    network: JString<'_>,
) -> jstring {
    let status = match (env.get_string(&data_dir), env.get_string(&network)) {
        (Ok(data_dir), Ok(network)) => match parse_network_kind(&network.to_string_lossy()) {
            Ok(network) => sync_once_for_network(&data_dir.to_string_lossy(), network),
            Err(error) => NativeSyncStatus::error(error).to_json(),
        },
        _ => NativeSyncStatus::error("invalid sync input".to_owned()).to_json(),
    };

    env.new_string(status)
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeSyncStatus(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    data_dir: JString<'_>,
    network: JString<'_>,
) -> jstring {
    let status = match (env.get_string(&data_dir), env.get_string(&network)) {
        (Ok(data_dir), Ok(network)) => match parse_network_kind(&network.to_string_lossy()) {
            Ok(network) => sync_status_for_network(&data_dir.to_string_lossy(), network),
            Err(error) => NativeSyncStatus::error(error).to_json(),
        },
        _ => NativeSyncStatus::error("invalid sync status input".to_owned()).to_json(),
    };

    env.new_string(status)
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeClearResolverCache(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    data_dir: JString<'_>,
    network: JString<'_>,
) -> jstring {
    let status = match (env.get_string(&data_dir), env.get_string(&network)) {
        (Ok(data_dir), Ok(network)) => match parse_network_kind(&network.to_string_lossy()) {
            Ok(network) => clear_resolver_cache_for_network(&data_dir.to_string_lossy(), network),
            Err(error) => NativeSyncStatus::error(error).to_json(),
        },
        _ => NativeSyncStatus::error("invalid clear cache input".to_owned()).to_json(),
    };

    env.new_string(status)
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeInstallHeaderSnapshot(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    data_dir: JString<'_>,
    snapshot_path: JString<'_>,
    network: JString<'_>,
) -> jstring {
    let status = match (
        env.get_string(&data_dir),
        env.get_string(&snapshot_path),
        env.get_string(&network),
    ) {
        (Ok(data_dir), Ok(snapshot_path), Ok(network)) => {
            match parse_network_kind(&network.to_string_lossy()) {
                Ok(network) => install_header_snapshot_for_network(
                    &data_dir.to_string_lossy(),
                    &snapshot_path.to_string_lossy(),
                    network,
                ),
                Err(error) => NativeSyncStatus::error(error).to_json(),
            }
        }
        _ => NativeSyncStatus::error("invalid header snapshot input".to_owned()).to_json(),
    };

    env.new_string(status)
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeResetHeadersFromPeers(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    data_dir: JString<'_>,
    network: JString<'_>,
) -> jstring {
    let status = match (env.get_string(&data_dir), env.get_string(&network)) {
        (Ok(data_dir), Ok(network)) => match parse_network_kind(&network.to_string_lossy()) {
            Ok(network) => {
                reset_headers_from_peers_for_network(&data_dir.to_string_lossy(), network)
            }
            Err(error) => NativeSyncStatus::error(error).to_json(),
        },
        _ => NativeSyncStatus::error("invalid reset headers input".to_owned()).to_json(),
    };

    env.new_string(status)
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeHnsProofDetails(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    data_dir: JString<'_>,
    host: JString<'_>,
    network: JString<'_>,
) -> jstring {
    let details = match (
        env.get_string(&data_dir),
        env.get_string(&host),
        env.get_string(&network),
    ) {
        (Ok(data_dir), Ok(host), Ok(network)) => {
            match parse_network_kind(&network.to_string_lossy()) {
                Ok(network) => hns_proof_details_for_network(
                    &data_dir.to_string_lossy(),
                    &host.to_string_lossy(),
                    network,
                ),
                Err(error) => hns_proof_details_error_json(&host.to_string_lossy(), &error),
            }
        }
        _ => hns_proof_details_error_json("", "invalid proof detail input"),
    };

    env.new_string(details)
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn runtime_gateway_header_parser_strips_internal_headers_and_rejects_unsafe_input() {
        assert_eq!(
            parse_runtime_gateway_headers(
                "Accept: text/html\r\nX-HNS-Browser-Network: regtest\r\nx-hns-untrusted: value\r\nAccept: */*\r\n",
            )
            .unwrap(),
            vec![
                ("Accept".to_owned(), "text/html".to_owned()),
                ("Accept".to_owned(), "*/*".to_owned()),
            ]
        );
        assert_eq!(
            parse_runtime_gateway_headers("missing-separator\r\n").unwrap_err(),
            "request header is malformed"
        );
        assert_eq!(
            parse_runtime_gateway_headers("X-Test: value\rnot-a-header\r\n").unwrap_err(),
            "request header is invalid"
        );
        assert_eq!(
            parse_runtime_gateway_headers(&"a".repeat(MAX_GATEWAY_HEADER_TEXT_BYTES + 1))
                .unwrap_err(),
            "request headers are too large"
        );
    }

    #[test]
    fn runtime_gateway_configuration_uses_the_persistent_handle() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data_dir = std::env::temp_dir().join(format!(
            "hns-dane-browser-android-runtime-gateway-{}-{unique}",
            std::process::id()
        ));
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();
        let handle = Box::into_raw(Box::new(AndroidRuntimeRecord {
            runtime,
            gateway_lock: Arc::new(Mutex::new(())),
        })) as usize as jlong;
        let (call_runtime, gateway_lock) = runtime_gateway_from_handle(handle).unwrap();
        // SAFETY: this test owns the unique Box pointer and destroys it exactly once. The call
        // clones must keep both the runtime and gateway lock alive after platform destruction.
        unsafe { drop(Box::from_raw(handle as usize as *mut AndroidRuntimeRecord)) };
        let policy = RuntimePolicy {
            resolution_mode: ResolutionMode::Strict,
            hns_doh_resolver: Some("https://resolver.example/dns-query".to_owned()),
            stateless_dane_certificates: true,
        };

        let configured = with_configured_runtime_gateway(
            call_runtime.clone(),
            Arc::clone(&gateway_lock),
            "reg",
            policy.clone(),
            |runtime| runtime.policy(),
        )
        .unwrap();
        assert_eq!(configured, policy);
        let policy_revision = call_runtime.policy_revision();
        let idempotent_revision = with_configured_runtime_gateway(
            call_runtime.clone(),
            Arc::clone(&gateway_lock),
            "regtest",
            policy,
            |runtime| Ok(runtime.policy_revision()),
        )
        .unwrap();
        assert_eq!(idempotent_revision, policy_revision);
        assert!(matches!(
            with_configured_runtime_gateway(
                call_runtime,
                gateway_lock,
                "mainnet",
                RuntimePolicy::compatibility(),
                |runtime| runtime.policy(),
            ),
            Err(RuntimeError::InvalidConfiguration(_))
        ));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn runtime_gateway_file_errors_keep_head_and_body_separate() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data_dir = std::env::temp_dir().join(format!(
            "hns-dane-browser-android-runtime-gateway-file-{}-{unique}",
            std::process::id()
        ));
        let body_path = data_dir.join("response.body");
        let head = runtime_gateway_error_response_to_file(
            RuntimeError::InvalidConfiguration("invalid request".to_owned()),
            "https://welcome.test/resource",
            &body_path,
        )
        .unwrap();
        let body = std::fs::read(&body_path).unwrap();
        let head_text = String::from_utf8(head).unwrap();

        assert!(head_text.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(head_text.ends_with("\r\n\r\n"));
        assert!(head_text.contains(&format!("Content-Length: {}\r\n", body.len())));
        assert_eq!(
            body,
            b"https://welcome.test/resource\n400 Bad Request\ninvalid request\n"
        );
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn runtime_handle_call_clone_outlives_platform_handle() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data_dir = std::env::temp_dir().join(format!(
            "hns-dane-browser-android-runtime-handle-{}-{unique}",
            std::process::id()
        ));
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();
        let handle = Box::into_raw(Box::new(AndroidRuntimeRecord {
            runtime,
            gateway_lock: Arc::new(Mutex::new(())),
        })) as usize as jlong;

        let call_runtime = runtime_from_handle(handle).unwrap();
        // SAFETY: this test owns the unique Box pointer and destroys it exactly once.
        unsafe { drop(Box::from_raw(handle as usize as *mut AndroidRuntimeRecord)) };

        assert_eq!(
            call_runtime.sync_status().unwrap().network,
            NetworkKind::Regtest
        );
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn proxy_registry_uses_revocable_non_pointer_handles() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data_dir = std::env::temp_dir().join(format!(
            "hns-dane-browser-android-proxy-handle-{}-{unique}",
            std::process::id()
        ));
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();
        let proxy = runtime.start_proxy("welcome").unwrap();
        let statuses = Arc::new(AndroidProxyStatusMailbox::new());
        let (handle, record) = register_proxy(proxy, statuses).unwrap();

        assert!(handle > 0);
        assert!(proxy_from_handle(handle).is_some());
        record.proxy.request_stop();
        assert!(
            !record
                .proxy
                .matches_local_certificate("welcome", b"certificate")
        );
        assert!(destroy_proxy(handle));
        assert!(proxy_from_handle(handle).is_none());
        assert!(!destroy_proxy(handle));
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn proxy_endpoint_bundle_is_versioned_bounded_and_complete() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data_dir = std::env::temp_dir().join(format!(
            "hns-dane-browser-android-proxy-bundle-{}-{unique}",
            std::process::id()
        ));
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();
        let proxy = runtime.start_proxy("welcome").unwrap();
        let statuses = Arc::new(AndroidProxyStatusMailbox::new());
        let (handle, record) = register_proxy(proxy, statuses).unwrap();

        let bundle = proxy_endpoint_bundle(handle, &record.proxy).unwrap();
        assert_eq!(&bundle[..4], PROXY_ENDPOINT_BUNDLE_MAGIC);
        assert_eq!(bundle[4], PROXY_ENDPOINT_BUNDLE_VERSION);
        assert_eq!(
            jlong::from_be_bytes(bundle[5..13].try_into().unwrap()),
            handle
        );
        assert_eq!(
            u16::from_be_bytes(bundle[13..15].try_into().unwrap()),
            record.proxy.port()
        );
        assert_eq!(
            u64::from_be_bytes(bundle[15..23].try_into().unwrap()),
            record.proxy.generation()
        );
        for value in [
            record.proxy.session_id(),
            record.proxy.authorization_realm(),
            record.proxy.authorization_username(),
            record.proxy.authorization_password(),
        ] {
            assert!(
                bundle
                    .windows(value.len())
                    .any(|window| window == value.as_bytes())
            );
        }
        assert!(bundle.len() < 1024);

        assert!(destroy_proxy(handle));
        let _ = std::fs::remove_dir_all(data_dir);
    }

    fn test_proxy_status(
        generation: u64,
        host: &str,
        likely_main_frame: bool,
    ) -> AndroidProxyStatus {
        AndroidProxyStatus {
            generation,
            host: host.to_owned(),
            status_code: 200,
            likely_main_frame,
            tls_policy: Some(BrowserProxyTlsPolicy::Dane),
            resolver_policy: Some(BrowserProxyResolverPolicy::HnsDohCompatibility),
            security_path: Some(BrowserProxySecurityPath::DaneAuthoritativeDoh),
            resolution_trace_json: Some(r#"{"mode":"strict"}"#.to_owned()),
        }
    }

    #[test]
    fn proxy_status_mailbox_is_main_frame_bounded_exact_and_revocable() {
        let mailbox = AndroidProxyStatusMailbox::new();
        mailbox.record_status(test_proxy_status(7, "welcome", false));
        assert!(mailbox.peek_matching(7, "welcome").is_none());

        mailbox.record_status(test_proxy_status(7, "welcome", true));
        assert!(mailbox.peek_matching(8, "welcome").is_none());
        assert!(mailbox.peek_matching(7, "other").is_none());
        let pending = mailbox.peek_matching(7, "welcome").unwrap();
        assert_eq!(pending.status, test_proxy_status(7, "welcome", true));
        assert!(!mailbox.acknowledge_matching(7, "welcome", pending.sequence + 1));
        assert!(mailbox.acknowledge_matching(7, "welcome", pending.sequence));
        assert!(mailbox.peek_matching(7, "welcome").is_none());

        mailbox.record_status(test_proxy_status(7, "welcome", true));
        let superseded = mailbox.peek_matching(7, "welcome").unwrap();
        let mut newer = test_proxy_status(7, "welcome", true);
        newer.status_code = 204;
        mailbox.record_status(newer);
        assert!(!mailbox.acknowledge_matching(7, "welcome", superseded.sequence));
        assert_eq!(
            mailbox
                .peek_matching(7, "welcome")
                .unwrap()
                .status
                .status_code,
            204
        );
        assert!(mailbox.discard_matching(7, "welcome"));
        assert!(!mailbox.discard_matching(7, "welcome"));
        mailbox.record_status(test_proxy_status(7, "welcome", true));
        mailbox.deactivate();
        assert!(mailbox.peek_matching(7, "welcome").is_none());
        mailbox.record_status(test_proxy_status(7, "welcome", true));
        assert!(mailbox.peek_matching(7, "welcome").is_none());
    }

    #[test]
    fn proxy_status_mailbox_is_per_host_ordered_and_aggregate_bounded() {
        let mailbox = AndroidProxyStatusMailbox::new();
        for index in 0..(MAX_PROXY_STATUS_HOSTS + 2) {
            let mut status = test_proxy_status(3, &format!("host{index}"), true);
            status.resolution_trace_json = Some("x".repeat(12 * 1024));
            mailbox.record_status(status);
        }

        let state = mailbox
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(state.latest_by_host.len() <= MAX_PROXY_STATUS_HOSTS);
        assert!(state.retained_trace_bytes <= MAX_PROXY_STATUS_RETAINED_TRACE_BYTES);
        assert!(!state.latest_by_host.contains_key("host0"));
        assert!(state.latest_by_host.contains_key("host9"));
    }

    #[test]
    fn proxy_status_bundle_is_versioned_typed_redacted_and_bounded() {
        let status = test_proxy_status(9, "welcome", true);
        let diagnostic = format!("{status:?}");
        assert!(!diagnostic.contains("strict"));
        assert!(diagnostic.contains("resolution_trace_bytes"));
        let pending = PendingAndroidProxyStatus {
            sequence: 12,
            status: status.clone(),
        };
        let bundle = proxy_status_bundle(&pending).unwrap();

        assert_eq!(&bundle[..4], PROXY_STATUS_BUNDLE_MAGIC);
        assert_eq!(bundle[4], PROXY_STATUS_BUNDLE_VERSION);
        assert_eq!(u64::from_be_bytes(bundle[5..13].try_into().unwrap()), 9);
        assert_eq!(u64::from_be_bytes(bundle[13..21].try_into().unwrap()), 12);
        assert_eq!(u16::from_be_bytes(bundle[21..23].try_into().unwrap()), 200);
        assert_eq!(&bundle[23..27], &[1, 1, 1, 1]);
        let host_length = u16::from_be_bytes(bundle[27..29].try_into().unwrap()) as usize;
        assert_eq!(&bundle[29..29 + host_length], b"welcome");
        let trace_length_offset = 29 + host_length;
        let trace_length = u32::from_be_bytes(
            bundle[trace_length_offset..trace_length_offset + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        assert_eq!(
            &bundle[trace_length_offset + 4..],
            status.resolution_trace_json.as_deref().unwrap().as_bytes()
        );
        assert_eq!(
            trace_length,
            status.resolution_trace_json.as_deref().unwrap().len()
        );
        assert!(bundle.len() <= MAX_PROXY_STATUS_BUNDLE_BYTES);

        for (path, code) in [
            (BrowserProxySecurityPath::DaneAuthoritativeDoh, 1),
            (BrowserProxySecurityPath::DaneAuthoritativeDns53, 2),
            (BrowserProxySecurityPath::DaneThirdPartyDoh, 3),
            (BrowserProxySecurityPath::StatelessDane, 4),
            (BrowserProxySecurityPath::DaneIcannDoh, 5),
            (BrowserProxySecurityPath::HnsAuthoritativeDoh, 6),
            (BrowserProxySecurityPath::HnsAuthoritativeDns53, 7),
            (BrowserProxySecurityPath::HnsThirdPartyDoh, 8),
        ] {
            let mapped = proxy_status_bundle(&PendingAndroidProxyStatus {
                sequence: 12,
                status: AndroidProxyStatus {
                    security_path: Some(path),
                    ..status.clone()
                },
            })
            .unwrap();
            assert_eq!(mapped[26], code);
        }

        let oversized = PendingAndroidProxyStatus {
            sequence: 12,
            status: AndroidProxyStatus {
                resolution_trace_json: Some("x".repeat(MAX_PROXY_STATUS_BUNDLE_BYTES)),
                ..status
            },
        };
        let bounded = proxy_status_bundle(&oversized).unwrap();
        let trace_length_offset = 29 + "welcome".len();
        assert_eq!(
            u32::from_be_bytes(
                bounded[trace_length_offset..trace_length_offset + 4]
                    .try_into()
                    .unwrap()
            ),
            0
        );
        assert!(bounded.len() <= MAX_PROXY_STATUS_BUNDLE_BYTES);
    }

    #[test]
    fn proxy_status_host_canonicalization_rejects_unsafe_names() {
        assert_eq!(
            canonical_proxy_status_host(" Welcome. ").as_deref(),
            Some("welcome")
        );
        for invalid in ["", ".", "-welcome", "welcome-", "wel_come", "a..b"] {
            assert!(canonical_proxy_status_host(invalid).is_none(), "{invalid}");
        }
    }
}
