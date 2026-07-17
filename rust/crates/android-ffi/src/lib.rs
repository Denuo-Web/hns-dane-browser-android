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
const MAX_BROWSER_NAMESPACE_INPUT_BYTES: usize = 1_024;
const ANDROID_BROWSER_NAMESPACE_INVALID: jint = 0;
const ANDROID_BROWSER_NAMESPACE_HNS: jint = 1;
const ANDROID_BROWSER_NAMESPACE_ICANN: jint = 2;
const ANDROID_BROWSER_NAMESPACE_NATIVE_GATEWAY: jint = 3;
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
        Some(BrowserProxySecurityPath::DaneP2pDnsRelay) => Some(9),
        Some(BrowserProxySecurityPath::HnsP2pDnsRelay) => Some(10),
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
    strict_hns_mode: jboolean,
    doh_resolver_url: JString<'local>,
    stateless_dane_certificates: jboolean,
    experimental_p2p_dns_relay: jboolean,
    legacy_hns_doh_compatibility: jboolean,
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

fn android_browser_namespace_code(input: &str) -> jint {
    if input.len() > MAX_BROWSER_NAMESPACE_INPUT_BYTES {
        return ANDROID_BROWSER_NAMESPACE_INVALID;
    }
    match classify_browser_host(input) {
        BrowserHostClass::Hns => ANDROID_BROWSER_NAMESPACE_HNS,
        BrowserHostClass::Icann => ANDROID_BROWSER_NAMESPACE_ICANN,
        BrowserHostClass::NativeGateway => ANDROID_BROWSER_NAMESPACE_NATIVE_GATEWAY,
        BrowserHostClass::Search => ANDROID_BROWSER_NAMESPACE_INVALID,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeClassifyBrowserHost(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    host: JString<'_>,
) -> jint {
    catch_unwind(AssertUnwindSafe(|| {
        env.get_string(&host)
            .ok()
            .map(|host| android_browser_namespace_code(&host.to_string_lossy()))
            .unwrap_or(ANDROID_BROWSER_NAMESPACE_INVALID)
    }))
    .unwrap_or(ANDROID_BROWSER_NAMESPACE_INVALID)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeBrowserWebSocketScopePolicyScript(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        env.new_string(browser_websocket_scope_policy_script())
            .map(|value| value.into_raw())
            .unwrap_or(std::ptr::null_mut())
    }))
    .unwrap_or(std::ptr::null_mut())
}

fn jni_runtime_gateway_request(
    env: &mut JNIEnv<'_>,
    input: JniRuntimeGatewayHttpRequest<'_>,
) -> Option<RawGatewayHttpRequest> {
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
    let body = env.convert_byte_array(&input.body).ok()?;
    Some(RawGatewayHttpRequest {
        method,
        scheme,
        host,
        port: input.port,
        path_and_query,
        header_text,
        body,
    })
}

fn runtime_gateway_policy(
    env: &mut JNIEnv<'_>,
    input: RuntimeGatewayPolicyInput<'_>,
) -> Option<RuntimePolicy> {
    let doh_resolver_url = env
        .get_string(&input.doh_resolver_url)
        .ok()?
        .to_string_lossy()
        .trim()
        .to_owned();
    Some(runtime_gateway_policy_from_values(
        input.strict_hns_mode,
        doh_resolver_url,
        input.stateless_dane_certificates,
        input.experimental_p2p_dns_relay,
        input.legacy_hns_doh_compatibility,
    ))
}

fn runtime_gateway_policy_from_values(
    strict_hns_mode: jboolean,
    doh_resolver_url: String,
    stateless_dane_certificates: jboolean,
    experimental_p2p_dns_relay: jboolean,
    legacy_hns_doh_compatibility: jboolean,
) -> RuntimePolicy {
    RuntimePolicy {
        resolution_mode: if strict_hns_mode == 0 {
            ResolutionMode::Compatibility
        } else {
            ResolutionMode::Strict
        },
        hns_doh_resolver: (!doh_resolver_url.is_empty()).then_some(doh_resolver_url),
        experimental_p2p_dns_relay: experimental_p2p_dns_relay != 0,
        legacy_hns_doh_compatibility: legacy_hns_doh_compatibility != 0,
        stateless_dane_certificates: stateless_dane_certificates != 0,
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
    Box::into_raw(Box::new(AndroidRuntimeRecord { runtime })) as usize as jlong
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
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeRuntimeAddStaticRelayPeer(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    endpoint: JString<'_>,
) -> jstring {
    let status = match (runtime_from_handle(handle), env.get_string(&endpoint)) {
        (Some(runtime), Ok(endpoint)) => runtime_status_json(
            runtime.network(),
            runtime.add_static_relay_peer(endpoint.to_string_lossy().as_ref()),
        ),
        _ => NativeSyncStatus::error("invalid static relay peer input".to_owned()).to_json(),
    };
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
    strict_hns_mode: jboolean,
    doh_resolver_url: JString<'_>,
    stateless_dane_certificates: jboolean,
    experimental_p2p_dns_relay: jboolean,
    legacy_hns_doh_compatibility: jboolean,
    scope_root: JString<'_>,
) -> jbyteArray {
    catch_unwind(AssertUnwindSafe(|| {
        let result = runtime_from_handle(handle)
            .zip(runtime_gateway_policy(
                &mut env,
                RuntimeGatewayPolicyInput {
                    strict_hns_mode,
                    doh_resolver_url,
                    stateless_dane_certificates,
                    experimental_p2p_dns_relay,
                    legacy_hns_doh_compatibility,
                },
            ))
            .zip(env.get_string(&scope_root).ok())
            .and_then(|((runtime, policy), scope_root)| {
                let scope_root = scope_root.to_string_lossy();
                let statuses = Arc::new(AndroidProxyStatusMailbox::new());
                runtime
                    .start_whole_browser_proxy_with_policy_and_observer(
                        Some(&scope_root),
                        policy,
                        statuses.clone(),
                    )
                    .ok()
                    .map(|proxy| (proxy, statuses))
            })
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
    strict_hns_mode: jboolean,
    doh_resolver_url: JString<'_>,
    stateless_dane_certificates: jboolean,
    experimental_p2p_dns_relay: jboolean,
    legacy_hns_doh_compatibility: jboolean,
    method: JString<'_>,
    scheme: JString<'_>,
    host: JString<'_>,
    port: jint,
    path_and_query: JString<'_>,
    header_text: JString<'_>,
    body: JByteArray<'_>,
) -> jbyteArray {
    catch_unwind(AssertUnwindSafe(|| {
        let response = runtime_from_handle(handle)
            .zip(runtime_gateway_policy(
                &mut env,
                RuntimeGatewayPolicyInput {
                    strict_hns_mode,
                    doh_resolver_url,
                    stateless_dane_certificates,
                    experimental_p2p_dns_relay,
                    legacy_hns_doh_compatibility,
                },
            ))
            .zip(jni_runtime_gateway_request(
                &mut env,
                JniRuntimeGatewayHttpRequest {
                    method,
                    scheme,
                    host,
                    port,
                    path_and_query,
                    header_text,
                    body,
                },
            ))
            .map(|((runtime, policy), request)| {
                runtime.raw_gateway_request(request, policy).into_bytes()
            });
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
    strict_hns_mode: jboolean,
    doh_resolver_url: JString<'_>,
    stateless_dane_certificates: jboolean,
    experimental_p2p_dns_relay: jboolean,
    legacy_hns_doh_compatibility: jboolean,
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
        let body_path = env
            .get_string(&body_path)
            .ok()
            .map(|value| value.to_string_lossy().into_owned());
        let response = runtime_from_handle(handle)
            .zip(runtime_gateway_policy(
                &mut env,
                RuntimeGatewayPolicyInput {
                    strict_hns_mode,
                    doh_resolver_url,
                    stateless_dane_certificates,
                    experimental_p2p_dns_relay,
                    legacy_hns_doh_compatibility,
                },
            ))
            .zip(jni_runtime_gateway_request(
                &mut env,
                JniRuntimeGatewayHttpRequest {
                    method,
                    scheme,
                    host,
                    port,
                    path_and_query,
                    header_text,
                    body,
                },
            ))
            .zip(body_path)
            .and_then(|(((runtime, policy), request), body_path)| {
                runtime
                    .raw_gateway_request_body_to_file(request, policy, Path::new(&body_path))
                    .ok()
            });
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn gateway_policy_carries_independent_relay_controls() {
        let policy = runtime_gateway_policy_from_values(
            1,
            "https://resolver.example/dns-query".to_owned(),
            0,
            1,
            0,
        );

        assert_eq!(policy.resolution_mode, ResolutionMode::Strict);
        assert!(policy.experimental_p2p_dns_relay);
        assert!(!policy.legacy_hns_doh_compatibility);
        assert!(!policy.stateless_dane_certificates);
    }

    #[test]
    fn browser_namespace_jni_codes_follow_the_shared_rust_policy() {
        assert_eq!(
            android_browser_namespace_code("welcome"),
            ANDROID_BROWSER_NAMESPACE_HNS
        );
        assert_eq!(
            android_browser_namespace_code("sub.welcome"),
            ANDROID_BROWSER_NAMESPACE_HNS
        );
        assert_eq!(
            android_browser_namespace_code("DANE-TEST.DENUOWEB.COM."),
            ANDROID_BROWSER_NAMESPACE_NATIVE_GATEWAY
        );
        for host in [
            "example.com",
            "home.arpa",
            "printer.local",
            "127.0.0.1",
            "::1",
        ] {
            assert_eq!(
                android_browser_namespace_code(host),
                ANDROID_BROWSER_NAMESPACE_ICANN,
                "{host}"
            );
        }
        for host in ["", "two words", "https://"] {
            assert_eq!(
                android_browser_namespace_code(host),
                ANDROID_BROWSER_NAMESPACE_INVALID,
                "{host}"
            );
        }
        assert_eq!(
            android_browser_namespace_code(&"a".repeat(MAX_BROWSER_NAMESPACE_INPUT_BYTES + 1)),
            ANDROID_BROWSER_NAMESPACE_INVALID
        );
    }

    #[test]
    fn websocket_policy_jni_payload_is_the_shared_runtime_script() {
        let script = browser_websocket_scope_policy_script();
        assert!(script.contains("window.__hnsRustNamespacePolicyVersion = 1"));
        assert!(script.contains("'com'"));
        assert!(script.contains("'localhost'"));
        assert!(script.contains("requiresHnsResolution(targetHost)"));
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
        let handle = Box::into_raw(Box::new(AndroidRuntimeRecord { runtime })) as usize as jlong;

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
            (BrowserProxySecurityPath::DaneP2pDnsRelay, 9),
            (BrowserProxySecurityPath::HnsP2pDnsRelay, 10),
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
