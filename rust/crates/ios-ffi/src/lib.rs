//! Stable, panic-contained C ABI for the iOS browser shell.
//!
//! The ABI exposes only numeric registry handles and allocator-paired owned
//! buffers. No Rust object address crosses the boundary.

#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]
#![deny(unsafe_op_in_unsafe_fn)]

use hns_browser_runtime::{
    BrowserNameClass, BrowserProxy, BrowserProxyResolverPolicy, BrowserProxySecurityPath,
    BrowserProxyStatus, BrowserProxyStatusObserver, BrowserProxyTlsPolicy, BrowserRuntime,
    DEFAULT_RESOURCE_CACHE_LIMIT_BYTES, NetworkKind, ResolutionMode, RuntimeConfiguration,
    RuntimePolicy, SyncOptions, browser_hns_root_label, canonical_browser_host,
    classify_browser_name, core_version, diagnostics_json,
};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, TryLockError};
use std::time::Duration;

pub const HNS_BROWSER_ABI_VERSION: u32 = 1;

pub type HnsBrowserResult = u32;
pub const HNS_BROWSER_RESULT_OK: HnsBrowserResult = 0;
pub const HNS_BROWSER_RESULT_INVALID_ARGUMENT: HnsBrowserResult = 1;
pub const HNS_BROWSER_RESULT_INVALID_UTF8: HnsBrowserResult = 2;
pub const HNS_BROWSER_RESULT_NOT_FOUND: HnsBrowserResult = 3;
pub const HNS_BROWSER_RESULT_RESOURCE_EXHAUSTED: HnsBrowserResult = 4;
pub const HNS_BROWSER_RESULT_RUNTIME_ERROR: HnsBrowserResult = 5;
pub const HNS_BROWSER_RESULT_PROXY_ERROR: HnsBrowserResult = 6;
pub const HNS_BROWSER_RESULT_BUFFER_ERROR: HnsBrowserResult = 7;
pub const HNS_BROWSER_RESULT_PANIC: HnsBrowserResult = 8;
pub const HNS_BROWSER_RESULT_NOT_READY: HnsBrowserResult = 9;

pub type HnsBrowserRuntimeHandle = u64;
pub type HnsBrowserProxyHandle = u64;

const HNS_BROWSER_NETWORK_MAINNET: u32 = 0;
const HNS_BROWSER_NETWORK_TESTNET: u32 = 1;
const HNS_BROWSER_NETWORK_REGTEST: u32 = 2;
const HNS_BROWSER_RESOLUTION_COMPATIBILITY: u32 = 0;
const HNS_BROWSER_RESOLUTION_STRICT: u32 = 1;
const HNS_BROWSER_NAME_HNS: u32 = 0;
const HNS_BROWSER_NAME_ICANN: u32 = 1;
const HNS_BROWSER_NAME_SEARCH: u32 = 2;
const HNS_BROWSER_TLS_POLICY_UNKNOWN: u32 = 0;
const HNS_BROWSER_TLS_POLICY_DANE: u32 = 1;
const HNS_BROWSER_TLS_POLICY_WEBPKI_FALLBACK: u32 = 2;
const HNS_BROWSER_RESOLVER_POLICY_UNKNOWN: u32 = 0;
const HNS_BROWSER_RESOLVER_POLICY_HNS_DOH_COMPATIBILITY: u32 = 1;
const HNS_BROWSER_SECURITY_PATH_UNKNOWN: u32 = 0;
const HNS_BROWSER_SECURITY_PATH_DANE_AUTHORITATIVE_DOH: u32 = 1;
const HNS_BROWSER_SECURITY_PATH_DANE_AUTHORITATIVE_DNS53: u32 = 2;
const HNS_BROWSER_SECURITY_PATH_DANE_THIRD_PARTY_DOH: u32 = 3;
const HNS_BROWSER_SECURITY_PATH_STATELESS_DANE: u32 = 4;
const HNS_BROWSER_SECURITY_PATH_DANE_ICANN_DOH: u32 = 5;
const HNS_BROWSER_SECURITY_PATH_HNS_AUTHORITATIVE_DOH: u32 = 6;
const HNS_BROWSER_SECURITY_PATH_HNS_AUTHORITATIVE_DNS53: u32 = 7;
const HNS_BROWSER_SECURITY_PATH_HNS_THIRD_PARTY_DOH: u32 = 8;

const DEFAULT_SYNC_TIMEOUT_MILLIS: u64 = 3_000;
const MAX_SYNC_TIMEOUT_MILLIS: u64 = 10 * 60 * 1_000;
const MAX_RESOURCE_CACHE_LIMIT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_RUNTIME_HANDLES: usize = 16;
const MAX_PROXY_HANDLES: usize = 64;
const MAX_MAIN_FRAME_STATUSES: usize = 64;
const MAX_ALLOCATIONS: usize = 256;
const MAX_ALLOCATED_BYTES: usize = 8 * 1024 * 1024;
const MAX_OUTPUT_BUFFER_BYTES: usize = 1024 * 1024;
const MAX_ERROR_BYTES: usize = 4 * 1024;
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_POLICY_ENDPOINT_BYTES: usize = 4 * 1024;
const MAX_NAME_INPUT_BYTES: usize = 4 * 1024;
const MAX_HOST_BYTES: usize = 253;
const MAX_AUTH_FIELD_BYTES: usize = 4 * 1024;
const MAX_CERTIFICATE_DER_BYTES: usize = 1024 * 1024;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HnsBrowserSlice {
    pub ptr: *const u8,
    pub len: u64,
}

impl HnsBrowserSlice {
    const fn empty() -> Self {
        Self {
            ptr: ptr::null(),
            len: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HnsBrowserBuffer {
    pub ptr: *mut u8,
    pub len: u64,
    pub allocation_id: u64,
}

impl HnsBrowserBuffer {
    const fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
            allocation_id: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HnsBrowserRuntimeOptions {
    pub struct_size: u32,
    pub network: u32,
    pub data_dir: HnsBrowserSlice,
    pub sync_timeout_millis: u64,
    pub resource_cache_limit_bytes: u64,
    pub resolution_mode: u32,
    pub seed_peers: u8,
    pub stateless_dane_certificates: u8,
    pub reserved0: [u8; 2],
    pub hns_doh_resolver: HnsBrowserSlice,
    pub reserved1: [u64; 2],
}

impl HnsBrowserRuntimeOptions {
    fn defaults() -> Self {
        Self {
            struct_size: size_u32::<Self>(),
            network: HNS_BROWSER_NETWORK_MAINNET,
            data_dir: HnsBrowserSlice::empty(),
            sync_timeout_millis: DEFAULT_SYNC_TIMEOUT_MILLIS,
            resource_cache_limit_bytes: DEFAULT_RESOURCE_CACHE_LIMIT_BYTES as u64,
            resolution_mode: HNS_BROWSER_RESOLUTION_COMPATIBILITY,
            seed_peers: 1,
            stateless_dane_certificates: 0,
            reserved0: [0; 2],
            hns_doh_resolver: HnsBrowserSlice::empty(),
            reserved1: [0; 2],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HnsBrowserPolicy {
    pub struct_size: u32,
    pub resolution_mode: u32,
    pub hns_doh_resolver: HnsBrowserSlice,
    pub stateless_dane_certificates: u8,
    pub reserved0: [u8; 7],
    pub reserved1: u64,
}

impl HnsBrowserPolicy {
    fn defaults() -> Self {
        Self {
            struct_size: size_u32::<Self>(),
            resolution_mode: HNS_BROWSER_RESOLUTION_COMPATIBILITY,
            hns_doh_resolver: HnsBrowserSlice::empty(),
            stateless_dane_certificates: 0,
            reserved0: [0; 7],
            reserved1: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HnsBrowserProxyEndpoint {
    pub struct_size: u32,
    pub port: u16,
    pub reserved0: u16,
    pub generation: u64,
    pub session_id: HnsBrowserBuffer,
    pub realm: HnsBrowserBuffer,
    pub username: HnsBrowserBuffer,
    pub password: HnsBrowserBuffer,
}

impl HnsBrowserProxyEndpoint {
    fn empty() -> Self {
        Self {
            struct_size: size_u32::<Self>(),
            port: 0,
            reserved0: 0,
            generation: 0,
            session_id: HnsBrowserBuffer::empty(),
            realm: HnsBrowserBuffer::empty(),
            username: HnsBrowserBuffer::empty(),
            password: HnsBrowserBuffer::empty(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HnsBrowserProxyStatus {
    pub struct_size: u32,
    pub tls_policy: u32,
    pub resolver_policy: u32,
    pub security_path: u32,
    pub generation: u64,
    pub http_status: u32,
    pub reserved0: u32,
    pub host: HnsBrowserBuffer,
    pub resolution_trace_json: HnsBrowserBuffer,
}

impl HnsBrowserProxyStatus {
    fn empty() -> Self {
        Self {
            struct_size: size_u32::<Self>(),
            tls_policy: HNS_BROWSER_TLS_POLICY_UNKNOWN,
            resolver_policy: HNS_BROWSER_RESOLVER_POLICY_UNKNOWN,
            security_path: HNS_BROWSER_SECURITY_PATH_UNKNOWN,
            generation: 0,
            http_status: 0,
            reserved0: 0,
            host: HnsBrowserBuffer::empty(),
            resolution_trace_json: HnsBrowserBuffer::empty(),
        }
    }
}

const fn size_u32<T>() -> u32 {
    std::mem::size_of::<T>() as u32
}

struct FfiFailure {
    code: HnsBrowserResult,
    message: &'static str,
}

impl FfiFailure {
    const fn new(code: HnsBrowserResult, message: &'static str) -> Self {
        Self { code, message }
    }

    const fn invalid(message: &'static str) -> Self {
        Self::new(HNS_BROWSER_RESULT_INVALID_ARGUMENT, message)
    }

    const fn internal() -> Self {
        Self::new(
            HNS_BROWSER_RESULT_RUNTIME_ERROR,
            "internal runtime state is unavailable",
        )
    }
}

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

fn bounded_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while end != 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn set_last_error(message: &str) {
    let message = bounded_utf8(message, MAX_ERROR_BYTES);
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = message;
    });
}

fn clear_last_error() {
    LAST_ERROR.with(|slot| slot.borrow_mut().clear());
}

fn last_error_snapshot() -> String {
    LAST_ERROR.with(|slot| slot.borrow().clone())
}

fn contained_set_last_error(message: &str) {
    let _ = catch_unwind(AssertUnwindSafe(|| set_last_error(message)));
}

fn ffi_call(operation: impl FnOnce() -> Result<(), FfiFailure>) -> HnsBrowserResult {
    match catch_unwind(AssertUnwindSafe(|| {
        clear_last_error();
        operation()
    })) {
        Ok(Ok(())) => HNS_BROWSER_RESULT_OK,
        Ok(Err(failure)) => {
            contained_set_last_error(failure.message);
            failure.code
        }
        Err(_) => {
            contained_set_last_error("panic contained at the C ABI boundary");
            HNS_BROWSER_RESULT_PANIC
        }
    }
}

fn ffi_call_preserving_error(
    operation: impl FnOnce() -> Result<(), FfiFailure>,
) -> HnsBrowserResult {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => HNS_BROWSER_RESULT_OK,
        Ok(Err(failure)) => {
            contained_set_last_error(failure.message);
            failure.code
        }
        Err(_) => {
            contained_set_last_error("panic contained at the C ABI boundary");
            HNS_BROWSER_RESULT_PANIC
        }
    }
}

fn checked_len(len: u64, max: usize) -> Result<usize, FfiFailure> {
    let len = usize::try_from(len).map_err(|_| FfiFailure::invalid("input length is invalid"))?;
    if len > max {
        return Err(FfiFailure::invalid("input exceeds its ABI size limit"));
    }
    Ok(len)
}

unsafe fn input_bytes(slice: HnsBrowserSlice, max: usize) -> Result<Vec<u8>, FfiFailure> {
    let len = checked_len(slice.len, max)?;
    if len == 0 {
        return Ok(Vec::new());
    }
    if slice.ptr.is_null() {
        return Err(FfiFailure::invalid("non-empty input has a null pointer"));
    }
    // SAFETY: The C ABI contract requires a non-null input pointer to remain
    // readable for `len` bytes for the duration of the call. Length is bounded
    // before constructing the slice.
    Ok(unsafe { std::slice::from_raw_parts(slice.ptr, len) }.to_vec())
}

unsafe fn input_str(slice: HnsBrowserSlice, max: usize) -> Result<String, FfiFailure> {
    // SAFETY: Propagates the caller's readable-slice contract.
    String::from_utf8(unsafe { input_bytes(slice, max) }?)
        .map_err(|_| FfiFailure::new(HNS_BROWSER_RESULT_INVALID_UTF8, "input is not valid UTF-8"))
}

unsafe fn required_input_str(slice: HnsBrowserSlice, max: usize) -> Result<String, FfiFailure> {
    // SAFETY: Propagates the caller's readable-slice contract.
    let value = unsafe { input_str(slice, max) }?;
    if value.is_empty() {
        return Err(FfiFailure::invalid("required text input is empty"));
    }
    Ok(value)
}

unsafe fn optional_scope(slice: HnsBrowserSlice) -> Result<Option<String>, FfiFailure> {
    if slice.ptr.is_null() {
        if slice.len == 0 {
            return Ok(None);
        }
        return Err(FfiFailure::invalid(
            "scope length is nonzero with a null pointer",
        ));
    }
    if slice.len == 0 {
        return Err(FfiFailure::invalid(
            "an empty non-null scope is ambiguous; use a null slice for no HNS scope",
        ));
    }
    // SAFETY: The non-null, bounded slice is covered by the caller contract.
    unsafe { required_input_str(slice, MAX_HOST_BYTES) }.map(Some)
}

fn require_output<T>(output: *mut T) -> Result<(), FfiFailure> {
    if output.is_null() {
        Err(FfiFailure::invalid("output pointer is null"))
    } else {
        Ok(())
    }
}

unsafe fn write_output<T>(output: *mut T, value: T) {
    // SAFETY: The caller supplied a non-null, writable output pointer under
    // the C ABI contract; every call validates null before reaching here.
    unsafe { output.write(value) };
}

struct Allocation {
    bytes: Box<[u8]>,
    sensitive: bool,
}

impl Drop for Allocation {
    fn drop(&mut self) {
        if self.sensitive {
            self.bytes.fill(0);
        }
    }
}

#[derive(Default)]
struct AllocationRegistry {
    entries: HashMap<u64, Allocation>,
    total_bytes: usize,
}

static ALLOCATIONS: OnceLock<Mutex<AllocationRegistry>> = OnceLock::new();
static NEXT_ALLOCATION_ID: AtomicU64 = AtomicU64::new(1);

struct OutputValue<'a> {
    bytes: &'a [u8],
    sensitive: bool,
}

fn next_monotonic_id(counter: &AtomicU64) -> Result<u64, FfiFailure> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(1)
        })
        .map_err(|_| {
            FfiFailure::new(
                HNS_BROWSER_RESULT_RESOURCE_EXHAUSTED,
                "numeric handle space is exhausted",
            )
        })
}

fn allocation_registry() -> &'static Mutex<AllocationRegistry> {
    ALLOCATIONS.get_or_init(|| Mutex::new(AllocationRegistry::default()))
}

fn allocate_outputs(values: &[OutputValue<'_>]) -> Result<Vec<HnsBrowserBuffer>, FfiFailure> {
    let nonempty = values
        .iter()
        .filter(|value| !value.bytes.is_empty())
        .count();
    let additional_bytes = values.iter().try_fold(0usize, |total, value| {
        if value.bytes.len() > MAX_OUTPUT_BUFFER_BYTES {
            return Err(FfiFailure::new(
                HNS_BROWSER_RESULT_RESOURCE_EXHAUSTED,
                "output exceeds the ABI buffer size limit",
            ));
        }
        total.checked_add(value.bytes.len()).ok_or_else(|| {
            FfiFailure::new(
                HNS_BROWSER_RESULT_RESOURCE_EXHAUSTED,
                "output allocation size is exhausted",
            )
        })
    })?;
    let mut registry = allocation_registry()
        .lock()
        .map_err(|_| FfiFailure::internal())?;
    if registry.entries.len().saturating_add(nonempty) > MAX_ALLOCATIONS
        || registry.total_bytes.saturating_add(additional_bytes) > MAX_ALLOCATED_BYTES
    {
        return Err(FfiFailure::new(
            HNS_BROWSER_RESULT_RESOURCE_EXHAUSTED,
            "owned output buffer registry is full",
        ));
    }

    let mut ids = Vec::with_capacity(nonempty);
    for _ in 0..nonempty {
        ids.push(next_monotonic_id(&NEXT_ALLOCATION_ID)?);
    }
    let mut id_iter = ids.into_iter();
    let mut outputs = Vec::with_capacity(values.len());
    for value in values {
        if value.bytes.is_empty() {
            outputs.push(HnsBrowserBuffer::empty());
            continue;
        }
        let allocation_id = id_iter.next().ok_or_else(FfiFailure::internal)?;
        let mut allocation = Allocation {
            bytes: value.bytes.to_vec().into_boxed_slice(),
            sensitive: value.sensitive,
        };
        let output = HnsBrowserBuffer {
            ptr: allocation.bytes.as_mut_ptr(),
            len: allocation.bytes.len() as u64,
            allocation_id,
        };
        registry.entries.insert(allocation_id, allocation);
        outputs.push(output);
    }
    registry.total_bytes = registry
        .total_bytes
        .checked_add(additional_bytes)
        .ok_or_else(FfiFailure::internal)?;
    Ok(outputs)
}

fn allocate_output(bytes: &[u8], sensitive: bool) -> Result<HnsBrowserBuffer, FfiFailure> {
    let mut outputs = allocate_outputs(&[OutputValue { bytes, sensitive }])?;
    outputs.pop().ok_or_else(FfiFailure::internal)
}

fn free_output(buffer: HnsBrowserBuffer) -> Result<(), FfiFailure> {
    if buffer.allocation_id == 0 {
        if buffer.ptr.is_null() && buffer.len == 0 {
            return Ok(());
        }
        return Err(FfiFailure::new(
            HNS_BROWSER_RESULT_BUFFER_ERROR,
            "owned buffer token is invalid",
        ));
    }
    let mut registry = allocation_registry()
        .lock()
        .map_err(|_| FfiFailure::internal())?;
    let matches = registry
        .entries
        .get(&buffer.allocation_id)
        .is_some_and(|allocation| {
            allocation.bytes.as_ptr().cast_mut() == buffer.ptr
                && allocation.bytes.len() as u64 == buffer.len
        });
    if !matches {
        return Err(FfiFailure::new(
            HNS_BROWSER_RESULT_BUFFER_ERROR,
            "owned buffer is stale, mismatched, or foreign",
        ));
    }
    let allocation = registry
        .entries
        .remove(&buffer.allocation_id)
        .ok_or_else(FfiFailure::internal)?;
    registry.total_bytes = registry.total_bytes.saturating_sub(allocation.bytes.len());
    drop(allocation);
    Ok(())
}

fn release_allocated_outputs(outputs: &[HnsBrowserBuffer]) {
    for output in outputs {
        let _ = free_output(*output);
    }
}

struct RuntimeEntry {
    runtime: BrowserRuntime,
}

#[derive(Clone)]
struct QueuedMainFrameStatus {
    generation: u64,
    host: String,
    http_status: u16,
    tls_policy: u32,
    resolver_policy: u32,
    security_path: u32,
    resolution_trace_json: String,
}

struct MainFrameStatusMailbox {
    statuses: Mutex<VecDeque<QueuedMainFrameStatus>>,
    accepting: AtomicBool,
}

impl Default for MainFrameStatusMailbox {
    fn default() -> Self {
        Self {
            statuses: Mutex::new(VecDeque::new()),
            accepting: AtomicBool::new(true),
        }
    }
}

impl BrowserProxyStatusObserver for MainFrameStatusMailbox {
    fn observe_status(&self, status: &BrowserProxyStatus) {
        if !status.is_likely_main_frame() || !self.accepting.load(Ordering::Acquire) {
            return;
        }
        let queued = QueuedMainFrameStatus {
            generation: status.generation(),
            host: status.host().to_owned(),
            http_status: status.status_code(),
            tls_policy: tls_policy_code(status.tls_policy()),
            resolver_policy: resolver_policy_code(status.resolver_policy()),
            security_path: security_path_code(status.security_path()),
            resolution_trace_json: status
                .resolution_trace_json()
                .unwrap_or_default()
                .to_owned(),
        };
        let Ok(mut statuses) = self.statuses.lock() else {
            return;
        };
        if !self.accepting.load(Ordering::Acquire) {
            return;
        }
        if let Some(index) = statuses.iter().position(|existing| {
            existing.generation == queued.generation && existing.host == queued.host
        }) {
            statuses.remove(index);
        }
        if statuses.len() == MAX_MAIN_FRAME_STATUSES {
            statuses.pop_front();
        }
        statuses.push_back(queued);
    }
}

struct ProxyEntry {
    runtime_handle: HnsBrowserRuntimeHandle,
    #[cfg(test)]
    policy_revision: u64,
    proxy: BrowserProxy,
    mailbox: Arc<MainFrameStatusMailbox>,
    active: AtomicBool,
}

impl ProxyEntry {
    fn ensure_active(&self) -> Result<(), FfiFailure> {
        if !self.active.load(Ordering::Acquire)
            || self.proxy.is_stop_requested()
            || self.proxy.is_stopped()
        {
            return Err(FfiFailure::new(
                HNS_BROWSER_RESULT_NOT_FOUND,
                "proxy generation is inactive",
            ));
        }
        Ok(())
    }

    fn request_stop(&self) {
        self.active.store(false, Ordering::Release);
        self.mailbox.accepting.store(false, Ordering::Release);
        // Revoke the shared endpoint, credentials, pins, sockets, and backend
        // work without waiting for worker joins or in-flight FFI reads.
        self.proxy.request_stop();
        match self.mailbox.statuses.try_lock() {
            Ok(mut statuses) => statuses.clear(),
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner().clear(),
            Err(TryLockError::WouldBlock) => {}
        }
    }

    fn blocking_stop(&self) {
        self.request_stop();
        self.proxy.stop();
    }
}

#[derive(Default)]
struct HandleRegistry {
    runtimes: HashMap<HnsBrowserRuntimeHandle, Arc<RuntimeEntry>>,
    proxies: HashMap<HnsBrowserProxyHandle, Arc<ProxyEntry>>,
}

static HANDLES: OnceLock<Mutex<HandleRegistry>> = OnceLock::new();
// Runtime and proxy handles share one monotonic namespace so accidental
// cross-type use cannot alias a simultaneously live object.
static NEXT_OBJECT_HANDLE: AtomicU64 = AtomicU64::new(1);

fn handle_registry() -> &'static Mutex<HandleRegistry> {
    HANDLES.get_or_init(|| Mutex::new(HandleRegistry::default()))
}

fn runtime_entry(handle: HnsBrowserRuntimeHandle) -> Result<Arc<RuntimeEntry>, FfiFailure> {
    if handle == 0 {
        return Err(FfiFailure::new(
            HNS_BROWSER_RESULT_NOT_FOUND,
            "runtime handle is invalid or stale",
        ));
    }
    handle_registry()
        .lock()
        .map_err(|_| FfiFailure::internal())?
        .runtimes
        .get(&handle)
        .cloned()
        .ok_or_else(|| {
            FfiFailure::new(
                HNS_BROWSER_RESULT_NOT_FOUND,
                "runtime handle is invalid or stale",
            )
        })
}

fn proxy_entry(handle: HnsBrowserProxyHandle) -> Result<Arc<ProxyEntry>, FfiFailure> {
    if handle == 0 {
        return Err(FfiFailure::new(
            HNS_BROWSER_RESULT_NOT_FOUND,
            "proxy handle is invalid or stale",
        ));
    }
    handle_registry()
        .lock()
        .map_err(|_| FfiFailure::internal())?
        .proxies
        .get(&handle)
        .cloned()
        .ok_or_else(|| {
            FfiFailure::new(
                HNS_BROWSER_RESULT_NOT_FOUND,
                "proxy handle is invalid or stale",
            )
        })
}

fn network_kind(value: u32) -> Result<NetworkKind, FfiFailure> {
    match value {
        HNS_BROWSER_NETWORK_MAINNET => Ok(NetworkKind::Mainnet),
        HNS_BROWSER_NETWORK_TESTNET => Ok(NetworkKind::Testnet),
        HNS_BROWSER_NETWORK_REGTEST => Ok(NetworkKind::Regtest),
        _ => Err(FfiFailure::invalid("network value is unsupported")),
    }
}

fn resolution_mode(value: u32) -> Result<ResolutionMode, FfiFailure> {
    match value {
        HNS_BROWSER_RESOLUTION_COMPATIBILITY => Ok(ResolutionMode::Compatibility),
        HNS_BROWSER_RESOLUTION_STRICT => Ok(ResolutionMode::Strict),
        _ => Err(FfiFailure::invalid("resolution mode value is unsupported")),
    }
}

fn ffi_bool(value: u8) -> Result<bool, FfiFailure> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(FfiFailure::invalid("boolean ABI field must be zero or one")),
    }
}

unsafe fn optional_policy_endpoint(slice: HnsBrowserSlice) -> Result<Option<String>, FfiFailure> {
    // SAFETY: Propagates the caller's readable-slice contract.
    let value = unsafe { input_str(slice, MAX_POLICY_ENDPOINT_BYTES) }?;
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value.to_owned()))
    }
}

unsafe fn policy_from_fields(
    mode: u32,
    endpoint: HnsBrowserSlice,
    stateless_dane_certificates: u8,
) -> Result<RuntimePolicy, FfiFailure> {
    Ok(RuntimePolicy {
        resolution_mode: resolution_mode(mode)?,
        // SAFETY: Propagates the caller's readable-slice contract.
        hns_doh_resolver: unsafe { optional_policy_endpoint(endpoint) }?,
        stateless_dane_certificates: ffi_bool(stateless_dane_certificates)?,
    })
}

fn validate_options(options: HnsBrowserRuntimeOptions) -> Result<(), FfiFailure> {
    if options.struct_size != size_u32::<HnsBrowserRuntimeOptions>() {
        return Err(FfiFailure::invalid(
            "runtime options struct size does not match ABI version",
        ));
    }
    if options.reserved0 != [0; 2] || options.reserved1 != [0; 2] {
        return Err(FfiFailure::invalid(
            "reserved runtime option fields must be zero",
        ));
    }
    if options.sync_timeout_millis == 0 || options.sync_timeout_millis > MAX_SYNC_TIMEOUT_MILLIS {
        return Err(FfiFailure::invalid(
            "sync timeout is outside the supported range",
        ));
    }
    if options.resource_cache_limit_bytes == 0
        || options.resource_cache_limit_bytes > MAX_RESOURCE_CACHE_LIMIT_BYTES
    {
        return Err(FfiFailure::invalid(
            "resource cache limit is outside the supported range",
        ));
    }
    Ok(())
}

fn validate_policy(policy: HnsBrowserPolicy) -> Result<(), FfiFailure> {
    if policy.struct_size != size_u32::<HnsBrowserPolicy>() {
        return Err(FfiFailure::invalid(
            "policy struct size does not match ABI version",
        ));
    }
    if policy.reserved0 != [0; 7] || policy.reserved1 != 0 {
        return Err(FfiFailure::invalid("reserved policy fields must be zero"));
    }
    Ok(())
}

fn tls_policy_code(policy: Option<BrowserProxyTlsPolicy>) -> u32 {
    match policy {
        None => HNS_BROWSER_TLS_POLICY_UNKNOWN,
        Some(BrowserProxyTlsPolicy::Dane) => HNS_BROWSER_TLS_POLICY_DANE,
        Some(BrowserProxyTlsPolicy::WebPkiFallback) => HNS_BROWSER_TLS_POLICY_WEBPKI_FALLBACK,
        Some(_) => HNS_BROWSER_TLS_POLICY_UNKNOWN,
    }
}

fn resolver_policy_code(policy: Option<BrowserProxyResolverPolicy>) -> u32 {
    match policy {
        None => HNS_BROWSER_RESOLVER_POLICY_UNKNOWN,
        Some(BrowserProxyResolverPolicy::HnsDohCompatibility) => {
            HNS_BROWSER_RESOLVER_POLICY_HNS_DOH_COMPATIBILITY
        }
        Some(_) => HNS_BROWSER_RESOLVER_POLICY_UNKNOWN,
    }
}

fn security_path_code(path: Option<BrowserProxySecurityPath>) -> u32 {
    match path {
        None => HNS_BROWSER_SECURITY_PATH_UNKNOWN,
        Some(BrowserProxySecurityPath::DaneAuthoritativeDoh) => {
            HNS_BROWSER_SECURITY_PATH_DANE_AUTHORITATIVE_DOH
        }
        Some(BrowserProxySecurityPath::DaneAuthoritativeDns53) => {
            HNS_BROWSER_SECURITY_PATH_DANE_AUTHORITATIVE_DNS53
        }
        Some(BrowserProxySecurityPath::DaneThirdPartyDoh) => {
            HNS_BROWSER_SECURITY_PATH_DANE_THIRD_PARTY_DOH
        }
        Some(BrowserProxySecurityPath::StatelessDane) => HNS_BROWSER_SECURITY_PATH_STATELESS_DANE,
        Some(BrowserProxySecurityPath::DaneIcannDoh) => HNS_BROWSER_SECURITY_PATH_DANE_ICANN_DOH,
        Some(BrowserProxySecurityPath::HnsAuthoritativeDoh) => {
            HNS_BROWSER_SECURITY_PATH_HNS_AUTHORITATIVE_DOH
        }
        Some(BrowserProxySecurityPath::HnsAuthoritativeDns53) => {
            HNS_BROWSER_SECURITY_PATH_HNS_AUTHORITATIVE_DNS53
        }
        Some(BrowserProxySecurityPath::HnsThirdPartyDoh) => {
            HNS_BROWSER_SECURITY_PATH_HNS_THIRD_PARTY_DOH
        }
        Some(_) => HNS_BROWSER_SECURITY_PATH_UNKNOWN,
    }
}

fn name_class_code(class: BrowserNameClass) -> u32 {
    match class {
        BrowserNameClass::Hns => HNS_BROWSER_NAME_HNS,
        BrowserNameClass::Icann => HNS_BROWSER_NAME_ICANN,
        BrowserNameClass::Search => HNS_BROWSER_NAME_SEARCH,
    }
}

unsafe fn write_json_output(output: *mut HnsBrowserBuffer, json: &str) -> Result<(), FfiFailure> {
    let buffer = allocate_output(json.as_bytes(), false)?;
    // SAFETY: Output was validated by the exported caller before this helper.
    unsafe { write_output(output, buffer) };
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut difference = left.len() ^ right.len();
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
}

#[unsafe(no_mangle)]
pub extern "C" fn hns_browser_abi_version() -> u32 {
    match catch_unwind(|| {
        clear_last_error();
        HNS_BROWSER_ABI_VERSION
    }) {
        Ok(version) => version,
        Err(_) => {
            contained_set_last_error("panic contained at the C ABI boundary");
            0
        }
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// `out_version` must point to one writable [`HnsBrowserBuffer`].
pub unsafe extern "C" fn hns_browser_core_version(
    out_version: *mut HnsBrowserBuffer,
) -> HnsBrowserResult {
    ffi_call(|| {
        require_output(out_version)?;
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_version, HnsBrowserBuffer::empty()) };
        // SAFETY: The output pointer was validated above.
        unsafe { write_json_output(out_version, core_version()) }
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `out_json` must point to one writable [`HnsBrowserBuffer`].
pub unsafe extern "C" fn hns_browser_diagnostics_json(
    out_json: *mut HnsBrowserBuffer,
) -> HnsBrowserResult {
    ffi_call(|| {
        require_output(out_json)?;
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_json, HnsBrowserBuffer::empty()) };
        // SAFETY: The output pointer was validated above.
        unsafe { write_json_output(out_json, &diagnostics_json()) }
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `out_error` must point to one writable [`HnsBrowserBuffer`].
pub unsafe extern "C" fn hns_browser_last_error(
    out_error: *mut HnsBrowserBuffer,
) -> HnsBrowserResult {
    ffi_call_preserving_error(|| {
        require_output(out_error)?;
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_error, HnsBrowserBuffer::empty()) };
        let error = last_error_snapshot();
        let buffer = allocate_output(error.as_bytes(), false)?;
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_error, buffer) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn hns_browser_buffer_free(buffer: HnsBrowserBuffer) -> HnsBrowserResult {
    ffi_call(|| free_output(buffer))
}

#[unsafe(no_mangle)]
/// # Safety
/// `out_options` must point to one writable [`HnsBrowserRuntimeOptions`].
pub unsafe extern "C" fn hns_browser_runtime_options_default(
    out_options: *mut HnsBrowserRuntimeOptions,
) -> HnsBrowserResult {
    ffi_call(|| {
        require_output(out_options)?;
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_options, HnsBrowserRuntimeOptions::defaults()) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `out_policy` must point to one writable [`HnsBrowserPolicy`].
pub unsafe extern "C" fn hns_browser_policy_default(
    out_policy: *mut HnsBrowserPolicy,
) -> HnsBrowserResult {
    ffi_call(|| {
        require_output(out_policy)?;
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_policy, HnsBrowserPolicy::defaults()) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `options` must point to one readable options value, every nested non-empty
/// slice must remain readable for its declared length, and `out_runtime` must
/// point to one writable handle.
pub unsafe extern "C" fn hns_browser_runtime_create(
    options: *const HnsBrowserRuntimeOptions,
    out_runtime: *mut HnsBrowserRuntimeHandle,
) -> HnsBrowserResult {
    ffi_call(|| {
        require_output(out_runtime)?;
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_runtime, 0) };
        if options.is_null() {
            return Err(FfiFailure::invalid("runtime options pointer is null"));
        }
        // SAFETY: The C contract requires `options` to point to one readable struct.
        let options = unsafe { options.read() };
        validate_options(options)?;

        {
            let registry = handle_registry()
                .lock()
                .map_err(|_| FfiFailure::internal())?;
            if registry.runtimes.len() >= MAX_RUNTIME_HANDLES {
                return Err(FfiFailure::new(
                    HNS_BROWSER_RESULT_RESOURCE_EXHAUSTED,
                    "runtime handle registry is full",
                ));
            }
        }

        // SAFETY: The caller guarantees readable slices in the options struct.
        let data_dir = unsafe { required_input_str(options.data_dir, MAX_PATH_BYTES) }?;
        let network = network_kind(options.network)?;
        // SAFETY: The caller guarantees readable slices in the options struct.
        let initial_policy = unsafe {
            policy_from_fields(
                options.resolution_mode,
                options.hns_doh_resolver,
                options.stateless_dane_certificates,
            )
        }?;
        let resource_cache_limit_bytes = usize::try_from(options.resource_cache_limit_bytes)
            .map_err(|_| FfiFailure::invalid("resource cache limit is unsupported"))?;
        let sync = SyncOptions {
            seed_peers: ffi_bool(options.seed_peers)?,
            timeout: Duration::from_millis(options.sync_timeout_millis),
            resource_cache_limit_bytes,
        };
        let configuration = RuntimeConfiguration::new(data_dir, network)
            .with_sync_options(sync)
            .with_initial_policy(initial_policy);
        let runtime = BrowserRuntime::open(configuration).map_err(|_| {
            FfiFailure::new(
                HNS_BROWSER_RESULT_RUNTIME_ERROR,
                "unable to open browser runtime",
            )
        })?;
        let handle = next_monotonic_id(&NEXT_OBJECT_HANDLE)?;
        let entry = Arc::new(RuntimeEntry { runtime });
        let mut registry = handle_registry()
            .lock()
            .map_err(|_| FfiFailure::internal())?;
        if registry.runtimes.len() >= MAX_RUNTIME_HANDLES {
            return Err(FfiFailure::new(
                HNS_BROWSER_RESULT_RESOURCE_EXHAUSTED,
                "runtime handle registry is full",
            ));
        }
        registry.runtimes.insert(handle, entry);
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_runtime, handle) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn hns_browser_runtime_destroy(
    runtime: HnsBrowserRuntimeHandle,
) -> HnsBrowserResult {
    ffi_call(|| {
        let proxies = {
            let mut registry = handle_registry()
                .lock()
                .map_err(|_| FfiFailure::internal())?;
            if registry.runtimes.remove(&runtime).is_none() {
                return Err(FfiFailure::new(
                    HNS_BROWSER_RESULT_NOT_FOUND,
                    "runtime handle is invalid or stale",
                ));
            }
            let owned_handles = registry
                .proxies
                .iter()
                .filter_map(|(handle, entry)| (entry.runtime_handle == runtime).then_some(*handle))
                .collect::<Vec<_>>();
            owned_handles
                .into_iter()
                .filter_map(|handle| registry.proxies.remove(&handle))
                .collect::<Vec<_>>()
        };
        for proxy in &proxies {
            proxy.request_stop();
        }
        for proxy in proxies {
            proxy.blocking_stop();
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `policy` must point to one readable policy value, every nested non-empty
/// slice must remain readable for its declared length, and `out_revision`
/// must point to one writable `u64`.
pub unsafe extern "C" fn hns_browser_runtime_set_policy(
    runtime: HnsBrowserRuntimeHandle,
    policy: *const HnsBrowserPolicy,
    out_revision: *mut u64,
) -> HnsBrowserResult {
    ffi_call(|| {
        require_output(out_revision)?;
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_revision, 0) };
        if policy.is_null() {
            return Err(FfiFailure::invalid("policy pointer is null"));
        }
        // SAFETY: The C contract requires `policy` to point to one readable struct.
        let policy = unsafe { policy.read() };
        validate_policy(policy)?;
        // SAFETY: The caller guarantees readable slices in the policy struct.
        let policy = unsafe {
            policy_from_fields(
                policy.resolution_mode,
                policy.hns_doh_resolver,
                policy.stateless_dane_certificates,
            )
        }?;
        let entry = runtime_entry(runtime)?;
        let (revision, owned) = {
            // Serialize policy publication with proxy insertion. A start that
            // began before this update must observe a revision mismatch under
            // this same lock and tear down instead of publishing its handle.
            let registry = handle_registry()
                .lock()
                .map_err(|_| FfiFailure::internal())?;
            let runtime_is_live = registry
                .runtimes
                .get(&runtime)
                .is_some_and(|current| Arc::ptr_eq(current, &entry));
            if !runtime_is_live {
                return Err(FfiFailure::new(
                    HNS_BROWSER_RESULT_NOT_FOUND,
                    "runtime handle is invalid or stale",
                ));
            }
            let revision = entry.runtime.set_policy(policy).map_err(|_| {
                FfiFailure::new(
                    HNS_BROWSER_RESULT_RUNTIME_ERROR,
                    "unable to update runtime policy",
                )
            })?;
            // Revoke every published generation so no proxy continues under
            // a policy snapshot the native shell believes replaced.
            let owned = registry
                .proxies
                .values()
                .filter(|proxy| proxy.runtime_handle == runtime)
                .cloned()
                .collect::<Vec<_>>();
            (revision, owned)
        };
        for proxy in owned {
            proxy.request_stop();
        }
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_revision, revision) };
        Ok(())
    })
}

unsafe fn runtime_status_json(
    runtime: HnsBrowserRuntimeHandle,
    out_status_json: *mut HnsBrowserBuffer,
    operation: impl FnOnce(&BrowserRuntime) -> Result<String, ()>,
) -> Result<(), FfiFailure> {
    require_output(out_status_json)?;
    // SAFETY: Null was rejected above and the C contract requires writable output.
    unsafe { write_output(out_status_json, HnsBrowserBuffer::empty()) };
    let entry = runtime_entry(runtime)?;
    let json = operation(&entry.runtime).map_err(|()| {
        FfiFailure::new(HNS_BROWSER_RESULT_RUNTIME_ERROR, "runtime operation failed")
    })?;
    // SAFETY: The output pointer was validated above.
    unsafe { write_json_output(out_status_json, &json) }
}

#[unsafe(no_mangle)]
/// # Safety
/// `out_status_json` must point to one writable [`HnsBrowserBuffer`].
pub unsafe extern "C" fn hns_browser_runtime_sync_once(
    runtime: HnsBrowserRuntimeHandle,
    out_status_json: *mut HnsBrowserBuffer,
) -> HnsBrowserResult {
    ffi_call(|| {
        // SAFETY: This unsafe export carries the caller's writable-output contract.
        unsafe {
            runtime_status_json(runtime, out_status_json, |runtime| {
                runtime
                    .sync_once()
                    .map(|status| status.to_json())
                    .map_err(|_| ())
            })
        }
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `out_status_json` must point to one writable [`HnsBrowserBuffer`].
pub unsafe extern "C" fn hns_browser_runtime_sync_status(
    runtime: HnsBrowserRuntimeHandle,
    out_status_json: *mut HnsBrowserBuffer,
) -> HnsBrowserResult {
    ffi_call(|| {
        // SAFETY: This unsafe export carries the caller's writable-output contract.
        unsafe {
            runtime_status_json(runtime, out_status_json, |runtime| {
                runtime
                    .sync_status()
                    .map(|status| status.to_json())
                    .map_err(|_| ())
            })
        }
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `out_status_json` must point to one writable [`HnsBrowserBuffer`].
pub unsafe extern "C" fn hns_browser_runtime_clear_resolver_cache(
    runtime: HnsBrowserRuntimeHandle,
    out_status_json: *mut HnsBrowserBuffer,
) -> HnsBrowserResult {
    ffi_call(|| {
        // SAFETY: This unsafe export carries the caller's writable-output contract.
        unsafe {
            runtime_status_json(runtime, out_status_json, |runtime| {
                runtime
                    .clear_resolver_cache()
                    .map(|status| status.to_json())
                    .map_err(|_| ())
            })
        }
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// The non-empty snapshot path slice must remain readable for its declared
/// length and `out_status_json` must point to one writable buffer.
pub unsafe extern "C" fn hns_browser_runtime_install_header_snapshot(
    runtime: HnsBrowserRuntimeHandle,
    snapshot_path: HnsBrowserSlice,
    out_status_json: *mut HnsBrowserBuffer,
) -> HnsBrowserResult {
    ffi_call(|| {
        // SAFETY: This unsafe export carries the caller's readable-slice contract.
        let path = unsafe { required_input_str(snapshot_path, MAX_PATH_BYTES) }?;
        // SAFETY: This unsafe export carries the caller's writable-output contract.
        unsafe {
            runtime_status_json(runtime, out_status_json, |runtime| {
                runtime
                    .install_header_snapshot(path)
                    .map(|status| status.to_json())
                    .map_err(|_| ())
            })
        }
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `out_status_json` must point to one writable [`HnsBrowserBuffer`].
pub unsafe extern "C" fn hns_browser_runtime_reset_headers_from_peers(
    runtime: HnsBrowserRuntimeHandle,
    out_status_json: *mut HnsBrowserBuffer,
) -> HnsBrowserResult {
    ffi_call(|| {
        // SAFETY: This unsafe export carries the caller's writable-output contract.
        unsafe {
            runtime_status_json(runtime, out_status_json, |runtime| {
                runtime
                    .reset_headers_from_peers()
                    .map(|status| status.to_json())
                    .map_err(|_| ())
            })
        }
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// The non-empty input slice must remain readable for its declared length and
/// `out_details_json` must point to one writable buffer.
pub unsafe extern "C" fn hns_browser_runtime_proof_details(
    runtime: HnsBrowserRuntimeHandle,
    host_or_url: HnsBrowserSlice,
    out_details_json: *mut HnsBrowserBuffer,
) -> HnsBrowserResult {
    ffi_call(|| {
        // SAFETY: This unsafe export carries the caller's readable-slice contract.
        let input = unsafe { required_input_str(host_or_url, MAX_NAME_INPUT_BYTES) }?;
        // SAFETY: This unsafe export carries the caller's writable-output contract.
        unsafe {
            runtime_status_json(runtime, out_details_json, |runtime| {
                runtime.proof_details(&input).map_err(|_| ())
            })
        }
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// Every non-empty input slice must remain readable for its declared length
/// and `out_class` must point to one writable `u32`.
pub unsafe extern "C" fn hns_browser_classify_name(
    input: HnsBrowserSlice,
    out_class: *mut u32,
) -> HnsBrowserResult {
    ffi_call(|| {
        require_output(out_class)?;
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_class, HNS_BROWSER_NAME_SEARCH) };
        // SAFETY: This unsafe export carries the caller's readable-slice contract.
        let input = unsafe { input_str(input, MAX_NAME_INPUT_BYTES) }?;
        let class = name_class_code(classify_browser_name(&input));
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_class, class) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// The non-empty input slice must remain readable for its declared length and
/// `out_host` must point to one writable buffer.
pub unsafe extern "C" fn hns_browser_canonical_host(
    input: HnsBrowserSlice,
    out_host: *mut HnsBrowserBuffer,
) -> HnsBrowserResult {
    ffi_call(|| {
        require_output(out_host)?;
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_host, HnsBrowserBuffer::empty()) };
        // SAFETY: This unsafe export carries the caller's readable-slice contract.
        let input = unsafe { required_input_str(input, MAX_NAME_INPUT_BYTES) }?;
        let host = canonical_browser_host(&input).ok_or_else(|| {
            FfiFailure::new(
                HNS_BROWSER_RESULT_NOT_FOUND,
                "input is not a canonicalizable DNS host",
            )
        })?;
        let buffer = allocate_output(host.as_bytes(), false)?;
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_host, buffer) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// The non-empty input slice must remain readable for its declared length and
/// `out_root` must point to one writable buffer.
pub unsafe extern "C" fn hns_browser_hns_root(
    input: HnsBrowserSlice,
    out_root: *mut HnsBrowserBuffer,
) -> HnsBrowserResult {
    ffi_call(|| {
        require_output(out_root)?;
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_root, HnsBrowserBuffer::empty()) };
        // SAFETY: This unsafe export carries the caller's readable-slice contract.
        let input = unsafe { required_input_str(input, MAX_NAME_INPUT_BYTES) }?;
        let root = browser_hns_root_label(&input).ok_or_else(|| {
            FfiFailure::new(
                HNS_BROWSER_RESULT_NOT_FOUND,
                "input does not identify an HNS name",
            )
        })?;
        let buffer = allocate_output(root.as_bytes(), false)?;
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_root, buffer) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// A non-null scope slice must remain readable for its declared length and
/// `out_proxy` must point to one writable handle.
pub unsafe extern "C" fn hns_browser_proxy_start(
    runtime: HnsBrowserRuntimeHandle,
    hns_scope_root: HnsBrowserSlice,
    out_proxy: *mut HnsBrowserProxyHandle,
) -> HnsBrowserResult {
    ffi_call(|| {
        require_output(out_proxy)?;
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_proxy, 0) };
        let runtime_entry = runtime_entry(runtime)?;
        {
            let registry = handle_registry()
                .lock()
                .map_err(|_| FfiFailure::internal())?;
            if registry.proxies.len() >= MAX_PROXY_HANDLES {
                return Err(FfiFailure::new(
                    HNS_BROWSER_RESULT_RESOURCE_EXHAUSTED,
                    "proxy handle registry is full",
                ));
            }
            if registry.proxies.values().any(|proxy| {
                proxy.runtime_handle == runtime
                    && proxy.active.load(Ordering::Acquire)
                    && !proxy.proxy.is_stopped()
            }) {
                return Err(FfiFailure::new(
                    HNS_BROWSER_RESULT_PROXY_ERROR,
                    "runtime already owns an active proxy generation",
                ));
            }
        }
        // SAFETY: This unsafe export carries the caller's readable-slice contract.
        let scope = unsafe { optional_scope(hns_scope_root) }?;
        let mailbox = Arc::new(MainFrameStatusMailbox::default());
        let observer: Arc<dyn BrowserProxyStatusObserver> = mailbox.clone();
        let policy_revision = runtime_entry.runtime.policy_revision();
        let proxy = runtime_entry
            .runtime
            .start_whole_browser_proxy_with_observer(scope.as_deref(), observer)
            .map_err(|_| {
                FfiFailure::new(
                    HNS_BROWSER_RESULT_PROXY_ERROR,
                    "unable to start whole-browser proxy generation",
                )
            })?;
        let handle = next_monotonic_id(&NEXT_OBJECT_HANDLE)?;
        let entry = Arc::new(ProxyEntry {
            runtime_handle: runtime,
            #[cfg(test)]
            policy_revision,
            proxy,
            mailbox,
            active: AtomicBool::new(true),
        });
        let insertion = {
            let mut registry = handle_registry()
                .lock()
                .map_err(|_| FfiFailure::internal())?;
            let runtime_is_live = registry
                .runtimes
                .get(&runtime)
                .is_some_and(|current| Arc::ptr_eq(current, &runtime_entry));
            if !runtime_is_live {
                Err(FfiFailure::new(
                    HNS_BROWSER_RESULT_NOT_FOUND,
                    "runtime was destroyed while starting the proxy",
                ))
            } else if runtime_entry.runtime.policy_revision() != policy_revision {
                Err(FfiFailure::new(
                    HNS_BROWSER_RESULT_PROXY_ERROR,
                    "runtime policy changed while starting the proxy",
                ))
            } else if registry.proxies.len() >= MAX_PROXY_HANDLES {
                Err(FfiFailure::new(
                    HNS_BROWSER_RESULT_RESOURCE_EXHAUSTED,
                    "proxy handle registry is full",
                ))
            } else if registry.proxies.values().any(|proxy| {
                proxy.runtime_handle == runtime
                    && proxy.active.load(Ordering::Acquire)
                    && !proxy.proxy.is_stopped()
            }) {
                Err(FfiFailure::new(
                    HNS_BROWSER_RESULT_PROXY_ERROR,
                    "runtime already owns an active proxy generation",
                ))
            } else {
                registry.proxies.insert(handle, Arc::clone(&entry));
                Ok(())
            }
        };
        if let Err(failure) = insertion {
            entry.blocking_stop();
            return Err(failure);
        }
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_proxy, handle) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `out_endpoint` must point to one writable [`HnsBrowserProxyEndpoint`].
pub unsafe extern "C" fn hns_browser_proxy_endpoint(
    proxy: HnsBrowserProxyHandle,
    out_endpoint: *mut HnsBrowserProxyEndpoint,
) -> HnsBrowserResult {
    ffi_call(|| {
        require_output(out_endpoint)?;
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_endpoint, HnsBrowserProxyEndpoint::empty()) };
        let entry = proxy_entry(proxy)?;
        entry.ensure_active()?;
        let proxy = &entry.proxy;
        let outputs = allocate_outputs(&[
            OutputValue {
                bytes: proxy.session_id().as_bytes(),
                sensitive: false,
            },
            OutputValue {
                bytes: proxy.authorization_realm().as_bytes(),
                sensitive: false,
            },
            OutputValue {
                bytes: proxy.authorization_username().as_bytes(),
                sensitive: true,
            },
            OutputValue {
                bytes: proxy.authorization_password().as_bytes(),
                sensitive: true,
            },
        ])?;
        if outputs.len() != 4 {
            release_allocated_outputs(&outputs);
            return Err(FfiFailure::internal());
        }
        let endpoint = HnsBrowserProxyEndpoint {
            struct_size: size_u32::<HnsBrowserProxyEndpoint>(),
            port: proxy.port(),
            reserved0: 0,
            generation: proxy.generation(),
            session_id: outputs[0],
            realm: outputs[1],
            username: outputs[2],
            password: outputs[3],
        };
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_endpoint, endpoint) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// The session slice must remain readable for its declared length and
/// `out_matches` must point to one writable byte.
pub unsafe extern "C" fn hns_browser_proxy_matches_instance(
    proxy: HnsBrowserProxyHandle,
    session_id: HnsBrowserSlice,
    generation: u64,
    out_matches: *mut u8,
) -> HnsBrowserResult {
    ffi_call(|| {
        require_output(out_matches)?;
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_matches, 0) };
        // SAFETY: This unsafe export carries the caller's readable-slice contract.
        let session_id = unsafe { required_input_str(session_id, MAX_AUTH_FIELD_BYTES) }?;
        let entry = proxy_entry(proxy)?;
        entry.ensure_active()?;
        let matches = entry.proxy.generation() == generation
            && constant_time_eq(entry.proxy.session_id().as_bytes(), session_id.as_bytes());
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_matches, u8::from(matches)) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// The host and realm slices must remain readable for their declared lengths
/// and `out_matches` must point to one writable byte.
pub unsafe extern "C" fn hns_browser_proxy_matches_authentication_challenge(
    proxy: HnsBrowserProxyHandle,
    host: HnsBrowserSlice,
    port: u16,
    realm: HnsBrowserSlice,
    out_matches: *mut u8,
) -> HnsBrowserResult {
    ffi_call(|| {
        require_output(out_matches)?;
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_matches, 0) };
        // SAFETY: This unsafe export carries the caller's readable-slice contract.
        let host = unsafe { required_input_str(host, MAX_HOST_BYTES) }?;
        // SAFETY: This unsafe export carries the caller's readable-slice contract.
        let realm = unsafe { required_input_str(realm, MAX_AUTH_FIELD_BYTES) }?;
        let entry = proxy_entry(proxy)?;
        entry.ensure_active()?;
        let matches = entry
            .proxy
            .matches_authentication_challenge(&host, port, &realm);
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_matches, u8::from(matches)) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// The host and DER slices must remain readable for their declared lengths
/// and `out_matches` must point to one writable byte.
pub unsafe extern "C" fn hns_browser_proxy_matches_local_certificate(
    proxy: HnsBrowserProxyHandle,
    host: HnsBrowserSlice,
    certificate_der: HnsBrowserSlice,
    out_matches: *mut u8,
) -> HnsBrowserResult {
    ffi_call(|| {
        require_output(out_matches)?;
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_matches, 0) };
        // SAFETY: This unsafe export carries the caller's readable-slice contract.
        let host = unsafe { required_input_str(host, MAX_HOST_BYTES) }?;
        // SAFETY: This unsafe export carries the caller's readable-slice contract.
        let certificate_der = unsafe { input_bytes(certificate_der, MAX_CERTIFICATE_DER_BYTES) }?;
        if certificate_der.is_empty() {
            return Err(FfiFailure::invalid("certificate DER is empty"));
        }
        let entry = proxy_entry(proxy)?;
        entry.ensure_active()?;
        let matches = entry
            .proxy
            .matches_local_certificate(&host, &certificate_der);
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_matches, u8::from(matches)) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// The host slice must remain readable for its declared length and
/// `out_status` must point to one writable [`HnsBrowserProxyStatus`].
pub unsafe extern "C" fn hns_browser_proxy_take_main_frame_status(
    proxy: HnsBrowserProxyHandle,
    canonical_main_frame_host: HnsBrowserSlice,
    out_status: *mut HnsBrowserProxyStatus,
) -> HnsBrowserResult {
    ffi_call(|| {
        require_output(out_status)?;
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_status, HnsBrowserProxyStatus::empty()) };
        // SAFETY: This unsafe export carries the caller's readable-slice contract.
        let host = unsafe { required_input_str(canonical_main_frame_host, MAX_HOST_BYTES) }?;
        let entry = proxy_entry(proxy)?;
        entry.ensure_active()?;
        let generation = entry.proxy.generation();
        let mut mailbox = entry
            .mailbox
            .statuses
            .lock()
            .map_err(|_| FfiFailure::internal())?;
        let index = mailbox
            .iter()
            .rposition(|status| status.generation == generation && status.host == host)
            .ok_or_else(|| {
                FfiFailure::new(
                    HNS_BROWSER_RESULT_NOT_READY,
                    "no matching main-frame status is available",
                )
            })?;
        let queued = mailbox
            .get(index)
            .cloned()
            .ok_or_else(FfiFailure::internal)?;
        let outputs = allocate_outputs(&[
            OutputValue {
                bytes: queued.host.as_bytes(),
                sensitive: false,
            },
            OutputValue {
                bytes: queued.resolution_trace_json.as_bytes(),
                sensitive: true,
            },
        ])?;
        if outputs.len() != 2 {
            release_allocated_outputs(&outputs);
            return Err(FfiFailure::internal());
        }
        if mailbox.remove(index).is_none() {
            release_allocated_outputs(&outputs);
            return Err(FfiFailure::internal());
        }
        // Never make an older status for the same committed identity visible
        // after consuming its latest value.
        mailbox.retain(|status| !(status.generation == generation && status.host == host));
        let status = HnsBrowserProxyStatus {
            struct_size: size_u32::<HnsBrowserProxyStatus>(),
            tls_policy: queued.tls_policy,
            resolver_policy: queued.resolver_policy,
            security_path: queued.security_path,
            generation: queued.generation,
            http_status: u32::from(queued.http_status),
            reserved0: 0,
            host: outputs[0],
            resolution_trace_json: outputs[1],
        };
        // SAFETY: Null was rejected above and the C contract requires writable output.
        unsafe { write_output(out_status, status) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn hns_browser_proxy_request_stop(proxy: HnsBrowserProxyHandle) -> HnsBrowserResult {
    ffi_call(|| {
        let entry = proxy_entry(proxy)?;
        entry.request_stop();
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn hns_browser_proxy_destroy(proxy: HnsBrowserProxyHandle) -> HnsBrowserResult {
    ffi_call(|| {
        let entry = handle_registry()
            .lock()
            .map_err(|_| FfiFailure::internal())?
            .proxies
            .remove(&proxy)
            .ok_or_else(|| {
                FfiFailure::new(
                    HNS_BROWSER_RESULT_NOT_FOUND,
                    "proxy handle is invalid or stale",
                )
            })?;
        entry.blocking_stop();
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::mem::{align_of, offset_of, size_of};
    use std::sync::{Barrier, MutexGuard, OnceLock};
    use std::thread;

    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(1);

    fn test_guard() -> MutexGuard<'static, ()> {
        match TEST_LOCK.get_or_init(|| Mutex::new(())).lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn ffi_slice(bytes: &[u8]) -> HnsBrowserSlice {
        HnsBrowserSlice {
            ptr: bytes.as_ptr(),
            len: bytes.len() as u64,
        }
    }

    fn null_slice() -> HnsBrowserSlice {
        HnsBrowserSlice::empty()
    }

    fn owned_bytes(buffer: HnsBrowserBuffer) -> Vec<u8> {
        if buffer.len == 0 {
            return Vec::new();
        }
        assert!(!buffer.ptr.is_null());
        // SAFETY: Test reads a live buffer returned by this crate before free.
        unsafe { std::slice::from_raw_parts(buffer.ptr, buffer.len as usize) }.to_vec()
    }

    fn owned_string(buffer: HnsBrowserBuffer) -> String {
        String::from_utf8(owned_bytes(buffer)).expect("ABI output must be UTF-8")
    }

    fn unique_data_dir(label: &str) -> String {
        let id = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!(
                "hns-browser-ios-ffi-{label}-{}-{id}",
                std::process::id()
            ))
            .to_string_lossy()
            .into_owned()
    }

    fn create_runtime(data_dir: &str) -> HnsBrowserRuntimeHandle {
        let mut options = HnsBrowserRuntimeOptions::defaults();
        options.network = HNS_BROWSER_NETWORK_REGTEST;
        options.data_dir = ffi_slice(data_dir.as_bytes());
        let mut runtime = 0;
        // SAFETY: All pointers and borrowed slices are valid for this call.
        let result = unsafe { hns_browser_runtime_create(&options, &mut runtime) };
        assert_eq!(result, HNS_BROWSER_RESULT_OK);
        assert_ne!(runtime, 0);
        runtime
    }

    fn start_icann_proxy(runtime: HnsBrowserRuntimeHandle) -> HnsBrowserProxyHandle {
        let mut proxy = 0;
        // SAFETY: Output is writable and the null slice is the documented ICANN mode.
        let result = unsafe { hns_browser_proxy_start(runtime, null_slice(), &mut proxy) };
        assert_eq!(result, HNS_BROWSER_RESULT_OK);
        assert_ne!(proxy, 0);
        proxy
    }

    fn cleanup_dir(data_dir: &str) {
        let _ = fs::remove_dir_all(data_dir);
    }

    #[test]
    fn abi_layout_and_header_symbols_are_stable() {
        let _guard = test_guard();
        assert_eq!(size_of::<HnsBrowserSlice>(), 16);
        assert_eq!(align_of::<HnsBrowserSlice>(), 8);
        assert_eq!(offset_of!(HnsBrowserSlice, ptr), 0);
        assert_eq!(offset_of!(HnsBrowserSlice, len), 8);
        assert_eq!(size_of::<HnsBrowserBuffer>(), 24);
        assert_eq!(offset_of!(HnsBrowserBuffer, allocation_id), 16);
        assert_eq!(size_of::<HnsBrowserRuntimeOptions>(), 80);
        assert_eq!(offset_of!(HnsBrowserRuntimeOptions, data_dir), 8);
        assert_eq!(offset_of!(HnsBrowserRuntimeOptions, hns_doh_resolver), 48);
        assert_eq!(size_of::<HnsBrowserPolicy>(), 40);
        assert_eq!(size_of::<HnsBrowserProxyEndpoint>(), 112);
        assert_eq!(offset_of!(HnsBrowserProxyEndpoint, generation), 8);
        assert_eq!(offset_of!(HnsBrowserProxyEndpoint, session_id), 16);
        assert_eq!(size_of::<HnsBrowserProxyStatus>(), 80);
        assert_eq!(offset_of!(HnsBrowserProxyStatus, generation), 16);
        assert_eq!(offset_of!(HnsBrowserProxyStatus, host), 32);

        let header = include_str!("../include/hns_browser.h");
        let source = include_str!("lib.rs");
        let symbols = [
            "hns_browser_abi_version",
            "hns_browser_core_version",
            "hns_browser_diagnostics_json",
            "hns_browser_last_error",
            "hns_browser_buffer_free",
            "hns_browser_runtime_options_default",
            "hns_browser_policy_default",
            "hns_browser_runtime_create",
            "hns_browser_runtime_destroy",
            "hns_browser_runtime_set_policy",
            "hns_browser_runtime_sync_once",
            "hns_browser_runtime_sync_status",
            "hns_browser_runtime_clear_resolver_cache",
            "hns_browser_runtime_install_header_snapshot",
            "hns_browser_runtime_reset_headers_from_peers",
            "hns_browser_runtime_proof_details",
            "hns_browser_classify_name",
            "hns_browser_canonical_host",
            "hns_browser_hns_root",
            "hns_browser_proxy_start",
            "hns_browser_proxy_endpoint",
            "hns_browser_proxy_matches_instance",
            "hns_browser_proxy_matches_authentication_challenge",
            "hns_browser_proxy_matches_local_certificate",
            "hns_browser_proxy_take_main_frame_status",
            "hns_browser_proxy_request_stop",
            "hns_browser_proxy_destroy",
        ];
        for symbol in symbols {
            assert!(header.contains(&format!("{symbol}(")), "header: {symbol}");
            assert!(
                source.contains(&format!("fn {symbol}(")),
                "source: {symbol}"
            );
        }
        assert!(header.contains("#ifndef HNS_BROWSER_H"));
        assert!(header.contains("extern \"C\""));
        assert!(!header.contains("hns_browser_proxy_matches_authentication("));
    }

    #[test]
    fn owned_buffers_reject_foreign_mismatched_and_double_free() {
        let _guard = test_guard();
        let mut version = HnsBrowserBuffer::empty();
        // SAFETY: Output points to one writable buffer descriptor.
        assert_eq!(
            unsafe { hns_browser_core_version(&mut version) },
            HNS_BROWSER_RESULT_OK
        );
        assert!(owned_string(version).starts_with("hns-dane-browser-rust-core/"));

        let mismatched = HnsBrowserBuffer {
            ptr: ptr::without_provenance_mut::<u8>(1),
            ..version
        };
        assert_eq!(
            hns_browser_buffer_free(mismatched),
            HNS_BROWSER_RESULT_BUFFER_ERROR
        );
        assert_eq!(hns_browser_buffer_free(version), HNS_BROWSER_RESULT_OK);
        assert_eq!(
            hns_browser_buffer_free(version),
            HNS_BROWSER_RESULT_BUFFER_ERROR
        );
        assert_eq!(
            hns_browser_buffer_free(HnsBrowserBuffer::empty()),
            HNS_BROWSER_RESULT_OK
        );
        let foreign = HnsBrowserBuffer {
            ptr: ptr::without_provenance_mut::<u8>(7),
            len: 12,
            allocation_id: u64::MAX,
        };
        assert_eq!(
            hns_browser_buffer_free(foreign),
            HNS_BROWSER_RESULT_BUFFER_ERROR
        );
    }

    #[test]
    fn input_and_error_boundaries_are_bounded_and_utf8_checked() {
        let _guard = test_guard();
        let mut class = u32::MAX;
        let null_nonempty = HnsBrowserSlice {
            ptr: ptr::null(),
            len: 1,
        };
        // SAFETY: This deliberately exercises the documented null rejection path.
        assert_eq!(
            unsafe { hns_browser_classify_name(null_nonempty, &mut class) },
            HNS_BROWSER_RESULT_INVALID_ARGUMENT
        );
        let mut error = HnsBrowserBuffer::empty();
        // SAFETY: Output points to one writable buffer descriptor.
        assert_eq!(
            unsafe { hns_browser_last_error(&mut error) },
            HNS_BROWSER_RESULT_OK
        );
        let error_text = owned_string(error);
        assert!(!error_text.is_empty());
        assert!(error_text.len() <= MAX_ERROR_BYTES);
        assert_eq!(hns_browser_buffer_free(error), HNS_BROWSER_RESULT_OK);

        let oversized = HnsBrowserSlice {
            ptr: ptr::without_provenance::<u8>(1),
            len: (MAX_NAME_INPUT_BYTES as u64) + 1,
        };
        // SAFETY: Length is rejected before the intentionally invalid pointer is read.
        assert_eq!(
            unsafe { hns_browser_classify_name(oversized, &mut class) },
            HNS_BROWSER_RESULT_INVALID_ARGUMENT
        );
        let invalid_utf8 = [0xff, 0xfe];
        // SAFETY: The borrowed byte slice is readable for this call.
        assert_eq!(
            unsafe { hns_browser_classify_name(ffi_slice(&invalid_utf8), &mut class) },
            HNS_BROWSER_RESULT_INVALID_UTF8
        );

        set_last_error(&"é".repeat(MAX_ERROR_BYTES));
        let bounded = last_error_snapshot();
        assert!(bounded.len() <= MAX_ERROR_BYTES);
        assert!(std::str::from_utf8(bounded.as_bytes()).is_ok());
        assert_eq!(
            ffi_call(|| -> Result<(), FfiFailure> { panic!("contained test panic") }),
            HNS_BROWSER_RESULT_PANIC
        );
    }

    #[test]
    fn shared_name_classification_and_hns_root_are_exposed() {
        let _guard = test_guard();
        let mut class = u32::MAX;
        // SAFETY: Inputs and output are valid for each call.
        assert_eq!(
            unsafe { hns_browser_classify_name(ffi_slice(b"welcome."), &mut class) },
            HNS_BROWSER_RESULT_OK
        );
        assert_eq!(class, HNS_BROWSER_NAME_HNS);
        let mut canonical = HnsBrowserBuffer::empty();
        // SAFETY: Input and output are valid for this call.
        assert_eq!(
            unsafe { hns_browser_canonical_host(ffi_slice(b"WWW.WELCOME."), &mut canonical) },
            HNS_BROWSER_RESULT_OK
        );
        assert_eq!(owned_string(canonical), "www.welcome");
        assert_eq!(hns_browser_buffer_free(canonical), HNS_BROWSER_RESULT_OK);
        // SAFETY: Input and output are valid for this call.
        assert_eq!(
            unsafe { hns_browser_canonical_host(ffi_slice(b"127.0.0.1"), &mut canonical) },
            HNS_BROWSER_RESULT_OK
        );
        assert_eq!(owned_string(canonical), "127.0.0.1");
        assert_eq!(hns_browser_buffer_free(canonical), HNS_BROWSER_RESULT_OK);
        // SAFETY: Input and output are valid for this call.
        assert_eq!(
            unsafe { hns_browser_canonical_host(ffi_slice(b"[2001:0db8::1]"), &mut canonical) },
            HNS_BROWSER_RESULT_OK
        );
        assert_eq!(owned_string(canonical), "2001:db8::1");
        assert_eq!(hns_browser_buffer_free(canonical), HNS_BROWSER_RESULT_OK);
        // SAFETY: Input and output are valid for this call.
        assert_eq!(
            unsafe { hns_browser_canonical_host(ffi_slice(b"127.1"), &mut canonical) },
            HNS_BROWSER_RESULT_NOT_FOUND
        );
        let mut root = HnsBrowserBuffer::empty();
        // SAFETY: Input and output are valid for this call.
        assert_eq!(
            unsafe { hns_browser_hns_root(ffi_slice(b"sub.welcome."), &mut root) },
            HNS_BROWSER_RESULT_OK
        );
        assert_eq!(owned_string(root), "welcome");
        assert_eq!(hns_browser_buffer_free(root), HNS_BROWSER_RESULT_OK);

        // SAFETY: Inputs and output are valid for each call.
        assert_eq!(
            unsafe { hns_browser_classify_name(ffi_slice(b"example.com"), &mut class) },
            HNS_BROWSER_RESULT_OK
        );
        assert_eq!(class, HNS_BROWSER_NAME_ICANN);
        // SAFETY: Input and output are valid for this call.
        assert_eq!(
            unsafe { hns_browser_hns_root(ffi_slice(b"example.com"), &mut root) },
            HNS_BROWSER_RESULT_NOT_FOUND
        );
        // SAFETY: Inputs and output are valid for each call.
        assert_eq!(
            unsafe { hns_browser_classify_name(ffi_slice(b"two words"), &mut class) },
            HNS_BROWSER_RESULT_OK
        );
        assert_eq!(class, HNS_BROWSER_NAME_SEARCH);
    }

    #[test]
    fn runtime_handles_are_monotonic_typed_and_stale_safe() {
        let _guard = test_guard();
        let first_dir = unique_data_dir("runtime-first");
        let first = create_runtime(&first_dir);
        assert_eq!(hns_browser_runtime_destroy(first), HNS_BROWSER_RESULT_OK);
        assert_eq!(
            hns_browser_runtime_destroy(first),
            HNS_BROWSER_RESULT_NOT_FOUND
        );
        let second_dir = unique_data_dir("runtime-second");
        let second = create_runtime(&second_dir);
        assert!(second > first);
        assert_eq!(
            hns_browser_proxy_destroy(second),
            HNS_BROWSER_RESULT_NOT_FOUND
        );
        assert_eq!(hns_browser_runtime_destroy(second), HNS_BROWSER_RESULT_OK);
        cleanup_dir(&first_dir);
        cleanup_dir(&second_dir);
    }

    #[test]
    fn proxy_challenge_lifecycle_and_owned_endpoint_fail_closed() {
        let _guard = test_guard();
        let data_dir = unique_data_dir("proxy-lifecycle");
        let runtime = create_runtime(&data_dir);

        let nonnull_empty = HnsBrowserSlice {
            ptr: b"".as_ptr(),
            len: 0,
        };
        let mut rejected_proxy = 99;
        // SAFETY: Output is writable; the ambiguous slice is rejected before reading.
        assert_eq!(
            unsafe { hns_browser_proxy_start(runtime, nonnull_empty, &mut rejected_proxy) },
            HNS_BROWSER_RESULT_INVALID_ARGUMENT
        );
        assert_eq!(rejected_proxy, 0);

        let proxy = start_icann_proxy(runtime);
        assert_ne!(proxy, runtime);
        let mut endpoint = HnsBrowserProxyEndpoint::empty();
        // SAFETY: Output points to one writable endpoint descriptor.
        assert_eq!(
            unsafe { hns_browser_proxy_endpoint(proxy, &mut endpoint) },
            HNS_BROWSER_RESULT_OK
        );
        assert_ne!(endpoint.port, 0);
        let session = owned_bytes(endpoint.session_id);
        let realm = owned_bytes(endpoint.realm);
        assert!(!owned_bytes(endpoint.username).is_empty());
        assert!(!owned_bytes(endpoint.password).is_empty());

        let mut matches = 0;
        // SAFETY: All borrowed slices and output are valid for this call.
        assert_eq!(
            unsafe {
                hns_browser_proxy_matches_authentication_challenge(
                    proxy,
                    ffi_slice(b"127.0.0.1"),
                    endpoint.port,
                    ffi_slice(&realm),
                    &mut matches,
                )
            },
            HNS_BROWSER_RESULT_OK
        );
        assert_eq!(matches, 1);
        // SAFETY: All borrowed slices and output are valid for this call.
        assert_eq!(
            unsafe {
                hns_browser_proxy_matches_authentication_challenge(
                    proxy,
                    ffi_slice(b"localhost"),
                    endpoint.port,
                    ffi_slice(&realm),
                    &mut matches,
                )
            },
            HNS_BROWSER_RESULT_OK
        );
        assert_eq!(matches, 0);
        // SAFETY: All borrowed slices and output are valid for this call.
        assert_eq!(
            unsafe {
                hns_browser_proxy_matches_instance(
                    proxy,
                    ffi_slice(&session),
                    endpoint.generation,
                    &mut matches,
                )
            },
            HNS_BROWSER_RESULT_OK
        );
        assert_eq!(matches, 1);

        for buffer in [
            endpoint.session_id,
            endpoint.realm,
            endpoint.username,
            endpoint.password,
        ] {
            assert_eq!(hns_browser_buffer_free(buffer), HNS_BROWSER_RESULT_OK);
        }
        assert_eq!(hns_browser_proxy_request_stop(proxy), HNS_BROWSER_RESULT_OK);
        // SAFETY: Output points to one writable endpoint descriptor.
        assert_eq!(
            unsafe { hns_browser_proxy_endpoint(proxy, &mut endpoint) },
            HNS_BROWSER_RESULT_NOT_FOUND
        );
        // SAFETY: All borrowed slices and output are valid for this call.
        assert_eq!(
            unsafe {
                hns_browser_proxy_matches_authentication_challenge(
                    proxy,
                    ffi_slice(b"127.0.0.1"),
                    1,
                    ffi_slice(&realm),
                    &mut matches,
                )
            },
            HNS_BROWSER_RESULT_NOT_FOUND
        );
        // SAFETY: All borrowed slices and output are valid for this call.
        assert_eq!(
            unsafe {
                hns_browser_proxy_matches_local_certificate(
                    proxy,
                    ffi_slice(b"welcome"),
                    ffi_slice(&[1, 2, 3]),
                    &mut matches,
                )
            },
            HNS_BROWSER_RESULT_NOT_FOUND
        );
        assert_eq!(hns_browser_proxy_destroy(proxy), HNS_BROWSER_RESULT_OK);
        assert_eq!(
            hns_browser_proxy_destroy(proxy),
            HNS_BROWSER_RESULT_NOT_FOUND
        );
        assert_eq!(hns_browser_runtime_destroy(runtime), HNS_BROWSER_RESULT_OK);
        cleanup_dir(&data_dir);
    }

    #[test]
    fn one_active_proxy_per_runtime_and_runtime_destroy_owns_teardown() {
        let _guard = test_guard();
        let data_dir = unique_data_dir("proxy-owner");
        let runtime = create_runtime(&data_dir);
        let barrier = Arc::new(Barrier::new(3));
        let starts = (0..2)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    let mut proxy = 0;
                    // SAFETY: Output is thread-local and null scope is valid ICANN mode.
                    let result =
                        unsafe { hns_browser_proxy_start(runtime, null_slice(), &mut proxy) };
                    (result, proxy)
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let outcomes = starts
            .into_iter()
            .map(|start| start.join().expect("proxy start thread"))
            .collect::<Vec<_>>();
        let successful = outcomes
            .iter()
            .filter(|(result, _)| *result == HNS_BROWSER_RESULT_OK)
            .collect::<Vec<_>>();
        assert_eq!(successful.len(), 1);
        assert!(
            outcomes.iter().any(|(result, proxy)| {
                *result == HNS_BROWSER_RESULT_PROXY_ERROR && *proxy == 0
            })
        );
        let proxy = successful[0].1;
        assert_eq!(hns_browser_runtime_destroy(runtime), HNS_BROWSER_RESULT_OK);
        assert_eq!(
            hns_browser_proxy_destroy(proxy),
            HNS_BROWSER_RESULT_NOT_FOUND
        );
        cleanup_dir(&data_dir);
    }

    #[test]
    fn policy_change_revokes_published_proxy_before_returning() {
        let _guard = test_guard();
        let data_dir = unique_data_dir("policy-revoke");
        let runtime = create_runtime(&data_dir);
        let proxy = start_icann_proxy(runtime);
        let policy = HnsBrowserPolicy::defaults();
        let mut revision = 0;
        // SAFETY: Policy and output pointers are valid for this call.
        assert_eq!(
            unsafe { hns_browser_runtime_set_policy(runtime, &policy, &mut revision) },
            HNS_BROWSER_RESULT_OK
        );
        assert_eq!(revision, 1);
        let mut endpoint = HnsBrowserProxyEndpoint::empty();
        // SAFETY: Output points to one writable endpoint descriptor.
        assert_eq!(
            unsafe { hns_browser_proxy_endpoint(proxy, &mut endpoint) },
            HNS_BROWSER_RESULT_NOT_FOUND
        );
        assert_eq!(hns_browser_proxy_destroy(proxy), HNS_BROWSER_RESULT_OK);
        assert_eq!(hns_browser_runtime_destroy(runtime), HNS_BROWSER_RESULT_OK);
        cleanup_dir(&data_dir);
    }

    #[test]
    fn concurrent_policy_and_proxy_publication_never_leave_old_revision_active() {
        let _guard = test_guard();
        let data_dir = unique_data_dir("policy-start-race");
        let runtime = create_runtime(&data_dir);
        for _ in 0..12 {
            let barrier = Arc::new(Barrier::new(3));
            let start_barrier = Arc::clone(&barrier);
            let start = thread::spawn(move || {
                start_barrier.wait();
                let mut proxy = 0;
                // SAFETY: Output is thread-local and null scope is valid ICANN mode.
                let result = unsafe { hns_browser_proxy_start(runtime, null_slice(), &mut proxy) };
                (result, proxy)
            });
            let policy_barrier = Arc::clone(&barrier);
            let update = thread::spawn(move || {
                let policy = HnsBrowserPolicy::defaults();
                let mut revision = 0;
                policy_barrier.wait();
                // SAFETY: Policy and output live for the complete call.
                let result =
                    unsafe { hns_browser_runtime_set_policy(runtime, &policy, &mut revision) };
                (result, revision)
            });
            barrier.wait();
            let (start_result, proxy) = start.join().expect("proxy start thread");
            let (update_result, revision) = update.join().expect("policy update thread");
            assert_eq!(update_result, HNS_BROWSER_RESULT_OK);
            assert_ne!(revision, 0);
            assert!(matches!(
                start_result,
                HNS_BROWSER_RESULT_OK | HNS_BROWSER_RESULT_PROXY_ERROR
            ));
            if start_result == HNS_BROWSER_RESULT_OK {
                let entry = match proxy_entry(proxy) {
                    Ok(entry) => entry,
                    Err(_) => panic!("published proxy handle must remain registered"),
                };
                if entry.active.load(Ordering::Acquire) {
                    assert_eq!(entry.policy_revision, revision);
                }
                assert_eq!(hns_browser_proxy_destroy(proxy), HNS_BROWSER_RESULT_OK);
            } else {
                assert_eq!(proxy, 0);
            }
        }
        assert_eq!(hns_browser_runtime_destroy(runtime), HNS_BROWSER_RESULT_OK);
        cleanup_dir(&data_dir);
    }

    #[test]
    fn status_take_is_exact_latest_and_host_isolated() {
        let _guard = test_guard();
        let data_dir = unique_data_dir("status-mailbox");
        let runtime = create_runtime(&data_dir);
        let proxy = start_icann_proxy(runtime);
        let entry = match proxy_entry(proxy) {
            Ok(entry) => entry,
            Err(_) => panic!("live proxy entry must exist"),
        };
        let generation = entry.proxy.generation();
        {
            let mut statuses = entry.mailbox.statuses.lock().expect("status mailbox");
            statuses.push_back(QueuedMainFrameStatus {
                generation,
                host: "other.welcome".to_owned(),
                http_status: 201,
                tls_policy: HNS_BROWSER_TLS_POLICY_DANE,
                resolver_policy: HNS_BROWSER_RESOLVER_POLICY_UNKNOWN,
                security_path: HNS_BROWSER_SECURITY_PATH_DANE_AUTHORITATIVE_DOH,
                resolution_trace_json: "{\"other\":true}".to_owned(),
            });
            statuses.push_back(QueuedMainFrameStatus {
                generation,
                host: "www.welcome".to_owned(),
                http_status: 200,
                tls_policy: HNS_BROWSER_TLS_POLICY_DANE,
                resolver_policy: HNS_BROWSER_RESOLVER_POLICY_UNKNOWN,
                security_path: HNS_BROWSER_SECURITY_PATH_DANE_AUTHORITATIVE_DNS53,
                resolution_trace_json: "{\"old\":true}".to_owned(),
            });
            statuses.push_back(QueuedMainFrameStatus {
                generation,
                host: "www.welcome".to_owned(),
                http_status: 204,
                tls_policy: HNS_BROWSER_TLS_POLICY_WEBPKI_FALLBACK,
                resolver_policy: HNS_BROWSER_RESOLVER_POLICY_HNS_DOH_COMPATIBILITY,
                security_path: HNS_BROWSER_SECURITY_PATH_HNS_THIRD_PARTY_DOH,
                resolution_trace_json: "{\"latest\":true}".to_owned(),
            });
        }
        let mut status = HnsBrowserProxyStatus::empty();
        // SAFETY: Host slice and output are valid for this call.
        assert_eq!(
            unsafe {
                hns_browser_proxy_take_main_frame_status(
                    proxy,
                    ffi_slice(b"www.welcome"),
                    &mut status,
                )
            },
            HNS_BROWSER_RESULT_OK
        );
        assert_eq!(status.generation, generation);
        assert_eq!(status.http_status, 204);
        assert_eq!(status.tls_policy, HNS_BROWSER_TLS_POLICY_WEBPKI_FALLBACK);
        assert_eq!(owned_string(status.host), "www.welcome");
        assert_eq!(
            owned_string(status.resolution_trace_json),
            "{\"latest\":true}"
        );
        assert_eq!(hns_browser_buffer_free(status.host), HNS_BROWSER_RESULT_OK);
        assert_eq!(
            hns_browser_buffer_free(status.resolution_trace_json),
            HNS_BROWSER_RESULT_OK
        );

        // SAFETY: Host slice and output are valid for this call.
        assert_eq!(
            unsafe {
                hns_browser_proxy_take_main_frame_status(
                    proxy,
                    ffi_slice(b"other.welcome"),
                    &mut status,
                )
            },
            HNS_BROWSER_RESULT_OK
        );
        assert_eq!(status.http_status, 201);
        assert_eq!(hns_browser_buffer_free(status.host), HNS_BROWSER_RESULT_OK);
        assert_eq!(
            hns_browser_buffer_free(status.resolution_trace_json),
            HNS_BROWSER_RESULT_OK
        );

        assert_eq!(hns_browser_proxy_request_stop(proxy), HNS_BROWSER_RESULT_OK);
        // SAFETY: Host slice and output are valid; inactive record must fail closed.
        assert_eq!(
            unsafe {
                hns_browser_proxy_take_main_frame_status(
                    proxy,
                    ffi_slice(b"www.welcome"),
                    &mut status,
                )
            },
            HNS_BROWSER_RESULT_NOT_FOUND
        );
        assert_eq!(hns_browser_proxy_destroy(proxy), HNS_BROWSER_RESULT_OK);
        assert_eq!(hns_browser_runtime_destroy(runtime), HNS_BROWSER_RESULT_OK);
        cleanup_dir(&data_dir);
    }
}
