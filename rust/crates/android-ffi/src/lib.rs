//! Android JNI adapter for the platform-neutral browser runtime.

#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use hns_browser_runtime::*;
use jni::JNIEnv;
use jni::JavaVM;
use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring};
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

const TUNNEL_COPY_BUFFER_BYTES: usize = 16 * 1024;
const MAX_LOCAL_CERTIFICATE_DER_BYTES: usize = 64 * 1024;
const PROXY_ENDPOINT_BUNDLE_MAGIC: &[u8; 4] = b"HNSP";
const PROXY_ENDPOINT_BUNDLE_VERSION: u8 = 1;
static NEXT_PROXY_HANDLE: AtomicU64 = AtomicU64::new(1);
static PROXY_HANDLES: OnceLock<Mutex<HashMap<jlong, Arc<BrowserProxy>>>> = OnceLock::new();

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
    let runtime = handle as usize as *const BrowserRuntime;
    // SAFETY: handles are created from Box<BrowserRuntime> below. Platform callers serialize
    // destroy against calls, and cloning only retains the Arc-backed runtime inner state.
    unsafe { runtime.as_ref().cloned() }
}

fn proxy_registry() -> &'static Mutex<HashMap<jlong, Arc<BrowserProxy>>> {
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

fn register_proxy(proxy: BrowserProxy) -> Option<(jlong, Arc<BrowserProxy>)> {
    let handle = next_proxy_handle()?;
    let proxy = Arc::new(proxy);
    let mut registry = proxy_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match registry.entry(handle) {
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(Arc::clone(&proxy));
        }
        std::collections::hash_map::Entry::Occupied(_) => return None,
    }
    Some((handle, proxy))
}

fn proxy_from_handle(handle: jlong) -> Option<Arc<BrowserProxy>> {
    if handle <= 0 {
        return None;
    }
    proxy_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&handle)
        .cloned()
}

fn remove_proxy(handle: jlong) -> Option<Arc<BrowserProxy>> {
    if handle <= 0 {
        return None;
    }
    proxy_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&handle)
}

fn destroy_proxy(handle: jlong) -> bool {
    let Some(proxy) = proxy_from_handle(handle) else {
        return false;
    };
    proxy.request_stop();
    let Some(proxy) = remove_proxy(handle) else {
        return false;
    };
    proxy.stop();
    true
}

fn destroy_all_proxies() {
    let proxies: Vec<_> = proxy_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .drain()
        .map(|(_, proxy)| proxy)
        .collect();
    for proxy in &proxies {
        proxy.request_stop();
    }
    for proxy in proxies {
        proxy.stop();
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

struct JniGatewayHttpRequest<'local> {
    data_dir: JString<'local>,
    method: JString<'local>,
    scheme: JString<'local>,
    host: JString<'local>,
    port: jint,
    path_and_query: JString<'local>,
    header_text: JString<'local>,
    body: JByteArray<'local>,
}

struct JavaInputStream {
    vm: Arc<JavaVM>,
    stream: GlobalRef,
}

struct JavaOutputStream {
    vm: Arc<JavaVM>,
    stream: GlobalRef,
}

impl JavaInputStream {
    fn new(vm: Arc<JavaVM>, stream: GlobalRef) -> Self {
        Self { vm, stream }
    }
}

impl JavaOutputStream {
    fn new(vm: Arc<JavaVM>, stream: GlobalRef) -> Self {
        Self { vm, stream }
    }
}

fn checked_java_read_len(
    read: jint,
    requested: usize,
    returned_bytes: usize,
) -> std::io::Result<usize> {
    let read = usize::try_from(read)
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidData, "negative Java read length"))?;
    if read > requested || read > returned_bytes {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "Java InputStream returned an invalid byte count",
        ));
    }
    Ok(read)
}

impl Read for JavaInputStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let length = buf.len().min(TUNNEL_COPY_BUFFER_BYTES);
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let array = env
            .new_byte_array(length as i32)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let array_object = JObject::from(array);
        let read = env
            .call_method(
                self.stream.as_obj(),
                "read",
                "([B)I",
                &[JValue::Object(&array_object)],
            )
            .and_then(|value| value.i())
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        if read < 0 {
            return Ok(0);
        }
        let array = JByteArray::from(array_object);
        let bytes = env
            .convert_byte_array(&array)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let read = checked_java_read_len(read, length, bytes.len())?;
        buf[..read].copy_from_slice(&bytes[..read]);
        Ok(read)
    }
}

impl Write for JavaOutputStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let length = buf.len().min(TUNNEL_COPY_BUFFER_BYTES);
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let array = env
            .byte_array_from_slice(&buf[..length])
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let array_object = JObject::from(array);
        env.call_method(
            self.stream.as_obj(),
            "write",
            "([BII)V",
            &[
                JValue::Object(&array_object),
                JValue::Int(0),
                JValue::Int(length as i32),
            ],
        )
        .map_err(|error| std::io::Error::other(error.to_string()))?;
        Ok(length)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        env.call_method(self.stream.as_obj(), "flush", "()V", &[])
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        Ok(())
    }
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

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeGatewayHttpResponse(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    data_dir: JString<'_>,
    method: JString<'_>,
    scheme: JString<'_>,
    host: JString<'_>,
    port: jint,
    path_and_query: JString<'_>,
    header_text: JString<'_>,
    body: JByteArray<'_>,
) -> jbyteArray {
    let response = jni_gateway_http_response(
        &mut env,
        JniGatewayHttpRequest {
            data_dir,
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
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeGatewayHttpResponseBodyToFile(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    data_dir: JString<'_>,
    method: JString<'_>,
    scheme: JString<'_>,
    host: JString<'_>,
    port: jint,
    path_and_query: JString<'_>,
    header_text: JString<'_>,
    body: JByteArray<'_>,
    body_path: JString<'_>,
) -> jbyteArray {
    let response = jni_gateway_http_response_body_to_file(
        &mut env,
        JniGatewayHttpRequest {
            data_dir,
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
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeGatewayHttpUpgradeTunnel(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    data_dir: JString<'_>,
    method: JString<'_>,
    scheme: JString<'_>,
    host: JString<'_>,
    port: jint,
    path_and_query: JString<'_>,
    header_text: JString<'_>,
    client_input: JObject<'_>,
    client_output: JObject<'_>,
) -> jboolean {
    if jni_gateway_http_upgrade_tunnel(
        &mut env,
        data_dir,
        method,
        scheme,
        host,
        port,
        path_and_query,
        header_text,
        client_input,
        client_output,
    ) {
        1
    } else {
        0
    }
}

fn jni_gateway_http_response(
    env: &mut JNIEnv<'_>,
    input: JniGatewayHttpRequest<'_>,
) -> Option<Vec<u8>> {
    let data_dir = env
        .get_string(&input.data_dir)
        .ok()?
        .to_string_lossy()
        .into_owned();
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
    let body_len = usize::try_from(env.get_array_length(&input.body).ok()?).ok()?;
    if body_len > DEFAULT_MAX_REQUEST_BODY_BYTES {
        return Some(plain_response_with_address(
            413,
            "Origin Request Too Large",
            "Origin request body exceeds the configured gateway limit.",
            None,
        ));
    }
    let body = env.convert_byte_array(&input.body).ok()?;
    let port = u16::try_from(input.port).ok()?;
    Some(gateway_http_response(GatewayHttpRequestInput {
        data_dir: &data_dir,
        method: &method,
        scheme: &scheme,
        host: &host,
        port,
        path_and_query: &path_and_query,
        header_text: &header_text,
        body: &body,
    }))
}

fn jni_gateway_http_response_body_to_file(
    env: &mut JNIEnv<'_>,
    input: JniGatewayHttpRequest<'_>,
    body_path: JString<'_>,
) -> Option<Vec<u8>> {
    let data_dir = env
        .get_string(&input.data_dir)
        .ok()?
        .to_string_lossy()
        .into_owned();
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
    let output_path = env
        .get_string(&body_path)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let body_len = usize::try_from(env.get_array_length(&input.body).ok()?).ok()?;
    if body_len > DEFAULT_MAX_REQUEST_BODY_BYTES {
        return plain_response_to_file_with_address(
            413,
            "Origin Request Too Large",
            "Origin request body exceeds the configured gateway limit.",
            None,
            Path::new(&output_path),
        )
        .ok();
    }
    let body = env.convert_byte_array(&input.body).ok()?;
    let port = u16::try_from(input.port).ok()?;
    gateway_http_response_body_to_file(
        GatewayHttpRequestInput {
            data_dir: &data_dir,
            method: &method,
            scheme: &scheme,
            host: &host,
            port,
            path_and_query: &path_and_query,
            header_text: &header_text,
            body: &body,
        },
        Path::new(&output_path),
    )
    .ok()
}

#[allow(clippy::too_many_arguments)]
fn jni_gateway_http_upgrade_tunnel(
    env: &mut JNIEnv<'_>,
    data_dir: JString<'_>,
    method: JString<'_>,
    scheme: JString<'_>,
    host: JString<'_>,
    port: jint,
    path_and_query: JString<'_>,
    header_text: JString<'_>,
    client_input: JObject<'_>,
    client_output: JObject<'_>,
) -> bool {
    let data_dir = match env.get_string(&data_dir) {
        Ok(value) => value.to_string_lossy().into_owned(),
        Err(_) => return false,
    };
    let method = match env.get_string(&method) {
        Ok(value) => value.to_string_lossy().into_owned(),
        Err(_) => return false,
    };
    let scheme = match env.get_string(&scheme) {
        Ok(value) => value.to_string_lossy().into_owned(),
        Err(_) => return false,
    };
    let host = match env.get_string(&host) {
        Ok(value) => value.to_string_lossy().into_owned(),
        Err(_) => return false,
    };
    let path_and_query = match env.get_string(&path_and_query) {
        Ok(value) => value.to_string_lossy().into_owned(),
        Err(_) => return false,
    };
    let header_text = match env.get_string(&header_text) {
        Ok(value) => value.to_string_lossy().into_owned(),
        Err(_) => return false,
    };
    let port = match u16::try_from(port) {
        Ok(port) => port,
        Err(_) => return false,
    };
    let vm = match env.get_java_vm() {
        Ok(vm) => Arc::new(vm),
        Err(_) => return false,
    };
    let client_input = match env.new_global_ref(&client_input) {
        Ok(stream) => stream,
        Err(_) => return false,
    };
    let client_output = match env.new_global_ref(&client_output) {
        Ok(stream) => stream,
        Err(_) => return false,
    };

    gateway_http_upgrade_tunnel(
        GatewayHttpRequestInput {
            data_dir: &data_dir,
            method: &method,
            scheme: &scheme,
            host: &host,
            port,
            path_and_query: &path_and_query,
            header_text: &header_text,
            body: &[],
        },
        JavaInputStream::new(Arc::clone(&vm), client_input),
        JavaOutputStream::new(vm, client_output),
    )
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
    Box::into_raw(Box::new(runtime)) as usize as jlong
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
    let runtime = handle as usize as *mut BrowserRuntime;
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

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeRuntimeSetPolicy(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    strict_hns_mode: jboolean,
    doh_resolver_url: JString<'_>,
    stateless_dane_certificates: jboolean,
) -> jlong {
    let Some(runtime) = runtime_from_handle(handle) else {
        return 0;
    };
    let Ok(doh_resolver_url) = env.get_string(&doh_resolver_url) else {
        return 0;
    };
    let doh_resolver_url = doh_resolver_url.to_string_lossy();
    let doh_resolver_url = doh_resolver_url.trim();
    let policy = RuntimePolicy {
        resolution_mode: if strict_hns_mode == 0 {
            ResolutionMode::Compatibility
        } else {
            ResolutionMode::Strict
        },
        hns_doh_resolver: (!doh_resolver_url.is_empty()).then(|| doh_resolver_url.to_owned()),
        stateless_dane_certificates: stateless_dane_certificates != 0,
    };
    runtime
        .set_policy(policy)
        .ok()
        .and_then(|revision| jlong::try_from(revision).ok())
        .filter(|revision| *revision > 0)
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeRuntimeStartProxy(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    scope_root: JString<'_>,
) -> jbyteArray {
    let result = runtime_from_handle(handle)
        .zip(env.get_string(&scope_root).ok())
        .and_then(|(runtime, scope_root)| {
            let scope_root = scope_root.to_string_lossy();
            runtime.start_proxy(&scope_root).ok()
        })
        .and_then(register_proxy);
    let Some((proxy_handle, proxy)) = result else {
        return std::ptr::null_mut();
    };
    let Some(bundle) = proxy_endpoint_bundle(proxy_handle, &proxy) else {
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
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeProxyRequestStop(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    session_id: JString<'_>,
    generation: jlong,
) -> jboolean {
    let Some(proxy) = proxy_from_handle(handle) else {
        return 0;
    };
    let (Ok(session_id), Ok(generation)) = (env.get_string(&session_id), u64::try_from(generation))
    else {
        return 0;
    };
    if !proxy.matches_instance(&session_id.to_string_lossy(), generation) {
        return 0;
    }
    proxy.request_stop();
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
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeProxyMatchesLocalCertificate(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    session_id: JString<'_>,
    generation: jlong,
    host: JString<'_>,
    certificate_der: JByteArray<'_>,
) -> jboolean {
    let Some(proxy) = proxy_from_handle(handle) else {
        return 0;
    };
    let (Ok(session_id), Ok(generation)) = (env.get_string(&session_id), u64::try_from(generation))
    else {
        return 0;
    };
    if !proxy.matches_instance(&session_id.to_string_lossy(), generation) {
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
    if proxy.matches_local_certificate(&host, &certificate_der) {
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

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_denuoweb_hnsdane_net_NativeBridge_nativeLocalTlsCertificate(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    host: JString<'_>,
) -> jbyteArray {
    let bundle = env
        .get_string(&host)
        .ok()
        .and_then(|value| local_tls_certificate_bundle(&value.to_string_lossy()));

    match bundle.and_then(|bytes| env.byte_array_from_slice(&bytes).ok()) {
        Some(array) => array.into_raw(),
        None => std::ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn java_input_stream_rejects_invalid_read_count() {
        assert_eq!(checked_java_read_len(4, 4, 4).unwrap(), 4);
        assert_eq!(
            checked_java_read_len(5, 4, 4).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        assert_eq!(
            checked_java_read_len(-2, 4, 4).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
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
        let handle = Box::into_raw(Box::new(runtime)) as usize as jlong;

        let call_runtime = runtime_from_handle(handle).unwrap();
        // SAFETY: this test owns the unique Box pointer and destroys it exactly once.
        unsafe { drop(Box::from_raw(handle as usize as *mut BrowserRuntime)) };

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
        let (handle, proxy) = register_proxy(proxy).unwrap();

        assert!(handle > 0);
        assert!(proxy_from_handle(handle).is_some());
        proxy.request_stop();
        assert!(!proxy.matches_local_certificate("welcome", b"certificate"));
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
        let (handle, proxy) = register_proxy(proxy).unwrap();

        let bundle = proxy_endpoint_bundle(handle, &proxy).unwrap();
        assert_eq!(&bundle[..4], PROXY_ENDPOINT_BUNDLE_MAGIC);
        assert_eq!(bundle[4], PROXY_ENDPOINT_BUNDLE_VERSION);
        assert_eq!(
            jlong::from_be_bytes(bundle[5..13].try_into().unwrap()),
            handle
        );
        assert_eq!(
            u16::from_be_bytes(bundle[13..15].try_into().unwrap()),
            proxy.port()
        );
        assert_eq!(
            u64::from_be_bytes(bundle[15..23].try_into().unwrap()),
            proxy.generation()
        );
        for value in [
            proxy.session_id(),
            proxy.authorization_realm(),
            proxy.authorization_username(),
            proxy.authorization_password(),
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
}
