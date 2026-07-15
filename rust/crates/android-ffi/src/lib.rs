//! Android JNI adapter for the platform-neutral browser runtime.

#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use hns_browser_runtime::*;
use jni::JNIEnv;
use jni::JavaVM;
use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jbyteArray, jint, jstring};
use std::io::{ErrorKind, Read, Write};
use std::path::Path;
use std::sync::Arc;

const TUNNEL_COPY_BUFFER_BYTES: usize = 16 * 1024;

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
}
