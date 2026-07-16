#ifndef HNS_BROWSER_H
#define HNS_BROWSER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HNS_BROWSER_ABI_VERSION 1u

typedef uint32_t HnsBrowserResult;
#define HNS_BROWSER_RESULT_OK 0u
#define HNS_BROWSER_RESULT_INVALID_ARGUMENT 1u
#define HNS_BROWSER_RESULT_INVALID_UTF8 2u
#define HNS_BROWSER_RESULT_NOT_FOUND 3u
#define HNS_BROWSER_RESULT_RESOURCE_EXHAUSTED 4u
#define HNS_BROWSER_RESULT_RUNTIME_ERROR 5u
#define HNS_BROWSER_RESULT_PROXY_ERROR 6u
#define HNS_BROWSER_RESULT_BUFFER_ERROR 7u
#define HNS_BROWSER_RESULT_PANIC 8u
#define HNS_BROWSER_RESULT_NOT_READY 9u

typedef uint32_t HnsBrowserNetwork;
#define HNS_BROWSER_NETWORK_MAINNET 0u
#define HNS_BROWSER_NETWORK_TESTNET 1u
#define HNS_BROWSER_NETWORK_REGTEST 2u

typedef uint32_t HnsBrowserResolutionMode;
#define HNS_BROWSER_RESOLUTION_COMPATIBILITY 0u
#define HNS_BROWSER_RESOLUTION_STRICT 1u

typedef uint32_t HnsBrowserNameClass;
#define HNS_BROWSER_NAME_HNS 0u
#define HNS_BROWSER_NAME_ICANN 1u
#define HNS_BROWSER_NAME_SEARCH 2u

typedef uint32_t HnsBrowserTlsPolicy;
#define HNS_BROWSER_TLS_POLICY_UNKNOWN 0u
#define HNS_BROWSER_TLS_POLICY_DANE 1u
#define HNS_BROWSER_TLS_POLICY_WEBPKI_FALLBACK 2u

typedef uint32_t HnsBrowserResolverPolicy;
#define HNS_BROWSER_RESOLVER_POLICY_UNKNOWN 0u
#define HNS_BROWSER_RESOLVER_POLICY_HNS_DOH_COMPATIBILITY 1u

typedef uint32_t HnsBrowserSecurityPath;
#define HNS_BROWSER_SECURITY_PATH_UNKNOWN 0u
#define HNS_BROWSER_SECURITY_PATH_DANE_AUTHORITATIVE_DOH 1u
#define HNS_BROWSER_SECURITY_PATH_DANE_AUTHORITATIVE_DNS53 2u
#define HNS_BROWSER_SECURITY_PATH_DANE_THIRD_PARTY_DOH 3u
#define HNS_BROWSER_SECURITY_PATH_STATELESS_DANE 4u
#define HNS_BROWSER_SECURITY_PATH_DANE_ICANN_DOH 5u
#define HNS_BROWSER_SECURITY_PATH_HNS_AUTHORITATIVE_DOH 6u
#define HNS_BROWSER_SECURITY_PATH_HNS_AUTHORITATIVE_DNS53 7u
#define HNS_BROWSER_SECURITY_PATH_HNS_THIRD_PARTY_DOH 8u

typedef uint64_t HnsBrowserRuntimeHandle;
typedef uint64_t HnsBrowserProxyHandle;

/* A borrowed byte slice. A null pointer is valid only when len is zero. */
typedef struct HnsBrowserSlice {
    const uint8_t *ptr;
    uint64_t len;
} HnsBrowserSlice;

/*
 * A Rust-owned byte buffer. Treat all fields as opaque after receipt.
 * Release each non-empty buffer exactly once with hns_browser_buffer_free.
 */
typedef struct HnsBrowserBuffer {
    uint8_t *ptr;
    uint64_t len;
    uint64_t allocation_id;
} HnsBrowserBuffer;

/* Versioned runtime creation options. Initialize with the default function. */
typedef struct HnsBrowserRuntimeOptions {
    uint32_t struct_size;
    HnsBrowserNetwork network;
    HnsBrowserSlice data_dir;
    uint64_t sync_timeout_millis;
    uint64_t resource_cache_limit_bytes;
    HnsBrowserResolutionMode resolution_mode;
    uint8_t seed_peers;
    uint8_t stateless_dane_certificates;
    uint8_t reserved0[2];
    HnsBrowserSlice hns_doh_resolver;
    uint64_t reserved1[2];
} HnsBrowserRuntimeOptions;

/* Versioned live policy. Initialize with the default function. */
typedef struct HnsBrowserPolicy {
    uint32_t struct_size;
    HnsBrowserResolutionMode resolution_mode;
    HnsBrowserSlice hns_doh_resolver;
    uint8_t stateless_dane_certificates;
    uint8_t reserved0[7];
    uint64_t reserved1;
} HnsBrowserPolicy;

/*
 * Credentials are sensitive and intended only for the in-memory WebKit proxy
 * authentication challenge. Do not persist or log them. Release all four
 * buffers with hns_browser_buffer_free.
 */
typedef struct HnsBrowserProxyEndpoint {
    uint32_t struct_size;
    uint16_t port;
    uint16_t reserved0;
    uint64_t generation;
    HnsBrowserBuffer session_id;
    HnsBrowserBuffer realm;
    HnsBrowserBuffer username;
    HnsBrowserBuffer password;
} HnsBrowserProxyEndpoint;

/*
 * One consumed, typed main-frame status. The resolution trace is sensitive.
 * Release host and resolution_trace_json with hns_browser_buffer_free.
 */
typedef struct HnsBrowserProxyStatus {
    uint32_t struct_size;
    HnsBrowserTlsPolicy tls_policy;
    HnsBrowserResolverPolicy resolver_policy;
    HnsBrowserSecurityPath security_path;
    uint64_t generation;
    uint32_t http_status;
    uint32_t reserved0;
    HnsBrowserBuffer host;
    HnsBrowserBuffer resolution_trace_json;
} HnsBrowserProxyStatus;

uint32_t hns_browser_abi_version(void);

HnsBrowserResult hns_browser_core_version(HnsBrowserBuffer *out_version);
HnsBrowserResult hns_browser_diagnostics_json(HnsBrowserBuffer *out_json);

/* Copies the current thread's bounded error text into a Rust-owned buffer. */
HnsBrowserResult hns_browser_last_error(HnsBrowserBuffer *out_error);

/* Rejects stale, double, mismatched, and foreign frees without dereferencing. */
HnsBrowserResult hns_browser_buffer_free(HnsBrowserBuffer buffer);

HnsBrowserResult hns_browser_runtime_options_default(
    HnsBrowserRuntimeOptions *out_options);
HnsBrowserResult hns_browser_policy_default(HnsBrowserPolicy *out_policy);

HnsBrowserResult hns_browser_runtime_create(
    const HnsBrowserRuntimeOptions *options,
    HnsBrowserRuntimeHandle *out_runtime);
HnsBrowserResult hns_browser_runtime_destroy(
    HnsBrowserRuntimeHandle runtime);
HnsBrowserResult hns_browser_runtime_set_policy(
    HnsBrowserRuntimeHandle runtime,
    const HnsBrowserPolicy *policy,
    uint64_t *out_revision);

HnsBrowserResult hns_browser_runtime_sync_once(
    HnsBrowserRuntimeHandle runtime,
    HnsBrowserBuffer *out_status_json);
HnsBrowserResult hns_browser_runtime_sync_status(
    HnsBrowserRuntimeHandle runtime,
    HnsBrowserBuffer *out_status_json);
HnsBrowserResult hns_browser_runtime_clear_resolver_cache(
    HnsBrowserRuntimeHandle runtime,
    HnsBrowserBuffer *out_status_json);
HnsBrowserResult hns_browser_runtime_install_header_snapshot(
    HnsBrowserRuntimeHandle runtime,
    HnsBrowserSlice snapshot_path,
    HnsBrowserBuffer *out_status_json);
HnsBrowserResult hns_browser_runtime_reset_headers_from_peers(
    HnsBrowserRuntimeHandle runtime,
    HnsBrowserBuffer *out_status_json);
HnsBrowserResult hns_browser_runtime_proof_details(
    HnsBrowserRuntimeHandle runtime,
    HnsBrowserSlice host_or_url,
    HnsBrowserBuffer *out_details_json);

HnsBrowserResult hns_browser_classify_name(
    HnsBrowserSlice input,
    HnsBrowserNameClass *out_class);
/*
 * Canonicalizes one extracted host (not a URL): lowercase IDNA DNS form with
 * no terminal dot, or canonical strict IPv4/IPv6 text. Rejects authorities,
 * ports, legacy numeric IPv4 forms, and malformed input.
 */
HnsBrowserResult hns_browser_canonical_host(
    HnsBrowserSlice input,
    HnsBrowserBuffer *out_host);
HnsBrowserResult hns_browser_hns_root(
    HnsBrowserSlice input,
    HnsBrowserBuffer *out_root);

/*
 * Starts an authenticated whole-WebKit loopback proxy generation. A null
 * scope slice ({NULL, 0}) is ICANN mode and denies every HNS request. A
 * non-null, non-empty slice admits only that exact HNS root and subdomains.
 * A non-null zero-length scope is rejected as ambiguous.
 */
HnsBrowserResult hns_browser_proxy_start(
    HnsBrowserRuntimeHandle runtime,
    HnsBrowserSlice hns_scope_root,
    HnsBrowserProxyHandle *out_proxy);
HnsBrowserResult hns_browser_proxy_endpoint(
    HnsBrowserProxyHandle proxy,
    HnsBrowserProxyEndpoint *out_endpoint);
HnsBrowserResult hns_browser_proxy_matches_instance(
    HnsBrowserProxyHandle proxy,
    HnsBrowserSlice session_id,
    uint64_t generation,
    uint8_t *out_matches);
HnsBrowserResult hns_browser_proxy_matches_authentication_challenge(
    HnsBrowserProxyHandle proxy,
    HnsBrowserSlice host,
    uint16_t port,
    HnsBrowserSlice realm,
    uint8_t *out_matches);
HnsBrowserResult hns_browser_proxy_matches_local_certificate(
    HnsBrowserProxyHandle proxy,
    HnsBrowserSlice host,
    HnsBrowserSlice certificate_der,
    uint8_t *out_matches);

/*
 * Atomically consumes only the latest status matching the canonical host and
 * this live proxy generation. Statuses for other hosts remain isolated.
 */
HnsBrowserResult hns_browser_proxy_take_main_frame_status(
    HnsBrowserProxyHandle proxy,
    HnsBrowserSlice canonical_main_frame_host,
    HnsBrowserProxyStatus *out_status);

/* Immediate, non-blocking credential/certificate/socket revocation. */
HnsBrowserResult hns_browser_proxy_request_stop(
    HnsBrowserProxyHandle proxy);

/* Removes the handle, revokes immediately, then blocks for worker teardown. */
HnsBrowserResult hns_browser_proxy_destroy(
    HnsBrowserProxyHandle proxy);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* HNS_BROWSER_H */
