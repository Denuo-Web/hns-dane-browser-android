#include "hns_browser.h"

#include <stddef.h>

_Static_assert(HNS_BROWSER_ABI_VERSION == 1u, "unexpected ABI version");
_Static_assert(sizeof(HnsBrowserRuntimeHandle) == sizeof(uint64_t), "runtime handle width");
_Static_assert(sizeof(HnsBrowserProxyHandle) == sizeof(uint64_t), "proxy handle width");
_Static_assert(offsetof(HnsBrowserBuffer, allocation_id) > offsetof(HnsBrowserBuffer, len),
               "buffer field order");

static void typecheck_api(void) {
    uint32_t (*abi_version)(void) = hns_browser_abi_version;
    HnsBrowserResult (*runtime_create)(const HnsBrowserRuntimeOptions *,
                                       HnsBrowserRuntimeHandle *) =
        hns_browser_runtime_create;
    HnsBrowserResult (*proxy_start)(HnsBrowserRuntimeHandle, HnsBrowserSlice,
                                    HnsBrowserProxyHandle *) = hns_browser_proxy_start;
    HnsBrowserResult (*canonical_host)(HnsBrowserSlice, HnsBrowserBuffer *) =
        hns_browser_canonical_host;
    HnsBrowserResult (*proxy_stop)(HnsBrowserProxyHandle) =
        hns_browser_proxy_request_stop;

    (void)abi_version;
    (void)runtime_create;
    (void)proxy_start;
    (void)canonical_host;
    (void)proxy_stop;
}

int main(void) {
    typecheck_api();
    return 0;
}
